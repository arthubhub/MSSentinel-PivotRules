#!/usr/bin/env node
// Generates indicators/<type>/locations.yml + indicators/REVIEW-locations.md (#31).
//
// Goal: for each EasyPivot indicator type, a list of "Table.Column" pairs where that type of value is
// actually found, sorted by decreasing confidence:
//   1. Existing rules are the ground truth: in the rule text (and in 4 shared fragments that list
//      columns for a generic parameter), find the columns ACTUALLY compared to the value
//      (`== Value`, `has Value`…), not those merely projected or used for grouping
//      (`by Machine = tolower(DeviceName)` proves nothing about the type of DeviceName).
//   2. The Defender `Entity` -> EasyPivot type mapping (observed on a real tenant, see plan).
//   3. Column name patterns over the 105 schemas (`schemas/`), the least reliable of the three.
//
// Decision of 23/10: all three levels are kept. The first two go to `confirmed`, the third to
// `uncertain`, and BOTH are meant to be published. `locations` helps preselection, it is not a
// constraint: the panel always offers the 9 types and shows "The value does not match this type,
// pivot still possible", so the analyst can always pivot another way; this is required, since a
// device name can be an IP address. A wrong pair costs one click; a missing pair costs a useful
// preselection.
//
// This script does NOT write pivot-rules.json: publishing happens in 2d (build.mjs). It is not
// wired into build/check/test (standalone npm script).
//
// Determinism: every output (locations.yml, report) is sorted; two successive runs produce no
// difference if nothing changed in rules/, fragments/ or schemas/.

import fs from 'node:fs';
import path from 'node:path';
import * as yaml from 'js-yaml';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]);

const INDICATOR_TYPES = ['ip', 'account', 'email', 'url', 'domain', 'device', 'process', 'application', 'hash'];

  ////////////////////////////////
 // 1. Load the schemas       //
////////////////////////////////

// Table -> Set(exact columns). Dotted nested fields (AdditionalFields.xxx) are excluded: they are
// dynamic sub-fields, not KQL columns ("Table.AdditionalFields.xxx" would be an invalid pair).
const tableColumns = new Map();
// Column name without the Log Analytics suffix (_s, _d, _t) -> list of {table, column} (real column, with suffix).
// Columns written to locations.yml ALWAYS keep their suffix: it is the real KQL column name.
const byBaseName = new Map();
const stripSuffix = (n) => n.replace(/_(s|d|t)$/, '');

for (const file of fs.readdirSync(path.join(ROOT, 'schemas')).filter((f) => f.endsWith('.json'))) {
  const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'schemas', file), 'utf8'));
  const table = data.table;
  if (/_CL$/i.test(table)) throw new Error(`guard: custom table ${table} in schemas/ (should never happen, 2a already excludes it)`);
  const cols = new Set();
  for (const f of data.fields) {
    if (f.name.includes('.')) continue; // nested dynamic sub-field, not a KQL column
    cols.add(f.name);
    const base = stripSuffix(f.name);
    (byBaseName.get(base) || byBaseName.set(base, []).get(base)).push({ table, column: f.name });
  }
  tableColumns.set(table, cols);
}
const allTables = [...tableColumns.keys()].sort((a, b) => b.length - a.length);

  /////////////////////////////////////////////////////////
 // 2. Defender Entity -> type mapping                   //
/////////////////////////////////////////////////////////
// Exact copy of the plan's table (step 0), observed on a real tenant: DeviceInfo, DeviceProcessEvents,
// DeviceNetworkEvents, DeviceFileEvents, EmailEvents, EmailUrlInfo, IdentityLogonEvents, CloudAppEvents,
// EntraIdSignInEvents. The last 7 lines are the Entity=null columns listed as specifically needing
// `locations` (no Entity signal covers them).

const ENTITY_MAP = {
  device: ['DeviceName', 'DeviceId', 'DestinationDeviceName', 'TargetDeviceName'],
  ip: ['RemoteIP', 'LocalIP', 'IPAddress', 'FileOriginIP', 'PublicIP', 'SenderIPv4', 'DestinationIPAddress'],
  url: ['RemoteUrl', 'Url', 'FileOriginUrl', 'FileOriginReferrerUrl'],
  hash: ['SHA1', 'SHA256', 'MD5', 'InitiatingProcessSHA256'],
  account: ['AccountSid', 'InitiatingProcessAccountSid', 'RequestAccountSid', 'AccountObjectId', 'SenderObjectId',
    'RecipientObjectId', 'AccountUpn'],
  email: ['SenderFromAddress', 'RecipientEmailAddress'],
  process: ['FileName', 'FolderPath'],
  domain: ['UrlDomain'],
};

  ///////////////////////////////////////////////////////////
 // 3. Level 1: ground truth (rule comparisons)           //
///////////////////////////////////////////////////////////

// Variables derived from Value by the indicators/*.kql fragments -> type they actually represent.
// Bare "Value" is not here: its type depends on the indicators declared by the rule (handled separately).
// ValueMailLocal (local part of an email) is left out on purpose: a comparison against it
// (e.g. InitiatingProcessAccountName =~ ValueMailLocal) does not prove that a column holds an email,
// only an account name that looks like the local part; too weak a signal, excluded rather than
// misclassified.
const VALUE_TOKENS = {
  ValueUpn: 'account', ValueSam: 'account',
  ValueMail: 'email',
  ValueDomain: 'domain', ValueMailDomain: 'domain',
  ValueHost: 'device', ValueShort: 'device',
  ValueFile: 'process', ValuePath: 'process',
  ValueApp: 'application', ValueAppLower: 'application',
  ValueHash: 'hash',
  ValueUrl: 'url',
};

// 4 shared fragments that list columns for a generic parameter, over many tables:
// _IpEvents(ip), _DomainHits(d), _Signins(ip, upn), _SpnSignins(app, ip). Analyzed once, on their own
// (regardless of the rules that call them): the comparison "RemoteIP == ip" in ip_events.kql holds
// whoever the caller is. A documented special case, not a general solution: the other fragments
// (win_security, sysmon…) compare to a generic "term" parameter reused for different types depending on
// the caller, so using them would give a false signal; they are ignored.
const FRAGMENT_TOKENS = {
  'ip_events.kql': { ip: 'ip' },
  'domain_hits.kql': { d: 'domain' },
  'signins.kql': { ip: 'ip', upn: 'account' },
  'spn_signins.kql': { app: 'application', ip: 'ip' },
};

const EQ_OPS = ['==', '=~', '!=', '!~'];
const HAS_OPS = ['has', 'contains', 'startswith', 'endswith'];
const NON_COLUMN = new Set(['true', 'false', 'and', 'or', 'not', 'isempty', 'isnotempty', 'isnull', 'isnotnull']);

// "Free text" columns where a substring match (has/contains…) is unreliable, whatever the type
// searched: command line, raw XML/JSON, message, description…
// "pattern", "parameters", "members" added after review (#31, audit of 22/10): STIX Pattern
// (ThreatIntelIndicators), Parameters (OfficeActivity cmdlet), Members (OfficeActivity member list);
// same family as CommandLine/RawEventData/AdditionalFields (catch-all text or list), but names the rest
// of the list would not have covered. Hardcoded: no predicate on the name alone cleanly tells them apart
// from a legitimate column (see fallbackColumns below for the structural detection, which would have
// found them without naming them).
// "targetresources" added on 23/10 by user decision: AuditLogs.TargetResources is a catch-all JSON
// (resources targeted by an Entra ID operation), confident for both account and application; it was the
// last unresolved conflict. Classified as catch-all, so dropped from both.
// "entities" added on 22/10: SecurityAlert.Entities is a JSON of alert entities, same family as
// AdditionalFields. It was hidden until then because it fell into a type conflict; once the conflict
// was gone, it wrongly became confident.
const BLOB_RE = /(commandline|raweventdata|^eventdata$|additionalfields|syslogmessage|^message$|details|^content$|^contents$|^body$|subject|useragent|description|failurereason|^text$|^pattern$|^parameters$|^members$|^entities$|^targetresources$)/i;


// Principled structural detection of "fallback" columns: in "ColA == Value or ColB has Value"
// (or the reverse, "ColB has Value or ColA == Value"), ColB is only queried ON TOP of a strict
// comparison on ANOTHER column; it means "if not found elsewhere, search this catch-all". That is
// exactly the shape of the 3 cases found (ObservableValue == Value or Pattern has Value;
// UserId =~ ValueUpn or Parameters/Members has ValueUpn/ValueMail): detected automatically, without
// knowing the column name. Also covers Syslog.SyslogMessage and a few others already in BLOB_RE
// (double safety net, without relying on a hardcoded name for these structural cases).
function fallbackColumns(code) {
  const cols = new Set();
  const fwd = /([A-Za-z_][A-Za-z0-9_]*)\s*(?:==|=~)\s*\S+\s+or\s+([A-Za-z_][A-Za-z0-9_]*)\s+(?:has|contains|startswith|endswith)\s+[A-Za-z_][A-Za-z0-9_]*/g;
  const rev = /([A-Za-z_][A-Za-z0-9_]*)\s+(?:has|contains|startswith|endswith)\s+[A-Za-z_][A-Za-z0-9_]*\s+or\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:==|=~)\s*\S+/g;
  for (const m of code.matchAll(fwd)) cols.add(m[2]);
  for (const m of code.matchAll(rev)) cols.add(m[1]);
  return cols;
}
// For the domain type specifically: a URL column (Url, RemoteUrl, TargetUrl…) often CONTAINS the
// domain as a substring (Url has ValueDomain) without being a domain column itself; it is already
// classified "url" elsewhere. Confident only if the name explicitly contains "domain", or is in a short
// list of DNS query/name columns. "Name" is deliberately limited to DnsEvents.Name (the only real
// occurrence, DM-P4): a generic "Name" in another table has no reason to be a domain.
const DOMAIN_SAFE_EXACT = new Set(['fqdn', 'dnsquery', 'httphost']);
const isDomainSafe = (table, column) => DOMAIN_SAFE_EXACT.has(stripSuffix(column).toLowerCase()) ||
  (table === 'DnsEvents' && column === 'Name');

const stripComments = (text) => text.replace(/(^|[^:])\/\/.*$/gm, '$1');
// Peels a few simple wrappers (tolower(X), tostring(X)…) to expose the bare identifier, over
// several passes (tolower(tostring(X))).
function unwrap(text) {
  let prev;
  let out = text;
  for (let i = 0; i < 5; i++) {
    prev = out;
    out = out.replace(/\b(?:tolower|toupper|tostring|trim|trim_start|trim_end)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)/g, '$1');
    if (out === prev) break;
  }
  return out;
}

function tablesIn(text) {
  const found = [];
  for (const t of allTables) if (new RegExp(`(^|[^\\w.])${t}(?![\\w])`, 'm').test(text)) found.push(t);
  return found;
}

// Name patterns per type. Defined here (not further down) because scanComparisons uses it as a
// guard: a fallback column whose NAME already says the type stays confident.
const NAME_PATTERNS = {
  ip: (t, toks) => toks.includes('ip') && !toks.some((x) => ['city', 'country', 'region', 'latitude', 'longitude', 'asn', 'location'].includes(x)),
  hash: (t, toks) => toks.includes('hash') || /sha(1|256|512)$/i.test(stripSuffix(t)) || /md5$/i.test(stripSuffix(t)),
  email: (t, toks) => toks.includes('email') || (toks.includes('mail') && (toks.includes('from') || toks.includes('to') ||
    toks.includes('address') || toks.includes('recipient') || toks.includes('sender'))),
  url: (t, toks) => (toks.includes('url') || toks.includes('uri')) && !toks.some((x) => ['category', 'count', 'chain', 'position'].includes(x)),
  domain: (t, toks, table) => (table === 'DnsEvents' && t === 'Name') || toks.includes('fqdn') || toks.includes('dnsquery') ||
    (toks.includes('domain') && !toks.includes('type')),
  device: (t, toks) => toks.includes('computer') || toks.includes('machine') || toks.includes('hostname') ||
    (toks.includes('host') && toks.includes('name')) ||
    (toks.includes('device') && !toks.some((x) => ['type', 'action', 'insights', 'detail', 'details', 'payload', 'facility',
      'interface', 'timezone', 'version', 'direction', 'translated', 'vendor', 'product', 'externalid', 'ntdomain', 'eventcategory'].includes(x))),
  account: (t, toks) => toks.includes('sid') || toks.includes('upn') || toks.includes('sam') || (toks.includes('user') && toks.includes('name')) ||
    (toks.includes('account') && !toks.some((x) => ['type', 'properties', 'enabled', 'expires', 'control', 'creation', 'virtual'].includes(x))),
  process: (t, toks) => toks.includes('image') || (toks.includes('file') && toks.includes('name')) ||
    (toks.includes('process') && (toks.includes('name') || toks.includes('command') || toks.includes('path'))),
  application: (t, toks) => (toks.includes('app') || toks.includes('application')) && (toks.includes('id') || toks.includes('name') || toks.includes('display')) &&
    !toks.some((x) => ['role', 'type', 'protocol', 'entity', 'entitykey', 'owner', 'instance'].includes(x)),
};

// A raw candidate: a column found compared to a known value token, for a set of candidate tables
// (those quoted literally in the analyzed text).
function scanComparisons(text, tokenMap, candidateTables, bareValueTypes) {
  const out = [];
  const code = unwrap(stripComments(text));
  const tables = candidateTables.length ? candidateTables : tablesIn(code);
  const fallback = fallbackColumns(code);

  const emit = (column, typeOrTypes, op) => {
    if (NON_COLUMN.has(column) || tokenMap[column] || column === 'Value') return;
    const types = Array.isArray(typeOrTypes) ? typeOrTypes : [typeOrTypes];
    const resolvedTables = tables.filter((t) => tableColumns.get(t)?.has(column));
    for (const table of resolvedTables) {
      for (const type of types) {
        let confident;
        // The structural fallback must not downgrade a column whose NAME already says the type:
        // "ComputerIP == Value or ComputerPrivateIPs has Value" does query a list of IPs; the `has`
        // is only there because the column is multi-valued, not because it is a catch-all.
        const nameSaysType = !BLOB_RE.test(column) && NAME_PATTERNS[type]?.(column, tokenize(column), table) === true;
        if (EQ_OPS.includes(op)) confident = true;
        else if (fallback.has(column) && !nameSaysType) confident = false; // fallback to a catch-all
        else if (type === 'domain') confident = /domain/.test(column.toLowerCase()) || isDomainSafe(table, column);
        else confident = !BLOB_RE.test(column);
        out.push({ table, column, type, confident, op, evidence: `${column} ${op} … (${table})` });
      }
    }
  };

  // Derived tokens (ValueXxx, or a fragment parameter such as "ip"/"d"/"upn"/"app")
  for (const [token, type] of Object.entries(tokenMap)) {
    const tokenRe = `\\b${token}\\b`;
    for (const op of EQ_OPS) {
      const opRe = op.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      for (const m of code.matchAll(new RegExp(`([A-Za-z_][A-Za-z0-9_]*)\\s*${opRe}\\s*${tokenRe}`, 'g'))) emit(m[1], type, op);
      for (const m of code.matchAll(new RegExp(`${tokenRe}\\s*${opRe}\\s*([A-Za-z_][A-Za-z0-9_]*)`, 'g'))) emit(m[1], type, op);
    }
    for (const op of HAS_OPS) {
      for (const m of code.matchAll(new RegExp(`([A-Za-z_][A-Za-z0-9_]*)\\s+${op}\\s+${tokenRe}`, 'g'))) emit(m[1], type, op);
    }
  }
  // Bare "Value" token: type = indicator(s) declared by the rule (ambiguous only for the DM rules, which
  // declare [domain, url] together: Value can be either, depending on what the analyst entered).
  if (bareValueTypes) {
    for (const op of EQ_OPS) {
      const opRe = op.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      for (const m of code.matchAll(new RegExp(`([A-Za-z_][A-Za-z0-9_]*)\\s*${opRe}\\s*\\bValue\\b`, 'g'))) emit(m[1], bareValueTypes, op);
      for (const m of code.matchAll(new RegExp(`\\bValue\\b\\s*${opRe}\\s*([A-Za-z_][A-Za-z0-9_]*)`, 'g'))) emit(m[1], bareValueTypes, op);
    }
    for (const op of HAS_OPS) {
      for (const m of code.matchAll(new RegExp(`([A-Za-z_][A-Za-z0-9_]*)\\s+${op}\\s+\\bValue\\b`, 'g'))) emit(m[1], bareValueTypes, op);
    }
  }
  // _IsHost(X) / _IsHost(coalesce(X, Y)): equality comparison on the short name -> device, reliable.
  for (const m of code.matchAll(/_IsHost\(\s*([^()]*(?:\([^()]*\)[^()]*)?)\s*\)/g)) {
    const inner = m[1].replace(/^coalesce\(|\)$/g, '');
    for (const id of inner.split(',').map((s) => s.trim())) {
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(id)) emit(id, 'device', '==');
    }
  }
  return out;
}

const candidates = []; // { table, column, type, confident, tier, evidence }

// 3a. Rules
const ruleFiles = walk(path.join(ROOT, 'rules')).filter((f) => /\.ya?ml$/.test(f)).sort();
for (const file of ruleFiles) {
  const rel = path.relative(ROOT, file).replace(/\\/g, '/');
  let rule;
  try { rule = yaml.load(fs.readFileSync(file, 'utf8')); } catch { continue; }
  if (!rule || !rule.query || !rule.indicators) continue;
  for (const c of scanComparisons(rule.query, VALUE_TOKENS, [], rule.indicators)) {
    candidates.push({ ...c, tier: 'rule', source: `${rel} [${rule.id}]` });
  }
}

// 3b. 4 shared fragments (analyzed on their own, see comment above)
for (const [fname, tokenMap] of Object.entries(FRAGMENT_TOKENS)) {
  const text = fs.readFileSync(path.join(ROOT, 'fragments', fname), 'utf8');
  for (const c of scanComparisons(text, tokenMap, [], null)) {
    candidates.push({ ...c, tier: 'rule', source: `fragments/${fname}` });
  }
}

  ///////////////////////////////////////////
 // 4. Level 2: Entity table (tier 2)      //
///////////////////////////////////////////

for (const [type, names] of Object.entries(ENTITY_MAP)) {
  for (const name of names) {
    for (const { table, column } of byBaseName.get(name) || []) {
      candidates.push({ table, column, type, confident: true, tier: 'entity', evidence: `Defender Entity: column ${name}`, source: 'plan (step 0)' });
    }
  }
}

  /////////////////////////////////////////////////////
 // 5. Level 3: name patterns (never confident)       //
/////////////////////////////////////////////////////

function tokenize(name) {
  // Plural `IPs` was split into "i" + "ps" (ComputerPrivateIPs -> computer, private, i, ps),
  // so NAME_PATTERNS.ip did not match it. Normalized like ipv4/ipv6.
  const n = stripSuffix(name).replace(/(?:ipv[46])/ig, 'IP').replace(/IPs(?![a-z])/g, 'IP');
  const toks = [];
  for (const part of n.split(/[^A-Za-z0-9]+/)) {
    if (!part) continue;
    for (const m of part.matchAll(/[A-Z]+(?=[A-Z][a-z]|\d)|[A-Z]?[a-z0-9]+|[A-Z]+/g)) toks.push(m[0].toLowerCase());
  }
  return toks;
}

// Patterns per type, tightened after a first pass that gave 925 review lines (lots of noise: generic
// CEF fields DeviceCustomString1(Label), *Type/*Role/*EntityKey metadata, counters…).
// A single token (e.g. "device") is no longer enough: a second token must make it an identity value
// (name, id, command…), and an exclusion list drops known metadata. Everything matched here goes ONLY
// to the review report, never to locations.yml.
// Global exclusion: "free" CEF fields (DeviceCustomString1…) and field labels (…Label); their real
// type depends on the deployment, not on the name; guessing them would be worse than offering nothing.
const GLOBAL_SKIP = (toks) => toks.includes('custom') || toks.includes('label');


for (const [table, cols] of tableColumns) {
  for (const column of cols) {
    const toks = tokenize(column);
    if (GLOBAL_SKIP(toks)) continue;
    for (const type of INDICATOR_TYPES) {
      if (NAME_PATTERNS[type](column, toks, table)) {
        candidates.push({ table, column, type, confident: false, tier: 'name-pattern', evidence: `name pattern (tokens: ${toks.join(', ')})`, source: 'schemas/' });
      }
    }
  }
}

  //////////////////////////////////////////////
 // 6. Merge: confident vs review, conflicts //
//////////////////////////////////////////////

const byPair = new Map(); // "Table.Column" -> { types: Map(type -> [candidates]) }
for (const c of candidates) {
  const key = `${c.table}.${c.column}`;
  const entry = byPair.get(key) || byPair.set(key, { table: c.table, column: c.column, types: new Map() }).get(key);
  (entry.types.get(c.type) || entry.types.set(c.type, []).get(c.type)).push(c);
}

// Known polymorphic columns: one column holds several indicator types depending on the row
// (e.g. ThreatIntelIndicators.ObservableValue, STIX: IP, domain, URL or hash depending on Pattern/
// ObservableKey/Data.pattern, not on the column itself). No general detection here: only one known case
// among the 234 confident pairs, and a generic heuristic (table with a "key"/"type" column next to a
// value column) was not built for a single example. Explicitly excluded from the confident set whatever
// signal would have put them there, and sent to review with the exact reason: since `locations` is the
// FIRST signal of detection.ts (before Entity and the regexes), a mistyped polymorphic column there is
// worse than a missing one.
// Checked: ThreatIntelligenceIndicator (legacy table) does NOT have this problem; its columns are already
// split by type (NetworkIP, NetworkSourceIP, NetworkDestinationIP, DomainName, Url, FileHashValue…); no
// column there needs the same handling.
const POLYMORPHIC = {
  'ThreatIntelIndicators.ObservableValue': 'Polymorphic STIX column: holds an IP, a domain, a URL or a ' +
    'hash depending on the row (told apart by ObservableKey/Pattern/Data.pattern, not by the column itself). ' +
    'ThreatIntelligenceIndicator (legacy table) does not have this problem: columns already split by type.',

  'ThreatIntelIndicators.Pattern': 'STIX pattern (e.g. "[ipv4-addr:value = \'…\']"): free text that WRAPS ' +
    'the value instead of holding it, and of variable type like ObservableValue. Seen as a fallback in IP-P5 ' +
    '(`ObservableValue == Value or Pattern has Value`).',
  'SecurityAlert.CompromisedEntity': 'Compromised entity of an alert: a host name or an IP depending on ' +
    'the alert. Used both ways by the rules: MC-S2 `CompromisedEntity has ValueShort` ' +
    '(device) and IP-P5 `CompromisedEntity == Value` (ip).',
};
// Account/email conflict resolution (decision of 22/10, item 2b-bis of docs/STATE.md).
// A UPN *is* almost always an email address: for these columns both types are right, and dropping them
// from both (2b behavior) lost the pair instead of settling it. So they are published in BOTH
// locations.yml files; the ORDER (account first, then email) is not decided here but in
// INDICATOR_PRIORITY in the userscript, where email still comes before account: TO REVISIT IN 3a,
// otherwise the preselection will be email while the decision says account.
// Two name families, NOT promoted the same way.
//   UPN_SHAPED      : `*Upn`, `UserPrincipalName`: a UPN has the shape of an email address.
//   ACCOUNT_GENERIC : `AccountName`, `UserId`: account identifiers that are NOT addresses
//                     (`StorageBlobLogs.AccountName` = storage account, `SigninLogs.UserId` /
//                     `AppRequests.UserId` / `DataverseActivity.UserId` = object GUID).
const UPN_SHAPED = (column) => {
  const base = stripSuffix(column);
  return /Upn$/i.test(base) || /^UserPrincipalName$/i.test(base);
};
const ACCOUNT_GENERIC = (column) => /^(AccountName|UserId)$/i.test(stripSuffix(column));
const DUAL_ACCOUNT_EMAIL = (column) => UPN_SHAPED(column) || ACCOUNT_GENERIC(column);
// Deliberate asymmetry: only the email -> account direction is applied.
//   - email confident + name in the list => account too: a UPN/AccountName/UserId holding an email
//     address is indeed an account identifier.
//   - account confident ALONE            => definitely NOT email: the list also catches columns that are
//     not addresses: `StorageBlobLogs.AccountName` is a *storage* account name, and
//     `SigninLogs.UserId` / `AppRequests.UserId` / `DataverseActivity.UserId` are object GUIDs.
//     Promoting all 48 columns the pattern matches (29 tables) would publish those three as email
//     locations. So promotion only happens on evidence of a real email signal.
// User decision of 23/10: "if the UPN is an email address, we want to pivot both on the user name and on
// the email events; the analyst chooses". So the criterion is the VALUE, not the table: a UPN column
// declares BOTH types, and the shape of the value decides at pivot time.
//   - `UPN_SHAPED` confident for account OR email => published in both (symmetric promotion).
//   - `ACCOUNT_GENERIC`: still asymmetric, email -> account only. Promoting these names wholesale
//     would publish `StorageBlobLogs.AccountName` and `UserId` GUIDs as email locations.
// ⚠️ 3a MUST filter on the shape of the value: `locations` offers account + email for these columns,
// but a value without "@" (service account, non-routable UPN from an on-prem AD read by Defender for
// Identity) must NOT offer the email rules. Without this filter, pivoting on `CORP\\svcsql` would
// offer email rules that return nothing.
const dualArbitration = (types, column) => {
  if (!types.every((t) => t === 'account' || t === 'email')) return false;
  if (UPN_SHAPED(column)) return types.includes('account') || types.includes('email');
  return ACCOUNT_GENERIC(column) && types.includes('email');
};

// Hard exclusions, decided by hand: neither `confirmed` nor `uncertain`, so never published.
// Not to be confused with POLYMORPHIC (dropped from confident but sent to review with its reason): here
// the pair is deemed unusable, not uncertain.
const EXCLUDED = {
  // User decision of 23/10: catch-all JSON (resources targeted by an Entra ID operation). It was
  // confident for account AND application, the last unresolved conflict.
  'AuditLogs.TargetResources': 'Catch-all JSON, dropped by decision of 23/10',
};

const confident = {}; // type -> Set("Table.Column")
for (const t of INDICATOR_TYPES) confident[t] = new Set();
const reviewByType = {}; // type -> [ { pair, candidates, bestTier } ]
for (const t of INDICATOR_TYPES) reviewByType[t] = [];
const conflicts = [];
const arbitrated = []; // pairs published in account AND email by the rule above

for (const [key, entry] of byPair) {
  const confidentTypes = [...entry.types.entries()].filter(([, cs]) => cs.some((c) => c.confident)).map(([t]) => t);

  // Polymorphic exclusions run BEFORE conflict detection: otherwise a column dropped by hand
  // (SecurityAlert.CompromisedEntity, device/ip) came out as a "conflict" and its exclusion reason was
  // never shown; the report reader saw a decision to make where it had already been made.
  if (POLYMORPHIC[key] && confidentTypes.length) {
    const reason = POLYMORPHIC[key];
    for (const type of confidentTypes) {
      reviewByType[type].push({ key, table: entry.table, column: entry.column,
        candidates: [{ tier: 'polymorphic', evidence: reason, source: 'manual audit (#31)' }],
        best: { tier: 'polymorphic', evidence: reason } });
    }
    continue;
  }

  if (dualArbitration(confidentTypes, entry.column)) {
    confident.account.add(key);
    confident.email.add(key);
    arbitrated.push({ key, types: confidentTypes, entry });
    continue;
  }

  if (confidentTypes.length > 1) {
    conflicts.push({ key, table: entry.table, column: entry.column, types: confidentTypes, entry });
    continue; // ambiguous: neither published nor in the "normal" review -> dedicated conflicts section
  }
  if (confidentTypes.length === 1) {
    confident[confidentTypes[0]].add(key);
    continue;
  }
  // No confident signal for this pair: each type with a weak signal goes to review.
  for (const [type, cs] of entry.types) {
    const tierRank = (c) => (c.tier === 'rule' ? 0 : c.tier === 'entity' ? 1 : 2); // entity should never be non-confident, kept for safety
    const best = cs.slice().sort((a, b) => tierRank(a) - tierRank(b))[0];
    reviewByType[type].push({ key, table: entry.table, column: entry.column, candidates: cs, best });
  }
}

  //////////////////////////////////////
 // 7. Write indicators/<t>/...      //
//////////////////////////////////////

// User decision of 23/10: trust the algorithm, and **uncertain pairs are published too**.
// `locations` HELPS preselection, it is never a constraint: the panel always offers the 9 types
// (`getIndicatorIds()` in `ui/panel/params-view.ts`) and shows "The value does not match this type,
// pivot still possible", so the analyst can always pivot another way. This is required: a device
// name can be an IP address, and other indicators behave the same way. A wrong pair costs one click,
// a missing pair costs a useful preselection.
//
// The two levels stay SEPARATE in the file rather than merged: that is what carries the per-column
// order required by decision 2 (a column confirmed for `account` and uncertain for `email` must
// preselect `account`). On publishing (2d), the two lists are concatenated in this order to give the
// `string[]` of the plan's format.
const header = (type, nConf, nUnc) => [
  `# locations.yml — ${type}`,
  '# Generated by scripts/generate-locations.mjs (#31). DO NOT EDIT BY HAND: run the script again.',
  '# "Table.Column" pairs where this indicator type can appear.',
  '#   confirmed: strong signal (comparison in an existing rule, or Defender Entity table).',
  '#   uncertain: weak signal (column name pattern). Published anyway (decision of 23/10):',
  '#              helps preselection, and the analyst can always change the type in the panel.',
  '# ORDER MATTERS: confirmed before uncertain. For a column that is a candidate for several types, the type',
  '# that lists it as confirmed wins the preselection (decision 2: this order takes precedence over INDICATOR_PRIORITY).',
  `# ${nConf} confirmed, ${nUnc} uncertain. Published in pivot-rules.json: in 2d.`,
  '',
].join('\n');

const yamlList = (name, list) =>
  `${name}:\n` + (list.length ? list.map((k) => `  - ${k}`).join('\n') + '\n' : '');

for (const key of Object.keys(EXCLUDED)) {
  for (const type of INDICATOR_TYPES) {
    confident[type].delete(key);
    reviewByType[type] = reviewByType[type].filter((r) => r.key !== key);
  }
}

for (const type of INDICATOR_TYPES) {
  const conf = [...confident[type]].sort();
  // A pair is never in both lists: confirmed wins.
  const confSet = new Set(conf);
  const unc = [...new Set(reviewByType[type].map((r) => r.key))].filter((k) => !confSet.has(k)).sort();
  const out = header(type, conf.length, unc.length) + yamlList('confirmed', conf) + yamlList('uncertain', unc);
  fs.writeFileSync(path.join(ROOT, 'indicators', type, 'locations.yml'), out);
}

  ///////////////////////////////////
 // 8. Review report (MD)         //
///////////////////////////////////

const TIER_LABEL = { rule: 'rule (weak/substring comparison)', entity: 'Defender Entity',
  'name-pattern': 'name pattern (schemas)', polymorphic: 'polymorphic column (dropped by audit)' };
const md = [];
md.push('# Uncertain matches: `locations` (#31)', '');
md.push('Generated by `scripts/generate-locations.mjs`. **Nothing here is published** in `pivot-rules.json`: ' +
  'this report is for human review before integration (plan instruction, phase 2b).', '');
md.push('For each `Table.Column` pair, the candidate type(s), the level the signal comes from and the evidence. ' +
  'Sorted by type, from the most likely signal (rule comparison on a substring) to the least likely (name pattern only).', '');

const totalConfident = Object.values(confident).reduce((s, set) => s + set.size, 0);
const totalReview = Object.values(reviewByType).reduce((s, l) => s + l.length, 0);
md.push('## Summary', '', '| Type | Confident (published in locations.yml) | Uncertain (this report) |', '| --- | --- | --- |');
for (const type of INDICATOR_TYPES) md.push(`| ${type} | ${confident[type].size} | ${reviewByType[type].length} |`);
md.push(`| **Total** | **${totalConfident}** | **${totalReview}** |`);
md.push('', `Conflicts (same column confident for two different types): **${conflicts.length}**; see the dedicated section.`);
md.push(`Account/email resolutions applied (pair published in both types): **${arbitrated.length}**; see the dedicated section.`, '');

// polymorphic first: these are exclusions decided by hand, the most useful to review.
const tierOrder = { polymorphic: -1, rule: 0, entity: 1, 'name-pattern': 2 };
for (const type of INDICATOR_TYPES) {
  const list = reviewByType[type];
  if (!list.length) continue;
  list.sort((a, b) => tierOrder[a.best.tier] - tierOrder[b.best.tier] || a.key.localeCompare(b.key));
  md.push(`## ${type} (${list.length})`, '', '| Table.Column | Level | Evidence | Source |', '| --- | --- | --- | --- |');
  for (const r of list) {
    const sources = [...new Set(r.candidates.map((c) => c.source))].slice(0, 3).join('; ');
    md.push(`| \`${r.key}\` | ${TIER_LABEL[r.best.tier]} | ${r.best.evidence} | ${sources} |`);
  }
  md.push('');
}

if (arbitrated.length) {
  md.push('## Account/email resolution (published in BOTH types)', '',
    'Decision of 22/10: the `*Upn`, `UserPrincipalName`, `AccountName`, `UserId` columns confident for ' +
    '`email` are **account first, then email**: published in both `locations.yml` files instead of being ' +
    'dropped from both. The preselection order is carried by `INDICATOR_PRIORITY` in the userscript (to revisit ' +
    'in 3a). Columns of the same family confident for `account` **only** are deliberately ' +
    'not promoted to `email` (`StorageBlobLogs.AccountName` is a storage account, `SigninLogs.UserId` a GUID).', '',
    '| Table.Column | Original confident types | Detail |', '| --- | --- | --- |');
  for (const a of arbitrated.sort((x, y) => x.key.localeCompare(y.key))) {
    const detail = a.types.map((t) => `${t}: ${a.entry.types.get(t).map((x) => x.evidence).join(' / ')}`).join(' — ');
    md.push(`| \`${a.key}\` | ${a.types.join(', ')} | ${detail} |`);
  }
  md.push('');
}

if (conflicts.length) {
  md.push('## Conflicts (column confident for several types)', '', '| Table.Column | Conflicting types | Detail |', '| --- | --- | --- |');
  for (const c of conflicts.sort((a, b) => a.key.localeCompare(b.key))) {
    const detail = c.types.map((t) => `${t}: ${c.entry.types.get(t).map((x) => x.evidence).join(' / ')}`).join(' — ');
    md.push(`| \`${c.key}\` | ${c.types.join(', ')} | ${detail} |`);
  }
  md.push('');
}

fs.writeFileSync(path.join(ROOT, 'indicators', 'REVIEW-locations.md'), md.join('\n'));

console.log(`locations: ${totalConfident} confident pair(s) (${INDICATOR_TYPES.map((t) => `${t}: ${confident[t].size}`).join(', ')}), ` +
  `${totalReview} in review, ${conflicts.length} conflict(s), ${arbitrated.length} account/email resolution(s).`);
console.log('Written: indicators/<type>/locations.yml (9 files), indicators/REVIEW-locations.md');
console.log('Note: this script does not write pivot-rules.json; npm run build publishes locations (2d).');
