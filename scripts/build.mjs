#!/usr/bin/env node
// Compiles the YAML rules into JSON
// 1. Read the YAML files
// 2. Validate the schema
// 3. Assemble

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import * as yaml from 'js-yaml';
import Ajv from 'ajv';

const require = createRequire(import.meta.url);
const { createValidator } = require('./kql-validator.cjs');

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const args = new Set(process.argv.slice(2));
const CHECK_ONLY = args.has('--check');
const STRICT = args.has('--strict');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

  ///////////////////////
 // Menu variables    //
///////////////////////

// Values one can pivot on
const INDICATORS = {
  ip: { label: 'IP address', header: 'ip',
    patterns: ['^(25[0-5]|2[0-4]\\d|1?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}$', '^(?=.*:.*:)[0-9a-fA-F:.]{2,45}$'] },
  account: { label: 'Account', header: 'account',
    patterns: ['^[^@\\s"]+@[^@\\s"]+\\.[^@\\s"]+$', '^[\\w.-]+\\\\[\\w.$-]+$'] },
  email: { label: 'E-mail address', header: 'email', patterns: ['^[^@\\s"]+@[^@\\s"]+\\.[^@\\s"]+$'] },
  url: { label: 'URL', header: 'web', patterns: ['^https?://\\S+$'] },
  domain: { label: 'Domain', header: 'web',
    patterns: ['^(?=.{4,253}$)([a-zA-Z0-9-]{1,63}\\.)+[a-zA-Z]{2,63}\\.?$'] },
  // Requires at least one letter and excludes GUIDs: without this the pattern accepted
  // any alphanumeric token, so "4624", "0" and a CorrelationId GUID were detected
  // as devices (#5/#6). Also rules out IPv4 addresses, which have no letter, which
  // removes the double type [ip, device].
  // Keeps legitimate short names: DC01, SRV1, web-02, srv-prod-01.corp.local.
  device: { label: 'Device', header: 'device',
    patterns: ['^(?!(?:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})$)(?=[a-zA-Z0-9.-]*[a-zA-Z])[a-zA-Z0-9][a-zA-Z0-9-]{0,62}(?:\\.[a-zA-Z0-9-]{1,63})*$'] },
  // "com" is the only extension in the list that is also a TLD: "corp.com" and
  // "user@corp.com" were therefore detected as processes. It now requires a path
  // separator (C:\\tools\\legacy.com is still a process); the other extensions are
  // still accepted without a path, since DeviceProcessEvents.FileName holds bare
  // names (powershell.exe) that must not be lost.
  process: { label: 'Process', header: 'process',
    patterns: ['(?i)^(?:(?:.*[\\\\/])?[^\\\\/]+\\.(?:exe|dll|ps1|bat|cmd|vbs|vbe|js|jse|wsf|hta|msi|scr|cpl|lnk)|.*[\\\\/][^\\\\/]+\\.com)$'] },
  application: { label: 'Application', header: 'application',
    patterns: ['^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'] },
  hash: { label: 'Hash', header: 'hash', patterns: ['^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$'] },
};
const ACTIONS = {
  statistics: { label: 'Statistics', order: 0 }, // Stats on the IOC -> usage per table over a time T, ...
  pivot: { label: 'Pivot', order: 1 },           // Pivot functions on an IOC: IP -> accounts signed in from the IP
  timeline: { label: 'Timeline', order: 2 },     // Observed behaviors: 4625 -> 4624 -> 4768
};
const PLACEHOLDERS = {
  VALUE: 'Selected value, inserted in a verbatim string @"…".',
  T0: 'Reference time, ISO 8601 (TimeGenerated of the selected row).',
  BEFORE_MIN: 'Window before T0, in minutes (integer).',
  AFTER_MIN: 'Window after T0, in minutes (integer).',
  HOST: 'Optional: related device (DeviceName or Computer).',
};

  ///////////
 // Utils //
///////////

const toMinutes = (d) => {
  const m = d.match(/^(\d+)(m|h|d)$/);
  return Number(m[1]) * { m: 1, h: 60, d: 1440 }[m[2]];
};
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]);

// "// @sentinel-only:begin … // @sentinel-only:end" blocks in a fragment or a rule: union branches reading tables
// missing from Defender XDR. They are removed from the Defender variant (queryDefender), which stays possible.
const stripSentinelOnly = (text) =>
  text.replace(/^[ \t]*\/\/\s*@sentinel-only:begin[\s\S]*?^[ \t]*\/\/\s*@sentinel-only:end[ \t]*\n?/gm, '');
// Symmetric "// @defender-only:begin … // @defender-only:end" blocks: branches reading Defender XDR tables that
// duplicate a source already read by the Sentinel variant. Removed from `query`, kept (without the tags) in queryDefender.
const stripDefenderOnly = (text) =>
  text.replace(/^[ \t]*\/\/\s*@defender-only:begin[\s\S]*?^[ \t]*\/\/\s*@defender-only:end[ \t]*\n?/gm, '');
const unwrapDefenderOnly = (text) => text.replace(/^[ \t]*\/\/\s*@defender-only:(begin|end)[ \t]*\n?/gm, '');
// Sentinel text and Defender text of a fragment or a rule
const sentinelText = (text) => stripDefenderOnly(text);
const defenderText = (text) => unwrapDefenderOnly(stripSentinelOnly(text));
// Unclosed or nested tags: a tag left over after splitting
const TAG_RE = /@(sentinel|defender)-only:(begin|end)/;
// Comments removed before table detection (a table name quoted in a comment is not a source).
const stripComments = (text) => text.replace(/(^|[^:])\/\/.*$/gm, '$1');

function expandMacros(text) {
  // Replaces XMLFIELD(expr, Name) with a regex that extracts the field.
  return text.replace(/XMLFIELD\(\s*([A-Za-z_][\w.]*)\s*,\s*([A-Za-z]\w*)\s*\)/g,
    (_, expr, field) => `extract(@'<Data Name="${field}">([^<]*)</Data>', 1, ${expr})`);
}

function loadFragments() {
  const dir = path.join(ROOT, 'fragments');
  const frags = {};
  for (const file of walk(dir).filter((f) => f.endsWith('.kql'))) {
    const rel = path.relative(dir, file).replace(/\\/g, '/').replace(/\.kql$/, '');
    const raw = fs.readFileSync(file, 'utf8').replace(/\s+$/, '');
    const requires = [...raw.matchAll(/^\/\/\s*@requires:\s*(.+)$/gm)]
      .flatMap((m) => m[1].split(',').map((s) => s.trim()).filter(Boolean));
    const text = sentinelText(raw).replace(/\s+$/, '');
    frags[rel] = { name: rel, text, defenderText: defenderText(raw), requires,
      tagError: /@defender-only:(begin|end)/.test(text) || TAG_RE.test(defenderText(raw)) };
  }
  return frags;
}

function resolveFragments(names, frags, errors, ctx) {
  const order = [];
  const seen = new Set();
  const visit = (n, stack) => {
    if (seen.has(n)) return;
    if (stack.includes(n)) { errors.push(`${ctx}: circular dependency ${[...stack, n].join(' → ')}`); return; }
    const f = frags[n];
    if (!f) { errors.push(`${ctx}: unknown fragment "${n}"`); return; }
    for (const r of f.requires) visit(r, [...stack, n]);
    seen.add(n);
    order.push(f);
  };
  for (const n of names) visit(n, []);
  return order;
}

function detectTables(query, tableNames) {
  const found = new Set();
  const code = stripComments(query);
  for (const t of tableNames) if (new RegExp(`(^|[^\\w.])${t}(?![\\w])`, 'm').test(code)) found.add(t);
  return [...found].sort();
}

  /////////////////
 // Compilation //
/////////////////

const ajv = new Ajv({ allErrors: true });
const validateRule = ajv.compile(JSON.parse(fs.readFileSync(path.join(ROOT, 'schema/rule.schema.json'), 'utf8')));
const kql = createValidator(ROOT);
const tableNames = Object.keys(kql.tables).sort((a, b) => b.length - a.length);
const xdr = new Set(kql.xdrTables);
const defenderOptional = new Set(kql.defenderOptional);
const frags = loadFragments();

// Source families: table -> families (schema/sources.json)
// A family lists members: a whole table, or part of a log table (channel + EventID, or a where filter).
const SOURCES = JSON.parse(fs.readFileSync(path.join(ROOT, 'schema/sources.json'), 'utf8')).families;
const CHANNEL_FILTERS = {
  security: { SecurityEvent: '', WindowsEvent: 'Provider == "Microsoft-Windows-Security-Auditing"' },
  sysmon: { Event: 'Source == "Microsoft-Windows-Sysmon"', WindowsEvent: 'Provider == "Microsoft-Windows-Sysmon"' },
  system: { Event: 'Source == "Service Control Manager"', WindowsEvent: 'Provider == "Service Control Manager"' },
};
const famOrder = Object.keys(SOURCES);
const tableFamilies = {};
for (const [id, f] of Object.entries(SOURCES)) {
  f.members = (f.members || f.tables.map((t) => ({ table: t }))).map((m) => {
    const parts = [];
    if (m.channel) {
      const filter = CHANNEL_FILTERS[m.channel]?.[m.table];
      if (filter === undefined) throw new Error(`schema/sources.json: unknown channel ${m.channel} for ${m.table}`);
      if (filter) parts.push(filter);
    }
    if (m.ids) parts.push(`EventID in (${m.ids.join(', ')})`);
    if (m.where) parts.push(m.where);
    const channel = { security: 'Security', sysmon: 'Sysmon', system: 'System' }[m.channel];
    const key = m.label ? `${m.table} · ${channel ? `${channel} · ` : ''}${m.label}${m.ids ? ` (${m.ids.join(', ')})` : ''}` : m.table;
    return { ...m, family: id, key, filter: parts.join(' and ') };
  });
  f.tables = [...new Set(f.members.map((m) => m.table))];
  for (const t of f.tables) (tableFamilies[t] ||= []).push(id);
}
// Events read per channel: EventIDs passed to _WinSecurity (Security log) and to _Sysmon; empty list = all.
function readChannels(query) {
  const out = {};
  for (const [channel, fn] of [['security', '_WinSecurity'], ['sysmon', '_Sysmon']]) {
    for (const m of query.matchAll(new RegExp(`${fn}\\(\\s*[^,]+,\\s*[^,]+,\\s*dynamic\\(\\[([^\\]]*)\\]\\)`, 'g'))) {
      const ids = m[1].split(',').map((x) => Number(x.trim())).filter((x) => x);
      if (!ids.length) out[channel] = 'all';
      else if (out[channel] !== 'all') out[channel] = [...new Set([...(out[channel] || []), ...ids])];
    }
  }
  if (/"Service Control Manager"/.test(query)) out.system = 'all';
  return out;
}
// Columns read by both variants; Timestamp in the Defender variant is just TimeGenerated renamed.
function mergeColumns(a, b) {
  const out = { ...a };
  for (const [t, cols] of Object.entries(b)) {
    const extra = [...cols].filter((c) => c !== 'Timestamp' && !(a[t] && a[t].has(c)));
    if (extra.length) out[t] = new Set([...(a[t] || []), ...extra]);
  }
  return out;
}
const PREFIX_INDICATORS = { IP: ['ip'], AC: ['account'], EM: ['email'], DM: ['domain', 'url'], MC: ['device'], PR: ['process'],
  AP: ['application'], HS: ['hash'] };

const errors = [];
const warnings = [];
const rules = [];
const ids = new Set();

function header(rule) {
  const kinds = [...new Set(rule.indicators.map((i) => INDICATORS[i].header))];
  const ind = rule.indicators.map((i) => INDICATORS[i].label).join(', ');
  const lines = [
    `// [${rule.id}] ${rule.name} — ${ACTIONS[rule.action].label} / ${ind}`,
    `// sentinel-pivot-rules ${pkg.version}. Parameters: {{VALUE}}, {{T0}}, {{BEFORE_MIN}}, {{AFTER_MIN}}${(rule.context || []).map((c) => `, {{${c}}}`).join('')}`,
    `let Value = trim(@"\\s", @"{{VALUE}}");`,
    `let T0 = coalesce(todatetime(@"{{T0}}"), now());`,
    `let Before = coalesce(tolong(@"{{BEFORE_MIN}}"), ${toMinutes(rule.window.before)}) * 1m; // default: ${rule.window.before}`,
    `let After = coalesce(tolong(@"{{AFTER_MIN}}"), ${toMinutes(rule.window.after)}) * 1m; // default: ${rule.window.after}`,
    'let StartTimestamp = T0 - Before;',
    'let EndTimestamp = T0 + After;',
  ];
  if ((rule.context || []).includes('HOST')) {
    lines.push('let HostFilter = tolower(tostring(split(trim(@"\\s", iff(@"{{HOST}}" startswith "{{", "", @"{{HOST}}")), ".")[0]));');
  }
  return { text: lines.join('\n'), kinds };
}

const ruleFiles = walk(path.join(ROOT, 'rules')).filter((f) => /\.ya?ml$/.test(f)).sort();
for (const file of ruleFiles) {
  const rel = path.relative(ROOT, file);
  let rule;
  try {
    rule = yaml.load(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    errors.push(`${rel}: invalid YAML — ${e.message}`);
    continue;
  }
  if (!validateRule(rule)) {
    for (const e of validateRule.errors) errors.push(`${rel}: ${e.instancePath || '(root)'} ${e.message}`);
    continue;
  }
  if (ids.has(rule.id)) errors.push(`${rel}: duplicate id ${rule.id}`);
  ids.add(rule.id);
  const prefix = PREFIX_INDICATORS[rule.id.slice(0, 2)];
  if (/-S(0|9)$/.test(rule.id)) errors.push(`${rel}: id ${rule.id} is reserved for generated rules (S0 coverage, S9 discovery)`);
  if (!prefix.includes(rule.indicators[0])) errors.push(`${rel}: prefix ${rule.id.slice(0, 2)} does not match indicator ${rule.indicators[0]}`);

  const h = header(rule);
  if (h.kinds.length > 1) { errors.push(`${rel}: indicators of different kinds (${h.kinds.join(', ')})`); continue; }
  const parts = resolveFragments([`indicators/${h.kinds[0]}`, ...(rule.uses || [])], frags, errors, rel);
  const rawBody = rule.query.replace(/\s+$/, '');
  const body = sentinelText(rawBody).replace(/\s+$/, '');
  for (const p of parts) if (p.tagError) errors.push(`${rel}: malformed @sentinel-only / @defender-only tag in fragment ${p.name}`);
  if (/@defender-only:(begin|end)/.test(body) || TAG_RE.test(defenderText(rawBody))) errors.push(`${rel}: malformed @sentinel-only / @defender-only tag`);
  const assembled = expandMacros([h.text, ...parts.map((p) => p.text), body].join('\n'));

  for (const d of kql.validate(assembled)) {
    const msg = `${rel} [${rule.id}] ${d.severity} ${d.code} l.${d.line}:${d.col} ${d.message}\n      > ${d.snippet.trim()}`;
    if (d.severity === 'Error') errors.push(msg); else warnings.push(msg);
  }

  // Tables of the Sentinel variant (without @defender-only blocks): sources, families, enrichment
  const sentinelTables = detectTables(body + '\n' + parts.map((p) => p.text).join('\n'), tableNames);
  // Event tables (query and non-role fragments) and tables read only to annotate roles
  const eventTables = detectTables(body + '\n' + parts.filter((p) => p.name !== 'roles').map((p) => p.text).join('\n'), tableNames)
    .filter((t) => tableFamilies[t]);
  const enrichment = sentinelTables.filter((t) => !eventTables.includes(t));
  // Defender variant: without @sentinel-only blocks, with @defender-only blocks; possible if all remaining
  // tables are Defender XDR tables
  const defenderBody = defenderText(rawBody).replace(/\s+$/, '');
  const defenderTables = detectTables(defenderBody + '\n' + parts.map((p) => p.defenderText).join('\n'), tableNames);
  // Tables read only by the Defender variant: counted in `tables` (and checked by XX-S0), not in `sources`
  const defenderOnlyTables = defenderTables.filter((t) => !sentinelTables.includes(t));
  const defenderEventTables = detectTables(defenderBody + '\n' + parts.filter((p) => p.name !== 'roles').map((p) => p.defenderText).join('\n'),
    tableNames).filter((t) => tableFamilies[t] && !sentinelTables.includes(t));
  const tables = [...new Set([...sentinelTables, ...defenderOnlyTables])].sort();
  for (const t of tables) if (!tableFamilies[t]) errors.push(`${rel}: table ${t} missing from schema/sources.json (unknown source family)`);
  // Functions removed from the Defender variant (defined in a @sentinel-only block) still called: no variant
  const strippedFns = parts.flatMap((p) => [...p.text.matchAll(/^let (_\w+) =/gm)].map((m) => m[1])
    .filter((fn) => !new RegExp(`^let ${fn} =`, 'm').test(p.defenderText)));
  const callsStripped = strippedFns.some((fn) => new RegExp(`\\b${fn}\\(`).test(stripComments(defenderBody + '\n' +
    parts.map((p) => p.defenderText).join('\n'))));
  const xdrOnly = !callsStripped && defenderTables.some((t) => xdr.has(t)) && defenderTables.every((t) => xdr.has(t) || defenderOptional.has(t));
  let queryDefender;
  if (xdrOnly) {
    queryDefender = expandMacros([h.text, ...parts.map((p) => p.defenderText), defenderBody].join('\n')).replace(/\bTimeGenerated\b/g, 'Timestamp');
    for (const d of kql.validate(queryDefender)) {
      if (d.severity === 'Error') errors.push(`${rel} [${rule.id}] (Defender variant) ${d.code} l.${d.line}: ${d.message}`);
    }
  }
  const usedPlaceholders = ['VALUE', 'T0', 'BEFORE_MIN', 'AFTER_MIN', ...(rule.context || [])];
  if ((rule.context || []).includes('HOST') && !/\bHostFilter\b/.test(body)) {
    warnings.push(`${rel}: HOST context declared but HostFilter never used`);
  }

  rules.push({
    id: rule.id,
    name: rule.name,
    category: `${ACTIONS[rule.action].label} · ${INDICATORS[rule.indicators[0]].label}`,
    indicators: rule.indicators,
    action: rule.action,
    ...(rule.targets ? { targets: rule.targets } : {}),
    description: rule.description.trim(),
    ...(rule.reading ? { reading: rule.reading } : {}),
    scenarios: rule.scenarios || [],
    v1: !!rule.v1,
    window: { before: rule.window.before, after: rule.window.after,
      beforeMinutes: toMinutes(rule.window.before), afterMinutes: toMinutes(rule.window.after) },
    render: rule.render || 'table',
    tables,
    sources: ruleSources(eventTables),
    ...(enrichment.length ? { enrichment } : {}),
    platforms: xdrOnly ? ['sentinel', 'defender-unified', 'defender'] : ['sentinel', 'defender-unified'],
    placeholders: usedPlaceholders,
    ...(rule.notes ? { notes: rule.notes.trim() } : {}),
    query: assembled,
    ...(queryDefender ? { queryDefender } : {}),
    source: rel.replace(/\\/g, '/'),
    columns: mergeColumns(kql.columnsUsed(assembled), queryDefender ? kql.columnsUsed(queryDefender) : {}),
    eventTables: [...eventTables, ...defenderEventTables],
    channels: readChannels(expandMacros([...parts.filter((p) => p.name !== 'roles').map((p) => p.text), body].join('\n'))),
  });
}

  ////////////////////////////////////////
 // "Source coverage" rules          //
////////////////////////////////////////
// One generated rule per indicator (XX-S0): for each table read by the indicator's rules, tells whether it exists,
// whether it receives data over the window, whether it lacks columns used by the rules, and whether its absence is
// made up for by another table of the same family. Shows what union isfuzzy=true silently ignores.

const kqlStr = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
const kqlArr = (a) => `dynamic([${a.map(kqlStr).join(', ')}])`;
const timeCol = (t) => (kql.tables[t] && kql.tables[t].TimeGenerated ? 'TimeGenerated' : 'Timestamp');
// Relevant families for a set of tables: those that own a table read by no other family, or whose tables are all
// read. SecurityEvent (authentications, processes, registry…) does not bring the "processes" family into the
// coverage of an indicator that reads no other process table.
function relevantFamilies(tables) {
  const used = new Set(tables);
  return new Set(Object.entries(SOURCES)
    .filter(([id, f]) => f.tables.every((t) => used.has(t)) || tables.some((t) => tableFamilies[t].length === 1 && tableFamilies[t][0] === id))
    .map(([id]) => id));
}

// Source families of a rule: those of its event tables, limited to the relevant families
function ruleSources(eventTables) {
  const relevant = relevantFamilies(eventTables);
  return [...new Set(eventTables.flatMap((t) => {
    const r = tableFamilies[t].filter((f) => relevant.has(f));
    return r.length ? r : tableFamilies[t];
  }))].sort((a, b) => famOrder.indexOf(a) - famOrder.indexOf(b));
}

// A member is read by a rule if the rule reads its table and, for a channel member, at least one of its EventIDs.
function memberReadBy(m, r) {
  if (!r.eventTables.includes(m.table)) return false;
  if (!m.channel) return true;
  const ids = r.channels[m.channel];
  return ids === 'all' || (Array.isArray(ids) && (!m.ids || m.ids.some((i) => ids.includes(i))));
}

// Members checked for a set of rules, with the rules that read them. A table read without a matching member
// (direct read, role enrichment) is checked as a whole.
function coverageMembers(list, tables) {
  const relevant = relevantFamilies(tables);
  const enrichOnly = new Set(tables.filter((t) => !list.some((r) => r.eventTables.includes(t))));
  const members = [];
  for (const t of tables) {
    const fams = tableFamilies[t].filter((f) => relevant.has(f));
    const own = Object.values(SOURCES).flatMap((f) => f.members)
      .filter((m) => m.table === t && (fams.length ? fams : tableFamilies[t]).includes(m.family));
    const byKey = new Map();
    for (const m of own) {
      const readers = list.filter((r) => memberReadBy(m, r)).map((r) => r.id);
      if (!readers.length) continue;
      const cur = byKey.get(m.key) || { ...m, families: [], readers: new Set() };
      cur.families.push(m.family);
      readers.forEach((x) => cur.readers.add(x));
      byKey.set(m.key, cur);
    }
    if (!byKey.size) {
      byKey.set(t, { table: t, key: t, filter: '', families: fams.length ? fams : tableFamilies[t],
        readers: new Set(list.filter((r) => r.tables.includes(t)).map((r) => r.id)), enrichment: enrichOnly.has(t) });
    }
    members.push(...byKey.values());
  }
  return members.sort((a, b) =>
    Math.min(...a.families.map((f) => famOrder.indexOf(f))) - Math.min(...b.families.map((f) => famOrder.indexOf(f)))
    || a.key.localeCompare(b.key));
}

function coverageQuery(members, usage) {
  const tables = [...new Set(members.map((m) => m.table))];
  const expected = members.map((m) => {
    const hints = `dynamic({${m.families.map((f) => `${kqlStr(SOURCES[f].label)}: ${kqlStr(SOURCES[f].hint)}`).join(', ')}})`;
    const optional = m.enrichment || m.families.every((f) => SOURCES[f].optional);
    return `    ${kqlStr(m.key)}, ${kqlStr(m.table)}, ${kqlArr(m.families.map((f) => SOURCES[f].label))}, ${hints}, ` +
      `${kqlStr(m.hint || '')}, ${!!optional}, ${kqlArr([...m.readers].sort())}, ${kqlArr([...(usage[m.table]?.columns || [])].sort())}`;
  });
  const volume = members.map((m) => `    (${m.table} | where ${timeCol(m.table)} between (StartTimestamp .. EndTimestamp)` +
    `${m.filter ? ` | where ${m.filter}` : ''} | summarize Events = count(), LastEvent = max(${timeCol(m.table)}) | extend Member = ${kqlStr(m.key)})`);
  const tableVolume = tables.map((t) => `    (${t} | where ${timeCol(t)} between (StartTimestamp .. EndTimestamp) | summarize TableEvents = count() | extend Table = ${kqlStr(t)})`);
  const schema = tables.map((t) => `    (${t} | getschema | summarize PresentColumns = make_set(ColumnName) | extend Table = ${kqlStr(t)})`);
  return [
    'let Expected = datatable(Member:string, Table:string, Families:dynamic, Hints:dynamic, MemberHint:string, Optional:bool, Rules:dynamic, Columns:dynamic) [',
    expected.join(',\n'),
    '];',
    'let Volume = union isfuzzy=true',
    '    (datatable(Member:string, Events:long, LastEvent:datetime) []),',
    volume.join(',\n') + ';',
    'let TableVolume = union isfuzzy=true',
    '    (datatable(Table:string, TableEvents:long) []),',
    tableVolume.join(',\n') + ';',
    'let Present = union isfuzzy=true',
    '    (datatable(Table:string, PresentColumns:dynamic) []),',
    schema.join(',\n') + ';',
    'let Rows = materialize(Expected',
    '    | join kind=leftouter (Volume) on Member',
    '    | join kind=leftouter (TableVolume) on Table',
    '    | join kind=leftouter (Present) on Table',
    '    | extend Exists = isnotnull(TableEvents) or isnotnull(PresentColumns)',
    '    | extend MissingColumns = iff(isnotnull(PresentColumns), set_difference(Columns, PresentColumns), dynamic([]))',
    '    | extend Status = case(not(Exists), "Missing or inaccessible", isnull(TableEvents) or isnull(Events), "Missing columns",',
    '        TableEvents == 0, "Empty in the window", Events == 0, "Events not collected",',
    '        array_length(MissingColumns) > 0, "Missing columns", "Fed"));',
    'let Fed = Rows',
    '    | mv-expand Family = Families to typeof(string)',
    '    | summarize FedMembers = make_set_if(Member, Status == "Fed") by Family;',
    'Rows',
    '| mv-expand Family = Families to typeof(string)',
    '| join kind=leftouter (Fed) on Family',
    '| extend FedMembers = iff(array_length(FedMembers) == 0, dynamic([""]), FedMembers)',
    '| mv-expand Alt = FedMembers to typeof(string)',
    '| summarize Families = make_set(Family), Alternatives = make_set_if(Alt, isnotempty(Alt) and Alt != Member),',
    '    Uncovered = make_set_if(Family, isempty(Alt)), FamilyHints = make_set_if(tostring(Hints[Family]), isempty(Alt))',
    '    by Member, Status, Optional, MemberHint, Events, LastEvent, Missing = strcat_array(MissingColumns, ", "), Rules = strcat_array(Rules, ", ")',
    '| extend Impact = case(Status == "Fed", "",',
    '    Optional, "Optional: role enrichment only",',
    '    array_length(Uncovered) > 0, strcat("Not covered: ", strcat_array(Uncovered, ", "), ". Incomplete results for ", Rules),',
    '    strcat("Compensated by ", strcat_array(Alternatives, ", ")))',
    '| extend Order = case(Status == "Fed", 4, Optional, 3, array_length(Uncovered) > 0, 0, Status == "Missing columns", 1, 2)',
    '| sort by Order asc, Member asc',
    '| project Status, Source = Member, Events, LastEvent, Impact, MissingColumns = Missing, Families, Rules,',
    '    Remediation = iff(Status == "Fed" or Optional, "", iff(isnotempty(MemberHint), MemberHint, strcat_array(FamilyHints, " ")))',
  ].join('\n');
}

const groups = {};
for (const r of rules) (groups[r.id.slice(0, 2)] ||= []).push(r);
for (const [pfx, list] of Object.entries(groups)) {
  const usage = {};
  for (const r of list) for (const t of r.tables) {
    const u = (usage[t] ||= { columns: new Set() });
    for (const c of r.columns[t] || []) u.columns.add(c);
  }
  const tables = Object.keys(usage).filter((t) => tableFamilies[t]);
  const members = coverageMembers(list, tables);
  const indicators = [...new Set(list.flatMap((r) => r.indicators))];
  const rule = {
    id: `${pfx}-S0`,
    name: 'Source coverage',
    indicators: PREFIX_INDICATORS[pfx].filter((i) => indicators.includes(i)),
    action: 'statistics',
    window: { before: '3d', after: '1d' },
  };
  const h = header(rule);
  const assembled = [h.text, coverageQuery(members, usage)].join('\n');
  for (const d of kql.validate(assembled)) {
    const msg = `(generated) [${rule.id}] ${d.severity} ${d.code} l.${d.line}:${d.col} ${d.message}\n      > ${d.snippet.trim()}`;
    if (d.severity === 'Error') errors.push(msg); else warnings.push(msg);
  }
  const xdrMembers = members.filter((m) => xdr.has(m.table));
  let queryDefender;
  if (xdrMembers.length) {
    queryDefender = [h.text, coverageQuery(xdrMembers, usage)].join('\n').replace(/\bTimeGenerated\b/g, 'Timestamp');
    for (const d of kql.validate(queryDefender)) {
      if (d.severity === 'Error') errors.push(`(generated) [${rule.id}] (Defender variant) ${d.code} l.${d.line}: ${d.message}`);
    }
  }
  rules.push({
    id: rule.id,
    name: rule.name,
    category: `${ACTIONS.statistics.label} · ${INDICATORS[rule.indicators[0]].label}`,
    indicators: rule.indicators,
    action: 'statistics',
    description: `State of the ${members.length} sources read by the "${INDICATORS[rule.indicators[0]].label}" rules (${tables.length} tables). ` +
      'A source is a table, or part of a logged table: for example SecurityEvent · file access (4656, 4660, 4663, 4670). ' +
      'For each one: table present or not, fed in the window, events actually collected (audit policy, data collection rule), ' +
      'missing columns used by the rules, and whether another source of the same family compensates. Run it first on a new environment: ' +
      'a missing source raises no error, it only returns empty results.',
    reading: {
      decisive: 'A "Not covered" row: no source of the family is fed, the listed rules cannot show anything of that kind of event.',
      context: 'An "Events not collected" row: the table is fed but not with these EventIDs (audit off, no SACL, data collection rule too narrow). ' +
        '"Missing columns": the schema differs, the matching branch is skipped.',
      noise: 'A missing source "Compensated by" another: an equivalent source provides the same events.',
    },
    scenarios: [],
    v1: true,
    window: { before: rule.window.before, after: rule.window.after,
      beforeMinutes: toMinutes(rule.window.before), afterMinutes: toMinutes(rule.window.after) },
    render: 'table',
    tables: [...tables].sort(),
    sources: ruleSources(tables),
    platforms: queryDefender ? ['sentinel', 'defender-unified', 'defender'] : ['sentinel', 'defender-unified'],
    placeholders: ['VALUE', 'T0', 'BEFORE_MIN', 'AFTER_MIN'],
    query: assembled,
    ...(queryDefender ? { queryDefender } : {}),
    source: 'scripts/build.mjs (generated)',
    columns: {},
    eventTables: [],
    channels: {},
  });
}

  ////////////////////////////////////////////////
 // "Discovery: where the value appears" rules    //
////////////////////////////////////////////////
// One generated rule per indicator (XX-S9): searches the value in every table (union *) and returns one row per
// (table, location): column or JSON path where it is found, likely role (source, destination), table statistics
// (volume, period, devices, accounts, actions), and whether the indicator's rules already read that location.
// Locations "Not read by the rules" are the sources still to model.

// Search term per indicator family: has compares whole terms ("CONTOSO\jdoe" → "jdoe")
const DISCOVERY_TERM = { ip: 'Value', account: 'ValueSam', email: 'ValueMail', web: 'ValueDomain', device: 'ValueShort',
  process: 'ValueFile', application: 'Value', hash: 'ValueHash' };

function discoveryQuery(term, known, depth = 5) {
  const rows = known.map((k) => `    ${kqlStr(k.table)}, ${kqlStr(k.column)}, ${kqlStr(k.rules.join(', '))}`);
  // One JSON level expanded: keys of a dictionary, indexes of an array; only branches that contain the value are kept
  const level = [
    '    | extend _t = gettype(V)',
    '    | extend _k = case(_t == "dictionary", bag_keys(V), _t == "array", range(0, array_length(V) - 1, 1), dynamic(["."]))',
    '    | mv-expand _k',
    '    | extend Path = case(_t == "dictionary", strcat(Path, "[\'", tostring(_k), "\']"), _t == "array", strcat(Path, "[", tostring(_k), "]"), Path),',
    '        V = case(_t == "dictionary", V[tostring(_k)], _t == "array", V[toint(_k)], V)',
    '    | where tostring(V) has Term',
  ];
  return [
    `let Term = ${term};`,
    'let SamplePerTable = 200;',
    '// Columns read by the rules of the indicator (generated at build): table, column, rules',
    'let Known = datatable(Table:string, Column:string, Rules:string) [',
    rows.join(',\n'),
    '];',
    '// 1. A single pass over every table',
    'let Hits = materialize(',
    '    union isfuzzy=true withsource=Table *',
    '    | where TimeGenerated between (StartTimestamp .. EndTimestamp)',
    '    | where * has Term',
    '    | extend Row = pack_all(true));',
    '// 2. Per-table statistics, over every row found',
    'let PerTable = Hits',
    '    | extend Host = tolower(coalesce(tostring(Row.DeviceName), tostring(Row.Computer), tostring(Row.HostName), tostring(Row.DvcHostname),',
    '          tostring(Row.SrcHostname), tostring(Row.SourceHostName))),',
    '        Account = tolower(coalesce(tostring(Row.AccountName), tostring(Row.UserPrincipalName), tostring(Row.TargetUserName),',
    '          tostring(Row.SubjectUserName), tostring(Row.InitiatingProcessAccountName), tostring(Row.AccountUpn), tostring(Row.UserId),',
    '          tostring(Row.Caller), tostring(Row.SrcUsername))),',
    '        Action = coalesce(tostring(Row.ActionType), tostring(Row.EventID), tostring(Row.Operation), tostring(Row.OperationName),',
    '          tostring(Row.ResultType), tostring(Row.DeviceAction))',
    '    | summarize TableEvents = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),',
    '        ActiveHours = dcount(bin(TimeGenerated, 1h)), Hosts = dcountif(Host, isnotempty(Host)), Accounts = dcountif(Account, isnotempty(Account)),',
    '        TopHosts = make_set_if(Host, isnotempty(Host), 5), TopAccounts = make_set_if(Account, isnotempty(Account), 5),',
    '        TopActions = make_set_if(Action, isnotempty(Action), 5)',
    '        by Table;',
    `// 3. Exact locations: column, or path in a JSON (${depth} levels), on a sample per table`,
    'let Locations = Hits',
    '    | sort by Table asc',
    '    | where row_number(1, prev(Table) != Table) <= SamplePerTable',
    '    | mv-apply Cell = Row on (',
    '        extend Column = tostring(bag_keys(Cell)[0])',
    '        | extend Raw = Cell[Column]',
    '        | where tostring(Raw) has Term',
    '        | project Column, Raw)',
    '    | project Table, Column, Path = Column, Text = substring(tostring(Raw), 0, 3000),',
    '        V = iff(gettype(Raw) in ("dictionary", "array"), Raw, parse_json(tostring(Raw)))',
    ...Array.from({ length: depth }, () => level).flat(),
    '    | extend Exact = tolower(tostring(V)) == tolower(Term) or tostring(V) == Value',
    '    | extend Role = case(Path matches regex @"(?i)(src|source|client|caller|remote|initiat|sender|origin)", "source",',
    '        Path matches regex @"(?i)(dst|dest|target|local|recipient|server)", "destination",',
    '        "undetermined")',
    '    | summarize LocationRows = count(), ExactRows = countif(Exact), Example = take_any(Text) by Table, Column, Path, Role;',
    'Locations',
    '| join kind=leftouter (Known) on Table, Column',
    '| join kind=inner (PerTable) on Table',
    '| extend Status = case(isempty(Rules), "Not read by the rules", Path == Column, "Read by the rules", "Column read, JSON path to check")',
    '| extend Order = case(Status startswith "Not read", 0, Status startswith "Column", 1, 2)',
    '| sort by Order asc, TableEvents desc',
    '| project Table, Path, Role, Status, Rules, LocationRows, ExactRows, TableEvents, FirstSeen, LastSeen, ActiveHours,',
    '    Hosts, Accounts, TopHosts, TopAccounts, TopActions, Example',
  ].join('\n');
}

for (const [pfx, list] of Object.entries(groups)) {
  const sourceRules = list.filter((r) => !/-S0$/.test(r.id));
  const indicators = [...new Set(sourceRules.flatMap((r) => r.indicators))];
  const rule = {
    id: `${pfx}-S9`,
    name: 'Discovery: where the value appears',
    indicators: PREFIX_INDICATORS[pfx].filter((i) => indicators.includes(i)),
    action: 'statistics',
    window: { before: '4h', after: '1h' },
  };
  const h = header(rule);
  const kind = h.kinds[0];
  const parts = resolveFragments([`indicators/${kind}`], frags, errors, `(generated) ${rule.id}`);
  const knownMap = new Map();
  for (const r of sourceRules) for (const t of r.eventTables) for (const c of r.columns[t] || []) {
    const k = `${t}\u0000${c}`;
    (knownMap.get(k) || knownMap.set(k, { table: t, column: c, rules: [] }).get(k)).rules.push(r.id);
  }
  const known = [...knownMap.values()].filter((k) => !['TimeGenerated', 'Timestamp'].includes(k.column))
    .sort((a, b) => a.table.localeCompare(b.table) || a.column.localeCompare(b.column));
  const body = discoveryQuery(DISCOVERY_TERM[kind] || 'Value', known);
  const assembled = expandMacros([h.text, ...parts.map((p) => p.text), body].join('\n'));
  for (const d of kql.validate(assembled)) {
    const msg = `(generated) [${rule.id}] ${d.severity} ${d.code} l.${d.line}:${d.col} ${d.message}\n      > ${d.snippet.trim()}`;
    if (d.severity === 'Error') errors.push(msg); else warnings.push(msg);
  }
  const queryDefender = assembled.replace(/\bTimeGenerated\b/g, 'Timestamp');
  rules.push({
    id: rule.id,
    name: rule.name,
    category: `${ACTIONS.statistics.label} · ${INDICATORS[rule.indicators[0]].label}`,
    indicators: rule.indicators,
    action: 'statistics',
    description: 'Looks for the value in every table (union * | where * has) and returns one row per table and location: column, or path ' +
      'in a JSON (for example RawEventData[\'1\'][\'parameters\'][\'ip\']), likely role (source or destination), value alone or ' +
      'inside a text, and table statistics (volume, first and last seen, active hours, top devices, accounts ' +
      'and actions). Status compares each location with the columns the rules of the indicator read: ' +
      '"Not read by the rules" points to a source to add to the catalog. Expensive: keep a short window.',
    reading: {
      decisive: 'A "Not read by the rules" location with exact rows: the value is there and no pivot looks at it.',
      context: 'Tables where the value appears with many devices or accounts (shared IP, service account), or only in free text.',
      noise: 'Matches in text fields (messages, command lines, URLs) that mention the value without carrying it.',
    },
    scenarios: [],
    v1: false,
    window: { before: rule.window.before, after: rule.window.after,
      beforeMinutes: toMinutes(rule.window.before), afterMinutes: toMinutes(rule.window.after) },
    render: 'table',
    tables: [],
    sources: [],
    platforms: ['sentinel', 'defender-unified', 'defender'],
    placeholders: ['VALUE', 'T0', 'BEFORE_MIN', 'AFTER_MIN'],
    query: assembled,
    queryDefender,
    source: 'scripts/build.mjs (generated)',
    columns: {},
    eventTables: [],
    channels: {},
  });
}
for (const r of rules) { delete r.columns; delete r.eventTables; delete r.channels; }

rules.sort((a, b) => {
  const ia = Object.keys(INDICATORS).indexOf(a.indicators[0]);
  const ib = Object.keys(INDICATORS).indexOf(b.indicators[0]);
  return ia - ib || ACTIONS[a.action].order - ACTIONS[b.action].order || a.id.localeCompare(b.id, 'en', { numeric: true });
});

  ////////////////////////////////////////////////
 // Scenarios (guided playbooks, #8 / app #32)  //
////////////////////////////////////////////////

// scenarios/<id>.yml : { id: S<n>, name, description, indicator, steps: [{ ruleId, carry? }] }.
// `carry` = type of value taken from the step's result for the next step: it must appear in the `targets`
// of the step's rule, and the next rule must accept that type. An unknown rule is an error
// (the userscript itself skips such a scenario with a warning: defense in depth).
const scenarios = [];
{
  const dir = path.join(ROOT, 'scenarios');
  const files = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.yml')).sort() : [];
  const byId = new Map(rules.map((r) => [r.id, r]));
  for (const file of files) {
    const rel = `scenarios/${file}`;
    let sc;
    try { sc = yaml.load(fs.readFileSync(path.join(dir, file), 'utf8')); } catch (e) { errors.push(`${rel}: invalid YAML (${e.message})`); continue; }
    if (!sc || !/^S[0-9]+$/.test(sc.id || '')) { errors.push(`${rel}: missing id S<n>`); continue; }
    if (`${sc.id}.yml` !== file) errors.push(`${rel}: the file name must be ${sc.id}.yml`);
    if (!sc.name || !sc.description) errors.push(`${rel}: name and description are required`);
    if (!INDICATORS[sc.indicator]) { errors.push(`${rel}: unknown indicator ${sc.indicator}`); continue; }
    if (!Array.isArray(sc.steps) || sc.steps.length < 2) { errors.push(`${rel}: at least 2 steps`); continue; }
    let current = sc.indicator;
    sc.steps.forEach((st, i) => {
      const r = byId.get(st.ruleId);
      if (!r) { errors.push(`${rel}: step ${i + 1}, unknown rule ${st.ruleId}`); return; }
      if (!r.indicators.includes(current)) errors.push(`${rel}: step ${i + 1}, ${st.ruleId} does not take type ${current}`);
      if (st.carry !== undefined) {
        if (!INDICATORS[st.carry]) errors.push(`${rel}: step ${i + 1}, unknown carry ${st.carry}`);
        else if (!(r.targets || []).includes(st.carry)) errors.push(`${rel}: step ${i + 1}, ${st.ruleId} does not produce ${st.carry} (targets)`);
        if (i === sc.steps.length - 1) warnings.push(`${rel}: carry on the last step has no effect`);
        current = st.carry;
      }
    });
    scenarios.push({ id: sc.id, name: sc.name, description: String(sc.description).trim(), indicator: sc.indicator,
      steps: sc.steps.map((st) => ({ ruleId: st.ruleId, ...(st.carry ? { carry: st.carry } : {}) })) });
  }
  // Membership published on each rule (existing `scenarios` field), on top of what the YAML declares
  for (const sc of scenarios) for (const st of sc.steps) {
    const r = byId.get(st.ruleId);
    if (r && !r.scenarios.includes(sc.id)) r.scenarios.push(sc.id);
  }
}

  /////////////////////////
 // Report and output   //
/////////////////////////

for (const w of warnings) console.warn(`! ${w}`);
for (const e of errors) console.error(`X ${e}`);
const byInd = {};
for (const r of rules) byInd[r.indicators[0]] = (byInd[r.indicators[0]] || 0) + 1;
console.log(`\n${rules.length} rules (${Object.entries(byInd).map(([k, v]) => `${k}: ${v}`).join(', ')}), ` +
  `${rules.filter((r) => r.v1).length} in V1, ${Object.keys(frags).length} fragments, ${scenarios.length} scenarios, ` +
  `${errors.length} error(s), ${warnings.length} warning(s).`);

if (errors.length || (STRICT && warnings.length)) process.exit(1);
if (CHECK_ONLY) process.exit(0);

const dist = path.join(ROOT, 'dist');
fs.mkdirSync(dist, { recursive: true });
const indicatorsOut = Object.fromEntries(Object.entries(INDICATORS).map(([k, v]) => [k, { label: v.label, patterns: v.patterns }]));
const actionsOut = Object.fromEntries(Object.entries(ACTIONS).map(([k, v]) => [k, { label: v.label }]));

  ////////////////////////////////////////////////////
 // 2d: formatVersion + published locations       //
////////////////////////////////////////////////////

// `formatVersion` MUST stay 1. core/catalog-validate.ts (userscript) treats any other value as a
// BLOCKING error: publishing 2 would make ALL already deployed userscripts reject the catalog, and they
// only update through Tampermonkey. To move to 2 one day: first widen SUPPORTED_FORMAT_VERSION in the
// script, publish the script, wait for it to be deployed, and only then bump it here. Never the reverse.
const FORMAT_VERSION = 1;

// locations: indicators/<type>/locations.yml, two ORDERED lists (confirmed then uncertain).
// The order matters (decision of 22/10): for a column that is a candidate for several types, the type
// that lists it as `confirmed` must win the preselection. So confirmed THEN uncertain are concatenated,
// and `core/detection.ts` (3a) reads that order; INDICATOR_PRIORITY is now only used for the regex fallback.
function loadLocations() {
  const out = {};
  for (const type of Object.keys(INDICATORS)) {
    const file = path.join(ROOT, 'indicators', type, 'locations.yml');
    if (!fs.existsSync(file)) continue;
    const doc = yaml.load(fs.readFileSync(file, 'utf8')) || {};
    const pairs = [...(doc.confirmed || []), ...(doc.uncertain || [])]
      .filter((k) => typeof k === 'string')
      // Last-resort guard: a _CL table must never leave the repository (rule 2), and a malformed
      // pair would break detection in the userscript.
      .filter((k) => /^[A-Za-z0-9_]+\.[A-Za-z0-9_]+$/.test(k) && !/_CL\./i.test(k));
    const seen = new Set();
    const ordered = pairs.filter((k) => !seen.has(k) && seen.add(k)); // dedupe, keeping the order
    if (ordered.length) out[type] = ordered;
  }
  return out;
}
const locationsOut = loadLocations();

const full = {
  name: pkg.name,
  version: pkg.version,
  formatVersion: FORMAT_VERSION,
  generatedAt: new Date().toISOString(),
  placeholders: PLACEHOLDERS,
  indicators: indicatorsOut,
  actions: actionsOut,
  locations: locationsOut,
  sources: Object.fromEntries(Object.entries(SOURCES).map(([k, v]) => [k, { label: v.label, tables: v.tables, hint: v.hint,
    ...(v.optional ? { optional: true } : {}),
    members: v.members.map((m) => ({ source: m.key, table: m.table, ...(m.filter ? { filter: m.filter } : {}), ...(m.hint ? { hint: m.hint } : {}) })) }])),
  rules,
  scenarios,
};
fs.writeFileSync(path.join(dist, 'pivot-rules.json'), JSON.stringify(full, null, 2) + '\n');
// Legacy userscript format: [{ name, category, description, query }]
const flat = rules.map((r) => ({
  name: `[${r.id}] ${r.name}`,
  category: r.category,
  description: r.description,
  query: r.query,
}));
fs.writeFileSync(path.join(dist, 'pivot-rules.flat.json'), JSON.stringify(flat, null, 2) + '\n');

// Readable catalog (Markdown), generated for review.
const md = [`# Pivot rules catalog (${pkg.version})`, '',
  `${rules.length} rules, ${rules.filter((r) => r.v1).length} of them in V1. Generated by \`npm run build\`: do not edit by hand.`, ''];
md.push('## Source families', '',
  'A family is covered as soon as one of its tables is fed. The XX-S0 "Source coverage" rules check it on your environment.', '',
  '| Family | Tables | Rules |', '| --- | --- | --- |');
for (const [id, f] of Object.entries(SOURCES)) {
  const users = rules.filter((r) => !/-S0$/.test(r.id) && r.sources.includes(id)).map((r) => r.id);
  md.push(`| ${f.label}${f.optional ? ' (facultative)' : ''} | ${f.tables.join(', ')} | ${users.join(', ') || '—'} |`);
}
md.push('');
// Scenarios (guided playbooks)
if (scenarios.length) {
  md.push('## Guided scenarios', '', 'Rule chains EasyPivot walks through step by step; "→ type": value carried from the result to the next step.', '');
  for (const sc of scenarios) {
    md.push(`### ${sc.id} · ${sc.name}`, '', sc.description, '');
    sc.steps.forEach((st, i) => {
      const r = rules.find((x) => x.id === st.ruleId);
      md.push(`${i + 1}. ${st.ruleId} · ${r ? r.name : '?'}${st.carry ? ` → ${INDICATORS[st.carry].label}` : ''}`);
    });
    md.push('');
  }
}
// Cross pivots (U3): Pivot/Timeline rules per start indicator (row) and produced type (column, `targets`).
// "2 (1 D)" = 2 rules, 1 of them with a Defender XDR variant; "—" = no rule.
{
  const kinds = Object.keys(INDICATORS);
  const label = (k) => INDICATORS[k].label;
  md.push('## Cross-pivot matrix', '',
    'Pivot and Timeline rules by starting indicator (row) and indicator type present in the result (column, `targets` field). "D": with a Defender XDR variant.', '',
    `| Start \\ Target | ${kinds.map(label).join(' | ')} |`, `| --- | ${kinds.map(() => '---').join(' | ')} |`);
  for (const from of kinds) {
    const cells = kinds.map((to) => {
      if (to === from) return '·';
      const list = rules.filter((r) => r.action !== 'statistics' && r.indicators.includes(from) && (r.targets || []).includes(to));
      if (!list.length) return '—';
      const d = list.filter((r) => r.queryDefender).length;
      return `${list.length}${d ? ` (${d} D)` : ''}`;
    });
    md.push(`| ${label(from)} | ${cells.join(' | ')} |`);
  }
  md.push('');
}
for (const [ind, meta] of Object.entries(INDICATORS)) {
  const list = rules.filter((r) => r.indicators[0] === ind);
  if (!list.length) continue;
  md.push(`## ${meta.label}`, '', '| ID | Action | Rule | Window | V1 | Tables |', '| --- | --- | --- | --- | --- | --- |');
  for (const r of list) {
    md.push(`| ${r.id} | ${ACTIONS[r.action].label} | ${r.name} | −${r.window.before} / +${r.window.after} | ${r.v1 ? 'yes' : ''} | ${r.tables.join(', ')} |`);
  }
  md.push('');
  for (const r of list) {
    md.push(`### ${r.id} · ${r.name}`, '', r.description, '');
    if (r.reading) {
      if (r.reading.decisive) md.push(`- **Decisive:** ${r.reading.decisive}`);
      if (r.reading.context) md.push(`- **Context:** ${r.reading.context}`);
      if (r.reading.noise) md.push(`- **Noise:** ${r.reading.noise}`);
      md.push('');
    }
    md.push(`Sources: ${r.sources.map((f) => SOURCES[f].label).join(' ; ')}` +
      (r.enrichment ? ` · Roles read from: ${r.enrichment.join(', ')}` : ''), '');
    if (r.targets) md.push(`Targets: ${r.targets.map((k) => INDICATORS[k].label).join(', ')}`, '');
    md.push(`Scenarios: ${r.scenarios.join(', ') || '—'} · Platforms: ${r.platforms.join(', ')} · Source: \`${r.source}\``, '');
  }
}
fs.writeFileSync(path.join(dist, 'CATALOGUE.md'), md.join('\n'));
console.log('Written: dist/pivot-rules.json, dist/pivot-rules.flat.json, dist/CATALOGUE.md');
