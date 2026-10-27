#!/usr/bin/env node
// Génère indicators/<type>/locations.yml + indicators/REVIEW-locations.md (#31).
//
// Objectif : pour chaque type d'indicateur EasyPivot, une liste de paires "Table.Colonne" où ce type de
// valeur est effectivement trouvé, triée par ordre de confiance décroissant :
//   1. Les règles existantes sont la vérité de terrain : on repère, dans le texte des règles (et de 4
//      fragments partagés qui énumèrent des colonnes pour un paramètre générique), les colonnes RÉELLEMENT
//      comparées à la valeur (`== Value`, `has Value`…) — pas celles simplement projetées ou utilisées
//      pour grouper (`by Machine = tolower(DeviceName)` ne prouve rien sur le type de DeviceName).
//   2. La table de correspondance `Entity` Defender → type EasyPivot (relevée sur tenant réel, cf. plan).
//   3. Les motifs de nom de colonne sur les 105 schémas (`schemas/`) — la moins fiable des trois.
//
// Décision du 23/10 : les trois niveaux sont retenus. Les deux premiers vont dans `confirmed`, le
// troisième dans `uncertain`, et les DEUX sont destinés à la publication. `locations` est une aide à la
// présélection, pas une contrainte : le panneau propose toujours les 9 types et signale « La valeur ne
// correspond pas à ce type, pivot possible quand même », donc l'analyste peut toujours pivoter
// autrement — indispensable, puisqu'un nom de machine peut être une adresse IP. Une paire fausse coûte
// un clic ; une paire absente coûte une présélection utile.
//
// Ce script n'écrit toujours PAS dans pivot-rules.json : la publication se fait en 2d. Il n'est pas
// câblé dans build/check/test (script npm indépendant).
//
// Déterminisme : toute sortie (locations.yml, rapport) est triée ; deux exécutions successives ne
// produisent aucune différence si rien n'a changé dans rules/, fragments/ ou schemas/.

import fs from 'node:fs';
import path from 'node:path';
import * as yaml from 'js-yaml';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]);

const INDICATOR_TYPES = ['ip', 'account', 'email', 'url', 'domain', 'device', 'process', 'application', 'hash'];

  ////////////////////////////////
 // 1. Chargement des schémas  //
////////////////////////////////

// Table -> Set(colonnes exactes). Les champs imbriqués pointés (AdditionalFields.xxx) sont exclus : ce sont
// des sous-champs dynamic, pas des colonnes KQL ("Table.AdditionalFields.xxx" serait une paire invalide).
const tableColumns = new Map();
// Nom de colonne sans le suffixe Log Analytics (_s, _d, _t) -> liste de {table, column} (colonne réelle, avec suffixe).
// Les colonnes émises dans locations.yml gardent TOUJOURS leur suffixe : c'est le vrai nom de la colonne KQL.
const byBaseName = new Map();
const stripSuffix = (n) => n.replace(/_(s|d|t)$/, '');

for (const file of fs.readdirSync(path.join(ROOT, 'schemas')).filter((f) => f.endsWith('.json'))) {
  const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'schemas', file), 'utf8'));
  const table = data.table;
  if (/_CL$/i.test(table)) throw new Error(`garde-fou : table personnalisée ${table} dans schemas/ (ne devrait jamais arriver, 2a l'exclut déjà)`);
  const cols = new Set();
  for (const f of data.fields) {
    if (f.name.includes('.')) continue; // sous-champ dynamic imbriqué, pas une colonne KQL
    cols.add(f.name);
    const base = stripSuffix(f.name);
    (byBaseName.get(base) || byBaseName.set(base, []).get(base)).push({ table, column: f.name });
  }
  tableColumns.set(table, cols);
}
const allTables = [...tableColumns.keys()].sort((a, b) => b.length - a.length);

  /////////////////////////////////////////////////////////
 // 2. Table de correspondance Entity Defender -> type   //
/////////////////////////////////////////////////////////
// Reprise exacte de la table du plan (step 0), relevée sur tenant réel : DeviceInfo, DeviceProcessEvents,
// DeviceNetworkEvents, DeviceFileEvents, EmailEvents, EmailUrlInfo, IdentityLogonEvents, CloudAppEvents,
// EntraIdSignInEvents. Les 7 dernières lignes sont les colonnes à Entity=null listées comme ayant
// spécifiquement besoin de `locations` (aucun signal Entity ne les couvre).

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
 // 3. Niveau 1 : vérité de terrain (comparaisons de règle) //
///////////////////////////////////////////////////////////

// Variables dérivées de Value par les fragments indicators/*.kql -> type qu'elles représentent réellement.
// « Value » nu n'est pas ici : son type dépend des indicateurs déclarés par la règle (traité à part).
// ValueMailLocal (partie locale d'un e-mail) est volontairement absente : une comparaison contre cette
// variable (ex. InitiatingProcessAccountName =~ ValueMailLocal) ne prouve pas qu'une colonne contient un
// e-mail, seulement un nom de compte qui ressemble à la partie locale — signal trop faible, exclu plutôt
// que mal classé.
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

// 4 fragments partagés qui énumèrent des colonnes pour un paramètre générique, sur de nombreuses tables :
// _IpEvents(ip), _DomainHits(d), _Signins(ip, upn), _SpnSignins(app, ip). Analysés une seule fois, pour
// eux-mêmes (indépendamment des règles qui les appellent) : la comparaison "RemoteIP == ip" dans
// ip_events.kql est vraie quel que soit l'appelant. Cas particulier documenté, pas une solution générale :
// les autres fragments (win_security, sysmon…) comparent à un paramètre "term" générique, réutilisé pour
// des types différents selon l'appelant, donc exploités à tort donnerait un signal faux ; ils sont ignorés.
const FRAGMENT_TOKENS = {
  'ip_events.kql': { ip: 'ip' },
  'domain_hits.kql': { d: 'domain' },
  'signins.kql': { ip: 'ip', upn: 'account' },
  'spn_signins.kql': { app: 'application', ip: 'ip' },
};

const EQ_OPS = ['==', '=~', '!=', '!~'];
const HAS_OPS = ['has', 'contains', 'startswith', 'endswith'];
const NON_COLUMN = new Set(['true', 'false', 'and', 'or', 'not', 'isempty', 'isnotempty', 'isnull', 'isnotnull']);

// Colonnes "texte libre" où une correspondance par sous-chaîne (has/contains…) est peu fiable, quel que
// soit le type recherché : ligne de commande, XML/JSON brut, message, description…
// "pattern", "parameters", "members" ajoutés après relecture (#31, audit du 22/10) : STIX Pattern
// (ThreatIntelIndicators), Parameters (cmdlet OfficeActivity), Members (liste de membres OfficeActivity) —
// même famille que CommandLine/RawEventData/AdditionalFields (texte ou liste fourre-tout), mais noms qui
// n'auraient pas été couverts par le reste de la liste. Hardcodé : aucun prédicat sur le nom seul ne les
// distingue proprement d'une colonne légitime (voir detectFallbackColumns ci-dessous pour la détection
// structurelle qui, elle, les aurait repérées sans les nommer).
// "targetresources" ajouté le 23/10 sur décision de l'utilisateur : AuditLogs.TargetResources est un
// JSON fourre-tout (ressources ciblées d'une opération Entra ID), confiant à la fois pour account et
// application — c'était le dernier conflit non tranché. Classé fourre-tout, donc écarté des deux.
// "entities" ajouté le 22/10 : SecurityAlert.Entities est un JSON d'entités d'alerte, même famille que
// AdditionalFields. Il était masqué jusque-là parce qu'il tombait en conflit de types ; le conflit ayant
// disparu, il devenait confiant à tort.
const BLOB_RE = /(commandline|raweventdata|^eventdata$|additionalfields|syslogmessage|^message$|details|^content$|^contents$|^body$|subject|useragent|description|failurereason|^text$|^pattern$|^parameters$|^members$|^entities$|^targetresources$)/i;


// Détection structurelle, principielle, des colonnes "de repli" : dans "ColA == Value or ColB has Value"
// (ou l'inverse, "ColB has Value or ColA == Value"), ColB n'est interrogée qu'EN PLUS d'une comparaison
// stricte sur une AUTRE colonne — elle sert à "si on ne l'a pas trouvée ailleurs, cherche dans ce fourre-
// tout". C'est exactement la forme des 3 cas relevés (ObservableValue == Value or Pattern has Value ;
// UserId =~ ValueUpn or Parameters/Members has ValueUpn/ValueMail) : repérée automatiquement, sans
// connaître le nom de la colonne. Couvre aussi Syslog.SyslogMessage et quelques autres déjà dans BLOB_RE
// (double filet, sans dépendre d'un nom codé en dur pour ces cas structurels).
function fallbackColumns(code) {
  const cols = new Set();
  const fwd = /([A-Za-z_][A-Za-z0-9_]*)\s*(?:==|=~)\s*\S+\s+or\s+([A-Za-z_][A-Za-z0-9_]*)\s+(?:has|contains|startswith|endswith)\s+[A-Za-z_][A-Za-z0-9_]*/g;
  const rev = /([A-Za-z_][A-Za-z0-9_]*)\s+(?:has|contains|startswith|endswith)\s+[A-Za-z_][A-Za-z0-9_]*\s+or\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:==|=~)\s*\S+/g;
  for (const m of code.matchAll(fwd)) cols.add(m[2]);
  for (const m of code.matchAll(rev)) cols.add(m[1]);
  return cols;
}
// Pour le type domain spécifiquement : une colonne-URL (Url, RemoteUrl, TargetUrl…) CONTIENT souvent le
// domaine comme sous-chaîne (Url has ValueDomain) sans pour autant être elle-même une colonne de domaine —
// elle est déjà classée "url" par ailleurs. Confiant seulement si le nom contient explicitement "domain",
// ou fait partie d'une courte liste de colonnes de requête/nom DNS. "Name" est volontairement limité à
// DnsEvents.Name (la seule occurrence réelle, DM-P4) : un "Name" générique sur une autre table n'a aucune
// raison d'être un domaine.
const DOMAIN_SAFE_EXACT = new Set(['fqdn', 'dnsquery', 'httphost']);
const isDomainSafe = (table, column) => DOMAIN_SAFE_EXACT.has(stripSuffix(column).toLowerCase()) ||
  (table === 'DnsEvents' && column === 'Name');

const stripComments = (text) => text.replace(/(^|[^:])\/\/.*$/gm, '$1');
// Décolle quelques enrobages simples (tolower(X), tostring(X)…) pour exposer l'identifiant nu, sur
// plusieurs passes (tolower(tostring(X))).
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

// Motifs de nom par type. Défini ici (et non plus bas) parce que scanComparisons s'en sert comme
// garde-fou : une colonne de repli dont le NOM dit déjà le type reste confiante.
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

// Un candidat brut : colonne trouvée comparée à un jeton de valeur connu, pour un ensemble de tables
// candidates (celles citées littéralement dans le texte analysé).
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
        // Le repli structurel ne doit pas déclasser une colonne dont le NOM dit déjà le type :
        // « ComputerIP == Value or ComputerPrivateIPs has Value » interroge bien une liste d'IP, le
        // `has` n'est là que parce que la colonne est multivaluée, pas parce qu'elle est fourre-tout.
        const nameSaysType = !BLOB_RE.test(column) && NAME_PATTERNS[type]?.(column, tokenize(column), table) === true;
        if (EQ_OPS.includes(op)) confident = true;
        else if (fallback.has(column) && !nameSaysType) confident = false; // repli vers un fourre-tout
        else if (type === 'domain') confident = /domain/.test(column.toLowerCase()) || isDomainSafe(table, column);
        else confident = !BLOB_RE.test(column);
        out.push({ table, column, type, confident, op, evidence: `${column} ${op} … (${table})` });
      }
    }
  };

  // Jetons dérivés (ValueXxx, ou paramètre de fragment comme "ip"/"d"/"upn"/"app")
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
  // Jeton nu "Value" : type = indicateur(s) déclaré(s) par la règle (ambigu seulement pour les règles DM,
  // qui déclarent [domain, url] ensemble — Value peut être l'un ou l'autre selon ce que l'analyste a saisi).
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
  // _IsHost(X) / _IsHost(coalesce(X, Y)) : comparaison d'égalité du nom court -> device, fiable.
  for (const m of code.matchAll(/_IsHost\(\s*([^()]*(?:\([^()]*\)[^()]*)?)\s*\)/g)) {
    const inner = m[1].replace(/^coalesce\(|\)$/g, '');
    for (const id of inner.split(',').map((s) => s.trim())) {
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(id)) emit(id, 'device', '==');
    }
  }
  return out;
}

const candidates = []; // { table, column, type, confident, tier, evidence }

// 3a. Règles
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

// 3b. 4 fragments partagés (analysés pour eux-mêmes, cf. commentaire plus haut)
for (const [fname, tokenMap] of Object.entries(FRAGMENT_TOKENS)) {
  const text = fs.readFileSync(path.join(ROOT, 'fragments', fname), 'utf8');
  for (const c of scanComparisons(text, tokenMap, [], null)) {
    candidates.push({ ...c, tier: 'rule', source: `fragments/${fname}` });
  }
}

  ///////////////////////////////////////////
 // 4. Niveau 2 : table Entity (tier 2)    //
///////////////////////////////////////////

for (const [type, names] of Object.entries(ENTITY_MAP)) {
  for (const name of names) {
    for (const { table, column } of byBaseName.get(name) || []) {
      candidates.push({ table, column, type, confident: true, tier: 'entity', evidence: `Entity Defender : colonne ${name}`, source: 'plan (step 0)' });
    }
  }
}

  /////////////////////////////////////////////////////
 // 5. Niveau 3 : motifs de nom (jamais confident)   //
/////////////////////////////////////////////////////

function tokenize(name) {
  // `IPs` au pluriel se découpait en "i" + "ps" (ComputerPrivateIPs -> computer, private, i, ps),
  // donc NAME_PATTERNS.ip ne le reconnaissait pas. Normalisé comme ipv4/ipv6.
  const n = stripSuffix(name).replace(/(?:ipv[46])/ig, 'IP').replace(/IPs(?![a-z])/g, 'IP');
  const toks = [];
  for (const part of n.split(/[^A-Za-z0-9]+/)) {
    if (!part) continue;
    for (const m of part.matchAll(/[A-Z]+(?=[A-Z][a-z]|\d)|[A-Z]?[a-z0-9]+|[A-Z]+/g)) toks.push(m[0].toLowerCase());
  }
  return toks;
}

// Motifs par type, resserrés après une première passe à 925 lignes de relecture (beaucoup de bruit :
// champs CEF génériques DeviceCustomString1(Label), métadonnées *Type/*Role/*EntityKey, compteurs…).
// Un jeton seul (ex. "device") ne suffit plus : il faut un second jeton qui en fait une valeur
// d'identité (name, id, command…), et une liste d'exclusion écarte les métadonnées connues. Tout ce qui
// matche ici va UNIQUEMENT au rapport de relecture, jamais dans locations.yml.
// Exclusion globale : champs CEF "libres" (DeviceCustomString1…) et libellés de champ (…Label) — leur
// type réel dépend du déploiement, pas du nom ; les deviner serait pire que ne rien proposer.
const GLOBAL_SKIP = (toks) => toks.includes('custom') || toks.includes('label');


for (const [table, cols] of tableColumns) {
  for (const column of cols) {
    const toks = tokenize(column);
    if (GLOBAL_SKIP(toks)) continue;
    for (const type of INDICATOR_TYPES) {
      if (NAME_PATTERNS[type](column, toks, table)) {
        candidates.push({ table, column, type, confident: false, tier: 'name-pattern', evidence: `motif de nom (jetons : ${toks.join(', ')})`, source: 'schemas/' });
      }
    }
  }
}

  //////////////////////////////////////////////
 // 6. Fusion : confident vs review, conflits //
//////////////////////////////////////////////

const byPair = new Map(); // "Table.Column" -> { types: Map(type -> [candidates]) }
for (const c of candidates) {
  const key = `${c.table}.${c.column}`;
  const entry = byPair.get(key) || byPair.set(key, { table: c.table, column: c.column, types: new Map() }).get(key);
  (entry.types.get(c.type) || entry.types.set(c.type, []).get(c.type)).push(c);
}

// Colonnes polymorphes connues : une même colonne contient plusieurs types d'indicateur selon la ligne
// (ex. ThreatIntelIndicators.ObservableValue, STIX : IP, domaine, URL ou hash selon Pattern/ObservableKey/
// Data.pattern — pas selon la colonne elle-même). Pas de détection générale ici : un seul cas connu dans
// les 234 paires confiantes, et une heuristique générique (table avec une colonne "clé"/"type" à côté d'une
// colonne de valeur) n'a pas été construite pour un seul exemple. Exclues explicitement du jeu confident
// quel que soit le signal qui les y aurait mises, et placées en relecture avec le motif exact : `locations`
// étant le PREMIER signal de detection.ts (avant Entity et les regex), une colonne polymorphe mal typée y
// est pire qu'une colonne absente.
// Vérifié : ThreatIntelligenceIndicator (table historique) n'a PAS ce problème — colonnes déjà séparées par
// type (NetworkIP, NetworkSourceIP, NetworkDestinationIP, DomainName, Url, FileHashValue…) ; aucune colonne
// de ce type n'y nécessite le même traitement.
const POLYMORPHIC = {
  'ThreatIntelIndicators.ObservableValue': 'Colonne STIX polymorphe : contient une IP, un domaine, une URL ou un ' +
    'hash selon la ligne (discriminée par ObservableKey/Pattern/Data.pattern, pas par la colonne elle-même). ' +
    'ThreatIntelligenceIndicator (table historique) n\'a pas ce problème : colonnes déjà séparées par type.',

  'ThreatIntelIndicators.Pattern': 'Motif STIX (ex. "[ipv4-addr:value = \'…\']") : texte libre qui ENCADRE ' +
    'la valeur au lieu de la contenir, et de type variable comme ObservableValue. Vu en repli dans IP-P5 ' +
    '(`ObservableValue == Value or Pattern has Value`).',
  'SecurityAlert.CompromisedEntity': 'Entité compromise d\'une alerte : un nom d\'hôte ou une IP selon ' +
    'l\'alerte. Utilisée dans les deux sens par les règles — MC-S2 `CompromisedEntity has ValueShort` ' +
    '(device) et IP-P5 `CompromisedEntity == Value` (ip).',
};
// Arbitrage des conflits account/email (décision du 22/10, point 2b-bis de docs/STATE.md).
// Un UPN *est* presque toujours une adresse e-mail : pour ces colonnes, les deux types sont corrects, et
// les écarter des deux (comportement de 2b) perdait la paire au lieu de trancher. Elles sont donc publiées
// dans les DEUX locations.yml ; l'ORDRE (account d'abord, email ensuite) ne se joue pas ici mais dans
// INDICATOR_PRIORITY côté userscript — où email précède encore account, À REVOIR EN 3a, sinon la
// présélection sera email alors que la décision dit account.
// Deux familles de noms, qui ne se promeuvent PAS de la même façon.
//   UPN_SHAPED      : `*Upn`, `UserPrincipalName` — un UPN a la forme d'une adresse e-mail.
//   ACCOUNT_GENERIC : `AccountName`, `UserId` — identifiants de compte qui ne sont PAS des adresses
//                     (`StorageBlobLogs.AccountName` = compte de stockage, `SigninLogs.UserId` /
//                     `AppRequests.UserId` / `DataverseActivity.UserId` = GUID d'objet).
const UPN_SHAPED = (column) => {
  const base = stripSuffix(column);
  return /Upn$/i.test(base) || /^UserPrincipalName$/i.test(base);
};
const ACCOUNT_GENERIC = (column) => /^(AccountName|UserId)$/i.test(stripSuffix(column));
const DUAL_ACCOUNT_EMAIL = (column) => UPN_SHAPED(column) || ACCOUNT_GENERIC(column);
// Asymétrie volontaire : seul le sens email -> account est appliqué.
//   - email confiant + nom de la liste  => account aussi : un UPN/AccountName/UserId qui contient une
//     adresse e-mail est bien un identifiant de compte.
//   - account confiant SEUL             => surtout PAS email : la liste attrape aussi des colonnes qui ne
//     sont pas des adresses — `StorageBlobLogs.AccountName` est un nom de compte de *stockage*, et
//     `SigninLogs.UserId` / `AppRequests.UserId` / `DataverseActivity.UserId` sont des GUID d'objet.
//     Promouvoir en bloc les 48 colonnes que le motif reconnaît (29 tables) publierait ces trois-là comme
//     emplacements d'e-mail. On ne promeut donc que sur preuve d'un signal e-mail réel.
// Décision de l'utilisateur du 23/10 : « si l'UPN est une adresse e-mail, on veut pouvoir pivoter à la
// fois sur le nom d'utilisateur et sur les événements e-mail ; l'analyste choisit ». Le critère est donc
// la VALEUR, pas la table : une colonne UPN déclare les DEUX types, et c'est la forme de la valeur qui
// tranche au moment du pivot.
//   - `UPN_SHAPED` confiant pour account OU email => publié dans les deux (promotion symétrique).
//   - `ACCOUNT_GENERIC` : toujours asymétrique, email -> account seulement. Promouvoir ces noms en bloc
//     publierait `StorageBlobLogs.AccountName` et des GUID `UserId` comme emplacements d'e-mail.
// ⚠️ 3a DOIT restreindre par la forme de la valeur : `locations` propose account + email pour ces
// colonnes, mais une valeur sans « @ » (compte de service, UPN non routable d'un AD on-prem lu par
// Defender for Identity) ne doit PAS proposer les règles e-mail. Sans ce filtre, pivoter sur
// `CORP\\svcsql` offrirait des règles e-mail qui ne renverront rien.
const dualArbitration = (types, column) => {
  if (!types.every((t) => t === 'account' || t === 'email')) return false;
  if (UPN_SHAPED(column)) return types.includes('account') || types.includes('email');
  return ACCOUNT_GENERIC(column) && types.includes('email');
};

// Exclusions dures, décidées à la main : ni `confirmed`, ni `uncertain`, donc jamais publiées.
// À distinguer de POLYMORPHIC (écartée du confiant mais renvoyée en relecture avec son motif) : ici la
// paire est jugée inutilisable, pas incertaine.
const EXCLUDED = {
  // Décision de l'utilisateur du 23/10 : JSON fourre-tout (ressources ciblées d'une opération Entra
  // ID). Elle était confiante pour account ET application — le dernier conflit non tranché.
  'AuditLogs.TargetResources': 'JSON fourre-tout, écarté sur décision du 23/10',
};

const confident = {}; // type -> Set("Table.Column")
for (const t of INDICATOR_TYPES) confident[t] = new Set();
const reviewByType = {}; // type -> [ { pair, candidates, bestTier } ]
for (const t of INDICATOR_TYPES) reviewByType[t] = [];
const conflicts = [];
const arbitrated = []; // paires publiées dans account ET email par la règle ci-dessus

for (const [key, entry] of byPair) {
  const confidentTypes = [...entry.types.entries()].filter(([, cs]) => cs.some((c) => c.confident)).map(([t]) => t);

  // Les exclusions polymorphes passent AVANT la détection de conflits : sinon une colonne écartée à la main
  // (SecurityAlert.CompromisedEntity, device/ip) ressortait en « conflit » et son motif d'exclusion n'était
  // jamais affiché — le lecteur du rapport voyait un arbitrage à rendre là où la décision était déjà prise.
  if (POLYMORPHIC[key] && confidentTypes.length) {
    const reason = POLYMORPHIC[key];
    for (const type of confidentTypes) {
      reviewByType[type].push({ key, table: entry.table, column: entry.column,
        candidates: [{ tier: 'polymorphic', evidence: reason, source: 'audit manuel (#31)' }],
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
    continue; // ambigu : ni publié, ni dans la review "normale" -> section conflits dédiée
  }
  if (confidentTypes.length === 1) {
    confident[confidentTypes[0]].add(key);
    continue;
  }
  // Pas de signal confident pour cette paire : chaque type porteur d'un signal faible va en relecture.
  for (const [type, cs] of entry.types) {
    const tierRank = (c) => (c.tier === 'rule' ? 0 : c.tier === 'entity' ? 1 : 2); // entity ne devrait jamais être non-confident, gardé par sécurité
    const best = cs.slice().sort((a, b) => tierRank(a) - tierRank(b))[0];
    reviewByType[type].push({ key, table: entry.table, column: entry.column, candidates: cs, best });
  }
}

  //////////////////////////////////////
 // 7. Écriture indicators/<t>/...   //
//////////////////////////////////////

// Décision de l'utilisateur du 23/10 : on fait confiance à l'algorithme, et les paires **incertaines
// sont publiées aussi**. `locations` est une AIDE à la présélection, jamais une contrainte : le panneau
// propose toujours les 9 types (`getIndicatorIds()` dans `ui/panel/params-view.ts`) et affiche
// « La valeur ne correspond pas à ce type, pivot possible quand même » — l'analyste peut donc toujours
// pivoter autrement. C'est nécessaire : un nom de machine peut être une adresse IP, et d'autres
// indicateurs ont des comportements analogues. Une paire fausse coûte un clic, une paire manquante
// coûte une présélection utile.
//
// Les deux niveaux restent SÉPARÉS dans le fichier plutôt que fusionnés : c'est ce qui porte l'ordre
// par colonne demandé par la décision 2 (une colonne confirmée pour `account` et incertaine pour
// `email` doit présélectionner `account`). À la publication (2d), les deux listes se concatènent
// dans cet ordre pour donner le `string[]` du format du plan.
const header = (type, nConf, nUnc) => [
  `# locations.yml — ${type}`,
  '# Généré par scripts/generate-locations.mjs (#31). NE PAS ÉDITER À LA MAIN : relancer le script.',
  '# Paires "Table.Colonne" où ce type d\'indicateur peut apparaître.',
  '#   confirmed : signal fort — comparaison dans une règle existante, ou table Entity Defender.',
  '#   uncertain : signal faible — motif de nom de colonne. Publié quand même (décision du 23/10) :',
  '#               aide à la présélection, et l\'analyste peut toujours changer de type dans le panneau.',
  '# L\'ORDRE COMPTE : confirmed avant uncertain. Pour une colonne candidate à plusieurs types, le type',
  '# qui la liste en confirmed gagne la présélection (décision 2 : cet ordre prime sur INDICATOR_PRIORITY).',
  `# ${nConf} confirmée(s), ${nUnc} incertaine(s). Publication dans pivot-rules.json : en 2d.`,
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
  // Même paire jamais dans les deux listes : confirmed gagne.
  const confSet = new Set(conf);
  const unc = [...new Set(reviewByType[type].map((r) => r.key))].filter((k) => !confSet.has(k)).sort();
  const out = header(type, conf.length, unc.length) + yamlList('confirmed', conf) + yamlList('uncertain', unc);
  fs.writeFileSync(path.join(ROOT, 'indicators', type, 'locations.yml'), out);
}

  ///////////////////////////////////
 // 8. Rapport de relecture (MD)  //
///////////////////////////////////

const TIER_LABEL = { rule: 'règle (comparaison faible/sous-chaîne)', entity: 'Entity Defender',
  'name-pattern': 'motif de nom (schémas)', polymorphic: 'colonne polymorphe (écartée par audit)' };
const md = [];
md.push('# Correspondances incertaines — `locations` (#31)', '');
md.push('Généré par `scripts/generate-locations.mjs`. **Rien ici n\'est publié** dans `pivot-rules.json` : ' +
  'ce rapport sert à la relecture humaine avant intégration (consigne du plan, phase 2b).', '');
md.push('Pour chaque paire `Table.Colonne`, le ou les types candidats, le niveau d\'où vient le signal et la preuve. ' +
  'Classées par type, du signal le plus probable (comparaison de règle sur une sous-chaîne) au moins probable (motif de nom seul).', '');

const totalConfident = Object.values(confident).reduce((s, set) => s + set.size, 0);
const totalReview = Object.values(reviewByType).reduce((s, l) => s + l.length, 0);
md.push('## Résumé', '', '| Type | Confiant (publié dans locations.yml) | Incertain (ce rapport) |', '| --- | --- | --- |');
for (const type of INDICATOR_TYPES) md.push(`| ${type} | ${confident[type].size} | ${reviewByType[type].length} |`);
md.push(`| **Total** | **${totalConfident}** | **${totalReview}** |`);
md.push('', `Conflits (même colonne confiante pour deux types différents) : **${conflicts.length}** — voir section dédiée.`);
md.push(`Arbitrages account/email appliqués (paire publiée dans les deux types) : **${arbitrated.length}** — voir section dédiée.`, '');

// polymorphic en tête : ce sont des exclusions décidées à la main, les plus utiles à relire.
const tierOrder = { polymorphic: -1, rule: 0, entity: 1, 'name-pattern': 2 };
for (const type of INDICATOR_TYPES) {
  const list = reviewByType[type];
  if (!list.length) continue;
  list.sort((a, b) => tierOrder[a.best.tier] - tierOrder[b.best.tier] || a.key.localeCompare(b.key));
  md.push(`## ${type} (${list.length})`, '', '| Table.Colonne | Niveau | Preuve | Source |', '| --- | --- | --- | --- |');
  for (const r of list) {
    const sources = [...new Set(r.candidates.map((c) => c.source))].slice(0, 3).join('; ');
    md.push(`| \`${r.key}\` | ${TIER_LABEL[r.best.tier]} | ${r.best.evidence} | ${sources} |`);
  }
  md.push('');
}

if (arbitrated.length) {
  md.push('## Arbitrage account/email (publié dans les DEUX types)', '',
    'Décision du 22/10 : les colonnes `*Upn`, `UserPrincipalName`, `AccountName`, `UserId` confiantes pour ' +
    '`email` sont **account d\'abord, puis email** — publiées dans les deux `locations.yml` au lieu d\'être ' +
    'écartées des deux. L\'ordre de présélection est porté par `INDICATOR_PRIORITY` côté userscript (à revoir ' +
    'en 3a). Les colonnes de la même famille confiantes pour `account` **seulement** ne sont volontairement ' +
    'pas promues en `email` (`StorageBlobLogs.AccountName` est un compte de stockage, `SigninLogs.UserId` un GUID).', '',
    '| Table.Colonne | Types confiants d\'origine | Détail |', '| --- | --- | --- |');
  for (const a of arbitrated.sort((x, y) => x.key.localeCompare(y.key))) {
    const detail = a.types.map((t) => `${t}: ${a.entry.types.get(t).map((x) => x.evidence).join(' / ')}`).join(' — ');
    md.push(`| \`${a.key}\` | ${a.types.join(', ')} | ${detail} |`);
  }
  md.push('');
}

if (conflicts.length) {
  md.push('## Conflits (colonne confiante pour plusieurs types)', '', '| Table.Colonne | Types en conflit | Détail |', '| --- | --- | --- |');
  for (const c of conflicts.sort((a, b) => a.key.localeCompare(b.key))) {
    const detail = c.types.map((t) => `${t}: ${c.entry.types.get(t).map((x) => x.evidence).join(' / ')}`).join(' — ');
    md.push(`| \`${c.key}\` | ${c.types.join(', ')} | ${detail} |`);
  }
  md.push('');
}

fs.writeFileSync(path.join(ROOT, 'indicators', 'REVIEW-locations.md'), md.join('\n'));

console.log(`locations : ${totalConfident} paire(s) confiante(s) (${INDICATOR_TYPES.map((t) => `${t}: ${confident[t].size}`).join(', ')}), ` +
  `${totalReview} en relecture, ${conflicts.length} conflit(s), ${arbitrated.length} arbitrage(s) account/email.`);
console.log('Écrit : indicators/<type>/locations.yml (9 fichiers), indicators/REVIEW-locations.md');
console.log('Rappel : PAS encore câblé dans pivot-rules.json. En attente de relecture humaine (#31).');
