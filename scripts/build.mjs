#!/usr/bin/env node
// Compile les règles YAML en JSON
// 1. Lecture des fichiers YAML
// 2. Validation du schéma
// 3. Assemblage

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
 // Variables du menu //
///////////////////////

// Valeurs sur lesquelles on peut pivoter
const INDICATORS = {
  ip: { label: 'Adresse IP', header: 'ip',
    patterns: ['^(25[0-5]|2[0-4]\\d|1?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}$', '^(?=.*:.*:)[0-9a-fA-F:.]{2,45}$'] },
  account: { label: 'Compte', header: 'account',
    patterns: ['^[^@\\s"]+@[^@\\s"]+\\.[^@\\s"]+$', '^[\\w.-]+\\\\[\\w.$-]+$'] },
  email: { label: 'Adresse e-mail', header: 'email', patterns: ['^[^@\\s"]+@[^@\\s"]+\\.[^@\\s"]+$'] },
  url: { label: 'URL', header: 'web', patterns: ['^https?://\\S+$'] },
  domain: { label: 'Domaine', header: 'web',
    patterns: ['^(?=.{4,253}$)([a-zA-Z0-9-]{1,63}\\.)+[a-zA-Z]{2,63}\\.?$'] },
  device: { label: 'Machine', header: 'device',
    patterns: ['^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}(\\.[a-zA-Z0-9-]{1,63})*$'] },
  process: { label: 'Processus', header: 'process',
    patterns: ['(?i)^(.*[\\\\/])?[^\\\\/]+\\.(exe|dll|ps1|bat|cmd|vbs|vbe|js|jse|wsf|hta|msi|scr|com|cpl|lnk)$'] },
  application: { label: 'Application', header: 'application',
    patterns: ['^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'] },
  hash: { label: 'Hash', header: 'hash', patterns: ['^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$'] },
};
const ACTIONS = {
  statistics: { label: 'Statistics', order: 0 }, // Stats sur l'IOC -> Utilisation par table sur un temps T, ...
  pivot: { label: 'Pivot', order: 1 },           // Fonctions de pivot sur IOC : IP -> Comptes connectés sur avec l'IP
  timeline: { label: 'Timeline', order: 2 },     // Comportements observés : 4625 -> 4624 -> 4768 
};
const PLACEHOLDERS = {
  VALUE: 'Valeur sélectionnée. Insérée dans une chaîne @"…" .',
  T0: 'Instant de référence au format ISO 8601 (TimeGenerated de la ligne sélectionnée).',
  BEFORE_MIN: 'Fenêtre avant T0, en minutes (entier).',
  AFTER_MIN: 'Fenêtre après T0, en minutes (entier).',
  HOST: 'Optionnel : machine associée (DeviceName ou Computer).',
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

// Blocs « // @sentinel-only:begin … // @sentinel-only:end » d'un fragment ou d'une règle : branches de union lisant des
// tables absentes de Defender XDR. Ils sont retirés de la variante Defender (queryDefender), qui reste donc possible.
const stripSentinelOnly = (text) =>
  text.replace(/^[ \t]*\/\/\s*@sentinel-only:begin[\s\S]*?^[ \t]*\/\/\s*@sentinel-only:end[ \t]*\n?/gm, '');
// Commentaires retirés avant la détection des tables (un nom de table cité en commentaire n'est pas une source).
const stripComments = (text) => text.replace(/(^|[^:])\/\/.*$/gm, '$1');

function expandMacros(text) {
  // Remplacement de XMLFIELD(expr, Nom) par une regex d'extraction du champ.
  return text.replace(/XMLFIELD\(\s*([A-Za-z_][\w.]*)\s*,\s*([A-Za-z]\w*)\s*\)/g,
    (_, expr, field) => `extract(@'<Data Name="${field}">([^<]*)</Data>', 1, ${expr})`);
}

function loadFragments() {
  const dir = path.join(ROOT, 'fragments');
  const frags = {};
  for (const file of walk(dir).filter((f) => f.endsWith('.kql'))) {
    const rel = path.relative(dir, file).replace(/\\/g, '/').replace(/\.kql$/, '');
    const text = fs.readFileSync(file, 'utf8').replace(/\s+$/, '');
    const requires = [...text.matchAll(/^\/\/\s*@requires:\s*(.+)$/gm)]
      .flatMap((m) => m[1].split(',').map((s) => s.trim()).filter(Boolean));
    frags[rel] = { name: rel, text, defenderText: stripSentinelOnly(text), requires };
  }
  return frags;
}

function resolveFragments(names, frags, errors, ctx) {
  const order = [];
  const seen = new Set();
  const visit = (n, stack) => {
    if (seen.has(n)) return;
    if (stack.includes(n)) { errors.push(`${ctx}: dépendance circulaire ${[...stack, n].join(' → ')}`); return; }
    const f = frags[n];
    if (!f) { errors.push(`${ctx}: fragment inconnu « ${n} »`); return; }
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

// Familles de sources : table -> familles (schema/sources.json)
// Une famille liste des membres : une table entière, ou une partie d'une table journalisée (canal + EventID, ou filtre where).
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
      if (filter === undefined) throw new Error(`schema/sources.json : canal ${m.channel} inconnu pour ${m.table}`);
      if (filter) parts.push(filter);
    }
    if (m.ids) parts.push(`EventID in (${m.ids.join(', ')})`);
    if (m.where) parts.push(m.where);
    const channel = { security: 'Sécurité', sysmon: 'Sysmon', system: 'Système' }[m.channel];
    const key = m.label ? `${m.table} · ${channel ? `${channel} · ` : ''}${m.label}${m.ids ? ` (${m.ids.join(', ')})` : ''}` : m.table;
    return { ...m, family: id, key, filter: parts.join(' and ') };
  });
  f.tables = [...new Set(f.members.map((m) => m.table))];
  for (const t of f.tables) (tableFamilies[t] ||= []).push(id);
}
// Événements lus par canal : EventID passés à _WinSecurity (journal Sécurité) et à _Sysmon ; liste vide = tous.
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
    `// sentinel-pivot-rules ${pkg.version}. Paramètres : {{VALUE}}, {{T0}}, {{BEFORE_MIN}}, {{AFTER_MIN}}${(rule.context || []).map((c) => `, {{${c}}}`).join('')}`,
    `let Value = trim(@"\\s", @"{{VALUE}}");`,
    `let T0 = coalesce(todatetime(@"{{T0}}"), now());`,
    `let Before = coalesce(tolong(@"{{BEFORE_MIN}}"), ${toMinutes(rule.window.before)}) * 1m; // défaut : ${rule.window.before}`,
    `let After = coalesce(tolong(@"{{AFTER_MIN}}"), ${toMinutes(rule.window.after)}) * 1m; // défaut : ${rule.window.after}`,
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
    errors.push(`${rel}: YAML invalide — ${e.message}`);
    continue;
  }
  if (!validateRule(rule)) {
    for (const e of validateRule.errors) errors.push(`${rel}: ${e.instancePath || '(racine)'} ${e.message}`);
    continue;
  }
  if (ids.has(rule.id)) errors.push(`${rel}: identifiant en double ${rule.id}`);
  ids.add(rule.id);
  const prefix = PREFIX_INDICATORS[rule.id.slice(0, 2)];
  if (/-S(0|9)$/.test(rule.id)) errors.push(`${rel}: l'identifiant ${rule.id} est réservé aux règles générées (S0 couverture, S9 découverte)`);
  if (!prefix.includes(rule.indicators[0])) errors.push(`${rel}: le préfixe ${rule.id.slice(0, 2)} ne correspond pas à l'indicateur ${rule.indicators[0]}`);

  const h = header(rule);
  if (h.kinds.length > 1) { errors.push(`${rel}: indicateurs de familles différentes (${h.kinds.join(', ')})`); continue; }
  const parts = resolveFragments([`indicators/${h.kinds[0]}`, ...(rule.uses || [])], frags, errors, rel);
  const body = rule.query.replace(/\s+$/, '');
  const assembled = expandMacros([h.text, ...parts.map((p) => p.text), body].join('\n'));

  for (const d of kql.validate(assembled)) {
    const msg = `${rel} [${rule.id}] ${d.severity} ${d.code} l.${d.line}:${d.col} ${d.message}\n      > ${d.snippet.trim()}`;
    if (d.severity === 'Error') errors.push(msg); else warnings.push(msg);
  }

  const tables = detectTables(body + '\n' + parts.map((p) => p.text).join('\n'), tableNames);
  for (const t of tables) if (!tableFamilies[t]) errors.push(`${rel}: table ${t} absente de schema/sources.json (famille de sources inconnue)`);
  // Tables d'événements (requête et fragments hors rôles) et tables lues seulement pour annoter les rôles
  const eventTables = detectTables(body + '\n' + parts.filter((p) => p.name !== 'roles').map((p) => p.text).join('\n'), tableNames)
    .filter((t) => tableFamilies[t]);
  const enrichment = tables.filter((t) => !eventTables.includes(t));
  // Variante Defender : fragments sans leurs blocs @sentinel-only ; possible si toutes les tables restantes sont Defender XDR
  const defenderBody = stripSentinelOnly(body);
  const defenderTables = detectTables(defenderBody + '\n' + parts.map((p) => p.defenderText).join('\n'), tableNames);
  // Fonctions retirées de la variante Defender (définies dans un bloc @sentinel-only) encore appelées : pas de variante
  const strippedFns = parts.flatMap((p) => [...p.text.matchAll(/^let (_\w+) =/gm)].map((m) => m[1])
    .filter((fn) => !new RegExp(`^let ${fn} =`, 'm').test(p.defenderText)));
  const callsStripped = strippedFns.some((fn) => new RegExp(`\\b${fn}\\(`).test(stripComments(defenderBody + '\n' +
    parts.map((p) => p.defenderText).join('\n'))));
  const xdrOnly = !callsStripped && defenderTables.some((t) => xdr.has(t)) && defenderTables.every((t) => xdr.has(t) || defenderOptional.has(t));
  let queryDefender;
  if (xdrOnly) {
    queryDefender = expandMacros([h.text, ...parts.map((p) => p.defenderText), defenderBody].join('\n')).replace(/\bTimeGenerated\b/g, 'Timestamp');
    for (const d of kql.validate(queryDefender)) {
      if (d.severity === 'Error') errors.push(`${rel} [${rule.id}] (variante Defender) ${d.code} l.${d.line}: ${d.message}`);
    }
  }
  const usedPlaceholders = ['VALUE', 'T0', 'BEFORE_MIN', 'AFTER_MIN', ...(rule.context || [])];
  if ((rule.context || []).includes('HOST') && !/\bHostFilter\b/.test(body)) {
    warnings.push(`${rel}: contexte HOST déclaré mais HostFilter jamais utilisé`);
  }

  rules.push({
    id: rule.id,
    name: rule.name,
    category: `${ACTIONS[rule.action].label} · ${INDICATORS[rule.indicators[0]].label}`,
    indicators: rule.indicators,
    action: rule.action,
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
    columns: kql.columnsUsed(assembled),
    eventTables,
    channels: readChannels(expandMacros([...parts.filter((p) => p.name !== 'roles').map((p) => p.text), body].join('\n'))),
  });
}

  ////////////////////////////////////////
 // Règles « Couverture des sources »  //
////////////////////////////////////////
// Une règle générée par indicateur (XX-S0) : pour chaque table lue par les règles de l'indicateur, dit si elle existe,
// si elle est alimentée sur la fenêtre, s'il lui manque des colonnes utilisées par les règles, et si son absence est
// compensée par une autre table de la même famille. Rend visible ce que les union isfuzzy=true ignorent en silence.

const kqlStr = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
const kqlArr = (a) => `dynamic([${a.map(kqlStr).join(', ')}])`;
const timeCol = (t) => (kql.tables[t] && kql.tables[t].TimeGenerated ? 'TimeGenerated' : 'Timestamp');
// Familles pertinentes pour un ensemble de tables : celles dont une table lue n'appartient qu'à elles, ou dont toutes les
// tables sont lues. SecurityEvent (authentifications, processus, registre…) ne fait pas apparaître la famille « processus »
// dans la couverture d'un indicateur qui ne lit aucune autre table de processus.
function relevantFamilies(tables) {
  const used = new Set(tables);
  return new Set(Object.entries(SOURCES)
    .filter(([id, f]) => f.tables.every((t) => used.has(t)) || tables.some((t) => tableFamilies[t].length === 1 && tableFamilies[t][0] === id))
    .map(([id]) => id));
}

// Familles de sources d'une règle : celles de ses tables d'événements, limitées aux familles pertinentes
function ruleSources(eventTables) {
  const relevant = relevantFamilies(eventTables);
  return [...new Set(eventTables.flatMap((t) => {
    const r = tableFamilies[t].filter((f) => relevant.has(f));
    return r.length ? r : tableFamilies[t];
  }))].sort((a, b) => famOrder.indexOf(a) - famOrder.indexOf(b));
}

// Un membre est lu par une règle si elle lit sa table et, pour un membre de canal, au moins un de ses EventID.
function memberReadBy(m, r) {
  if (!r.eventTables.includes(m.table)) return false;
  if (!m.channel) return true;
  const ids = r.channels[m.channel];
  return ids === 'all' || (Array.isArray(ids) && (!m.ids || m.ids.some((i) => ids.includes(i))));
}

// Membres contrôlés pour un ensemble de règles, avec les règles qui les lisent. Une table lue sans membre correspondant
// (lecture directe, enrichissement des rôles) est contrôlée en entier.
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
    '    | extend Status = case(not(Exists), "Absente ou inaccessible", isnull(TableEvents) or isnull(Events), "Colonnes manquantes",',
    '        TableEvents == 0, "Vide sur la fenêtre", Events == 0, "Événements non collectés",',
    '        array_length(MissingColumns) > 0, "Colonnes manquantes", "Alimentée"));',
    'let Fed = Rows',
    '    | mv-expand Family = Families to typeof(string)',
    '    | summarize FedMembers = make_set_if(Member, Status == "Alimentée") by Family;',
    'Rows',
    '| mv-expand Family = Families to typeof(string)',
    '| join kind=leftouter (Fed) on Family',
    '| extend FedMembers = iff(array_length(FedMembers) == 0, dynamic([""]), FedMembers)',
    '| mv-expand Alt = FedMembers to typeof(string)',
    '| summarize Families = make_set(Family), Alternatives = make_set_if(Alt, isnotempty(Alt) and Alt != Member),',
    '    Uncovered = make_set_if(Family, isempty(Alt)), FamilyHints = make_set_if(tostring(Hints[Family]), isempty(Alt))',
    '    by Member, Status, Optional, MemberHint, Events, LastEvent, Missing = strcat_array(MissingColumns, ", "), Rules = strcat_array(Rules, ", ")',
    '| extend Impact = case(Status == "Alimentée", "",',
    '    Optional, "Facultative : enrichissement des rôles uniquement",',
    '    array_length(Uncovered) > 0, strcat("Non couvert : ", strcat_array(Uncovered, ", "), ". Résultats incomplets pour ", Rules),',
    '    strcat("Compensé par ", strcat_array(Alternatives, ", ")))',
    '| extend Order = case(Status == "Alimentée", 4, Optional, 3, array_length(Uncovered) > 0, 0, Status == "Colonnes manquantes", 1, 2)',
    '| sort by Order asc, Member asc',
    '| project Status, Source = Member, Events, LastEvent, Impact, MissingColumns = Missing, Families, Rules,',
    '    Remediation = iff(Status == "Alimentée" or Optional, "", iff(isnotempty(MemberHint), MemberHint, strcat_array(FamilyHints, " ")))',
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
    name: 'Couverture des sources',
    indicators: PREFIX_INDICATORS[pfx].filter((i) => indicators.includes(i)),
    action: 'statistics',
    window: { before: '3d', after: '1d' },
  };
  const h = header(rule);
  const assembled = [h.text, coverageQuery(members, usage)].join('\n');
  for (const d of kql.validate(assembled)) {
    const msg = `(généré) [${rule.id}] ${d.severity} ${d.code} l.${d.line}:${d.col} ${d.message}\n      > ${d.snippet.trim()}`;
    if (d.severity === 'Error') errors.push(msg); else warnings.push(msg);
  }
  const xdrMembers = members.filter((m) => xdr.has(m.table));
  let queryDefender;
  if (xdrMembers.length) {
    queryDefender = [h.text, coverageQuery(xdrMembers, usage)].join('\n').replace(/\bTimeGenerated\b/g, 'Timestamp');
    for (const d of kql.validate(queryDefender)) {
      if (d.severity === 'Error') errors.push(`(généré) [${rule.id}] (variante Defender) ${d.code} l.${d.line}: ${d.message}`);
    }
  }
  rules.push({
    id: rule.id,
    name: rule.name,
    category: `${ACTIONS.statistics.label} · ${INDICATORS[rule.indicators[0]].label}`,
    indicators: rule.indicators,
    action: 'statistics',
    description: `État des ${members.length} sources lues par les règles « ${INDICATORS[rule.indicators[0]].label} » (${tables.length} tables). ` +
      'Une source est une table, ou une partie d\'une table journalisée : par exemple SecurityEvent · accès aux fichiers (4656, 4660, 4663, 4670). ' +
      'Pour chacune : table présente ou non, alimentée sur la fenêtre, événements réellement collectés (stratégie d\'audit, règle de collecte), ' +
      'colonnes utilisées manquantes, et si une autre source de la même famille compense. À lancer en premier sur un nouvel environnement : ' +
      'une source absente ne produit aucune erreur, seulement des résultats vides.',
    reading: {
      decisive: 'Ligne « Non couvert » : aucune source de la famille n\'est alimentée, les règles citées ne peuvent rien montrer de ce type d\'événement.',
      context: 'Ligne « Événements non collectés » : la table est alimentée mais pas ces EventID (audit non activé, SACL absente, règle de collecte trop restreinte). ' +
        '« Colonnes manquantes » : le schéma diffère, la branche correspondante est ignorée.',
      noise: 'Source absente mais « Compensé par » : une source équivalente fournit les mêmes événements.',
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
    source: 'scripts/build.mjs (généré)',
    columns: {},
    eventTables: [],
    channels: {},
  });
}

  ////////////////////////////////////////////////
 // Règles « Découverte : où apparaît la valeur » //
////////////////////////////////////////////////
// Une règle générée par indicateur (XX-S9) : recherche la valeur dans toutes les tables (union *), et rend une ligne par
// (table, emplacement) : colonne ou chemin JSON où elle se trouve, rôle probable (source, destination), statistiques de la
// table (volume, période, machines, comptes, actions), et si les règles de l'indicateur lisent déjà cet emplacement.
// Les emplacements « Non lu par les règles » sont les sources à modéliser.

// Terme recherché par famille d'indicateur : has compare des termes entiers (« CONTOSO\jdoe » → « jdoe »)
const DISCOVERY_TERM = { ip: 'Value', account: 'ValueSam', email: 'ValueMail', web: 'ValueDomain', device: 'ValueShort',
  process: 'ValueFile', application: 'Value', hash: 'ValueHash' };

function discoveryQuery(term, known, depth = 5) {
  const rows = known.map((k) => `    ${kqlStr(k.table)}, ${kqlStr(k.column)}, ${kqlStr(k.rules.join(', '))}`);
  // Un niveau de JSON déplié : clés d'un dictionnaire, indices d'un tableau ; seules les branches qui contiennent la valeur restent
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
    '// Colonnes lues par les règles de l\'indicateur (générées au build) : table, colonne, règles',
    'let Known = datatable(Table:string, Column:string, Rules:string) [',
    rows.join(',\n'),
    '];',
    '// 1. Un seul passage sur toutes les tables',
    'let Hits = materialize(',
    '    union isfuzzy=true withsource=Table *',
    '    | where TimeGenerated between (StartTimestamp .. EndTimestamp)',
    '    | where * has Term',
    '    | extend Row = pack_all(true));',
    '// 2. Statistiques par table, sur toutes les lignes trouvées',
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
    `// 3. Emplacements exacts : colonne, ou chemin dans un JSON (${depth} niveaux), sur un échantillon par table`,
    'let Locations = Hits',
    '    | sort by Table asc',
    '    | where row_number(1, prev(Table) != Table) <= SamplePerTable',
    '    | mv-apply Cell = Row on (',
    '        extend Column = tostring(bag_keys(Cell)[0])',
    '        | extend Raw = Cell[Column]',
    '        | where tostring(Raw) has Term',
    '        | project Column, Raw)',
    '    | project Table, Column, Path = Column, Text = substring(tostring(Raw), 0, 300),',
    '        V = iff(gettype(Raw) in ("dictionary", "array"), Raw, parse_json(tostring(Raw)))',
    ...Array.from({ length: depth }, () => level).flat(),
    '    | extend Exact = tolower(tostring(V)) == tolower(Term) or tostring(V) == Value',
    '    | extend Role = case(Path matches regex @"(?i)(src|source|client|caller|remote|initiat|sender|origin)", "source",',
    '        Path matches regex @"(?i)(dst|dest|target|local|recipient|server)", "destination",',
    '        "indéterminé")',
    '    | summarize LocationRows = count(), ExactRows = countif(Exact), Example = take_any(Text) by Table, Column, Path, Role;',
    'Locations',
    '| join kind=leftouter (Known) on Table, Column',
    '| join kind=inner (PerTable) on Table',
    '| extend Status = case(isempty(Rules), "Non lu par les règles", Path == Column, "Lu par les règles", "Colonne lue, chemin JSON à vérifier")',
    '| extend Order = case(Status startswith "Non lu", 0, Status startswith "Colonne", 1, 2)',
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
    name: 'Découverte : où apparaît la valeur',
    indicators: PREFIX_INDICATORS[pfx].filter((i) => indicators.includes(i)),
    action: 'statistics',
    window: { before: '4h', after: '1h' },
  };
  const h = header(rule);
  const kind = h.kinds[0];
  const parts = resolveFragments([`indicators/${kind}`], frags, errors, `(généré) ${rule.id}`);
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
    const msg = `(généré) [${rule.id}] ${d.severity} ${d.code} l.${d.line}:${d.col} ${d.message}\n      > ${d.snippet.trim()}`;
    if (d.severity === 'Error') errors.push(msg); else warnings.push(msg);
  }
  const queryDefender = assembled.replace(/\bTimeGenerated\b/g, 'Timestamp');
  rules.push({
    id: rule.id,
    name: rule.name,
    category: `${ACTIONS.statistics.label} · ${INDICATORS[rule.indicators[0]].label}`,
    indicators: rule.indicators,
    action: 'statistics',
    description: 'Cherche la valeur dans toutes les tables (union * | where * has) et rend une ligne par table et par emplacement : colonne, ou chemin ' +
      'dans un JSON (par exemple RawEventData[\'1\'][\'parameters\'][\'ip\']), rôle probable (source ou destination), valeur seule ou ' +
      'noyée dans un texte, et statistiques de la table (volume, première et dernière apparition, heures actives, machines, comptes ' +
      'et actions les plus fréquentes). Status compare chaque emplacement aux colonnes lues par les règles de l\'indicateur : ' +
      '« Non lu par les règles » signale une source à ajouter au modèle. Coûteuse : garder une fenêtre courte.',
    reading: {
      decisive: 'Emplacement « Non lu par les règles » avec des lignes exactes : la valeur est là, aucun pivot ne la regarde.',
      context: 'Tables où la valeur apparaît avec beaucoup de machines ou de comptes (IP partagée, compte de service), ou seulement dans un texte libre.',
      noise: 'Correspondances dans des champs de texte (messages, lignes de commande, URL) qui citent la valeur sans la porter.',
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
    source: 'scripts/build.mjs (généré)',
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

  /////////////////////////
 // Rapport et écriture //
/////////////////////////

for (const w of warnings) console.warn(`! ${w}`);
for (const e of errors) console.error(`X ${e}`);
const byInd = {};
for (const r of rules) byInd[r.indicators[0]] = (byInd[r.indicators[0]] || 0) + 1;
console.log(`\n${rules.length} règles (${Object.entries(byInd).map(([k, v]) => `${k}: ${v}`).join(', ')}), ` +
  `${rules.filter((r) => r.v1).length} en V1, ${Object.keys(frags).length} fragments, ` +
  `${errors.length} erreur(s), ${warnings.length} avertissement(s).`);

if (errors.length || (STRICT && warnings.length)) process.exit(1);
if (CHECK_ONLY) process.exit(0);

const dist = path.join(ROOT, 'dist');
fs.mkdirSync(dist, { recursive: true });
const indicatorsOut = Object.fromEntries(Object.entries(INDICATORS).map(([k, v]) => [k, { label: v.label, patterns: v.patterns }]));
const actionsOut = Object.fromEntries(Object.entries(ACTIONS).map(([k, v]) => [k, { label: v.label }]));
const full = {
  name: pkg.name,
  version: pkg.version,
  generatedAt: new Date().toISOString(),
  placeholders: PLACEHOLDERS,
  indicators: indicatorsOut,
  actions: actionsOut,
  sources: Object.fromEntries(Object.entries(SOURCES).map(([k, v]) => [k, { label: v.label, tables: v.tables, hint: v.hint,
    ...(v.optional ? { optional: true } : {}),
    members: v.members.map((m) => ({ source: m.key, table: m.table, ...(m.filter ? { filter: m.filter } : {}), ...(m.hint ? { hint: m.hint } : {}) })) }])),
  rules,
};
fs.writeFileSync(path.join(dist, 'pivot-rules.json'), JSON.stringify(full, null, 2) + '\n');
// Format historique de l'userscript : [{ name, category, description, query }]
const flat = rules.map((r) => ({
  name: `[${r.id}] ${r.name}`,
  category: r.category,
  description: r.description,
  query: r.query,
}));
fs.writeFileSync(path.join(dist, 'pivot-rules.flat.json'), JSON.stringify(flat, null, 2) + '\n');

// Catalogue lisible (Markdown), généré pour la relecture.
const md = [`# Catalogue des règles de pivot (${pkg.version})`, '',
  `${rules.length} règles, dont ${rules.filter((r) => r.v1).length} en V1. Fichier généré par \`npm run build\` : ne pas modifier à la main.`, ''];
md.push('## Familles de sources', '',
  'Une famille est couverte dès qu\'une de ses tables est alimentée. Les règles XX-S0 « Couverture des sources » le vérifient sur l\'environnement.', '',
  '| Famille | Tables | Règles |', '| --- | --- | --- |');
for (const [id, f] of Object.entries(SOURCES)) {
  const users = rules.filter((r) => !/-S0$/.test(r.id) && r.sources.includes(id)).map((r) => r.id);
  md.push(`| ${f.label}${f.optional ? ' (facultative)' : ''} | ${f.tables.join(', ')} | ${users.join(', ') || '—'} |`);
}
md.push('');
for (const [ind, meta] of Object.entries(INDICATORS)) {
  const list = rules.filter((r) => r.indicators[0] === ind);
  if (!list.length) continue;
  md.push(`## ${meta.label}`, '', '| ID | Action | Règle | Fenêtre | V1 | Tables |', '| --- | --- | --- | --- | --- | --- |');
  for (const r of list) {
    md.push(`| ${r.id} | ${ACTIONS[r.action].label} | ${r.name} | −${r.window.before} / +${r.window.after} | ${r.v1 ? 'oui' : ''} | ${r.tables.join(', ')} |`);
  }
  md.push('');
  for (const r of list) {
    md.push(`### ${r.id} · ${r.name}`, '', r.description, '');
    if (r.reading) {
      if (r.reading.decisive) md.push(`- **Tranche :** ${r.reading.decisive}`);
      if (r.reading.context) md.push(`- **Contexte :** ${r.reading.context}`);
      if (r.reading.noise) md.push(`- **Bruit :** ${r.reading.noise}`);
      md.push('');
    }
    md.push(`Sources : ${r.sources.map((f) => SOURCES[f].label).join(' ; ')}` +
      (r.enrichment ? ` · Rôles lus dans : ${r.enrichment.join(', ')}` : ''), '');
    md.push(`Scénarios : ${r.scenarios.join(', ') || '—'} · Plateformes : ${r.platforms.join(', ')} · Source : \`${r.source}\``, '');
  }
}
fs.writeFileSync(path.join(dist, 'CATALOGUE.md'), md.join('\n'));
console.log('Écrit : dist/pivot-rules.json, dist/pivot-rules.flat.json, dist/CATALOGUE.md');
