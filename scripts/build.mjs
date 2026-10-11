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
    frags[rel] = { name: rel, text, requires };
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
  for (const t of tableNames) if (new RegExp(`(^|[^\\w.])${t}(?![\\w])`, 'm').test(query)) found.add(t);
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
const frags = loadFragments();

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
    'let StartTime = T0 - Before;',
    'let EndTime = T0 + After;',
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
  const prefix = { IP: 'ip', AC: 'account', EM: 'email', DM: ['url', 'domain'], MC: 'device', PR: 'process', AP: 'application', HS: 'hash' }[rule.id.slice(0, 2)];
  if (![].concat(prefix).includes(rule.indicators[0])) errors.push(`${rel}: le préfixe ${rule.id.slice(0, 2)} ne correspond pas à l'indicateur ${rule.indicators[0]}`);

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
  const xdrOnly = tables.length > 0 && tables.every((t) => xdr.has(t));
  let queryDefender;
  if (xdrOnly) {
    queryDefender = assembled.replace(/\bTimeGenerated\b/g, 'Timestamp');
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
    platforms: xdrOnly ? ['sentinel', 'defender-unified', 'defender'] : ['sentinel', 'defender-unified'],
    placeholders: usedPlaceholders,
    ...(rule.notes ? { notes: rule.notes.trim() } : {}),
    query: assembled,
    ...(queryDefender ? { queryDefender } : {}),
    source: rel.replace(/\\/g, '/'),
  });
}

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
    md.push(`Scénarios : ${r.scenarios.join(', ') || '—'} · Plateformes : ${r.platforms.join(', ')} · Source : \`${r.source}\``, '');
  }
}
fs.writeFileSync(path.join(dist, 'CATALOGUE.md'), md.join('\n'));
console.log('Écrit : dist/pivot-rules.json, dist/pivot-rules.flat.json, dist/CATALOGUE.md');
