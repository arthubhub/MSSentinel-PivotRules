#!/usr/bin/env node
// End-to-end tests on dist/pivot-rules.json:
// 1. every query, once filled with a sample value (quotes included), is still valid KQL;
// 2. each indicator's sample value is matched by its patterns;
// 3. no {{…}} parameter is left after filling;
// 4. a Defender variant only reads Defender XDR tables (or tolerated ones, such as Watchlist) and never TimeGenerated;
// 5. every table read belongs to a source family, and every indicator has its coverage rule (XX-S0)
//    and its discovery rule (XX-S9);
// 6. `targets` only lists known types;
// 7. no leftover tag: `query` without @defender-only, queryDefender without @sentinel-only or @defender-only
//    (each variant is also validated by point 1).
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { fillQuery, matchesIndicator } from './fill-query.mjs';

const require = createRequire(import.meta.url);
const { createValidator } = require('./kql-validator.cjs');
const root = new URL('..', import.meta.url).pathname;
const bundle = JSON.parse(fs.readFileSync(new URL('../dist/pivot-rules.json', import.meta.url), 'utf8'));
const kql = createValidator(root);

const samples = {
  ip: '10.1.2.3',
  account: 'CONTOSO\\jdoe',
  email: 'jdoe@contoso.com',
  url: 'https://evil.example/login?next="x"',
  domain: 'evil.example',
  device: 'PC01.contoso.local',
  process: 'C:\\Users\\jdoe\\AppData\\Local\\node\\node.exe',
  application: '00000003-0000-0000-c000-000000000000',
  hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
};
let failures = 0;
const fail = (m) => { failures++; console.error(`✖ ${m}`); };

for (const [k, v] of Object.entries(samples)) {
  if (k === 'url') continue; // the sample's quotes are only there to test escaping
  if (!matchesIndicator(bundle.indicators[k], v)) fail(`pattern ${k} does not match "${v}"`);
}
// 6. `targets` (cross pivots): known types only (email → email is legitimate: correspondents).
for (const rule of bundle.rules) {
  for (const t of rule.targets || []) if (!(t in samples)) fail(`${rule.id}: unknown target ${t}`);
}

// 7. Variant tags: removed (or unwrapped) at build time
for (const rule of bundle.rules) {
  if (/@defender-only:(begin|end)/.test(rule.query)) fail(`${rule.id} (query) contains a @defender-only tag`);
  if (rule.queryDefender && /@(sentinel|defender)-only:(begin|end)/.test(rule.queryDefender)) fail(`${rule.id} (queryDefender) contains a variant tag`);
}

for (const rule of bundle.rules) {
  for (const variant of ['query', 'queryDefender']) {
    if (!rule[variant]) continue;
    for (const ind of rule.indicators) {
      const q = fillQuery(rule, { value: samples[ind], t0: '2026-10-08T10:00:00Z', beforeMinutes: 90, afterMinutes: 15, host: 'PC01' }, variant);
      if (/\{\{\w+\}\}/.test(q)) fail(`${rule.id} (${variant}, ${ind}): parameter not replaced`);
      for (const d of kql.validate(q)) if (d.severity === 'Error') fail(`${rule.id} (${variant}, ${ind}) l.${d.line} ${d.message}`);
    }
  }
}
const tableNames = Object.keys(kql.tables).sort((a, b) => b.length - a.length);
const allowedDefender = new Set([...kql.xdrTables, ...kql.defenderOptional]);
const tablesIn = (q) => {
  // Strip strings (a table name quoted in text is not a read) and comments
  const code = q.replace(/@"[^"]*"|@'[^']*'|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'/g, '""').replace(/(^|[^:])\/\/.*$/gm, '$1');
  return tableNames.filter((t) => new RegExp(`(^|[^\\w.])${t}(?![\\w])`, 'm').test(code));
};
const familyTables = new Set(Object.values(bundle.sources || {}).flatMap((f) => f.tables));
for (const rule of bundle.rules) {
  if (rule.queryDefender) {
    for (const t of tablesIn(rule.queryDefender)) if (!allowedDefender.has(t)) fail(`${rule.id} (queryDefender) reads ${t}, not in Defender XDR`);
    if (/\bTimeGenerated\b/.test(rule.queryDefender)) fail(`${rule.id} (queryDefender) contains TimeGenerated`);
    if (!rule.platforms.includes('defender')) fail(`${rule.id}: queryDefender without the defender platform`);
  }
  for (const t of rule.tables) if (!familyTables.has(t)) fail(`${rule.id}: table ${t} has no source family`);
  if (!/-S9$/.test(rule.id) && (!rule.sources || !rule.sources.length)) fail(`${rule.id}: empty sources field`);
}
for (const pfx of new Set(bundle.rules.map((r) => r.id.slice(0, 2)))) {
  if (!bundle.rules.some((r) => r.id === `${pfx}-S9`)) fail(`indicator ${pfx} has no discovery rule ${pfx}-S9`);
  const cov = bundle.rules.find((r) => r.id === `${pfx}-S0`);
  if (!cov) { fail(`indicator ${pfx} has no coverage rule ${pfx}-S0`); continue; }
  const read = new Set(bundle.rules.filter((r) => r.id.startsWith(pfx) && r !== cov).flatMap((r) => r.tables));
  for (const t of read) if (!cov.tables.includes(t)) fail(`${pfx}-S0 does not check table ${t}`);
}
console.log(failures ? `${failures} failure(s)` : `OK: ${bundle.rules.length} rules filled and validated.`);
process.exit(failures ? 1 : 0);
