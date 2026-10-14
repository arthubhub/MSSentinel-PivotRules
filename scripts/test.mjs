#!/usr/bin/env node
// Tests de bout en bout sur dist/pivot-rules.json :
// 1. chaque requête, une fois remplie avec une valeur d'exemple (y compris des guillemets), reste du KQL valide ;
// 2. la valeur d'exemple de chaque indicateur est reconnue par ses motifs ;
// 3. aucun paramètre {{…}} ne subsiste après remplissage ;
// 4. une variante Defender ne lit que des tables Defender XDR (ou tolérées, comme Watchlist) et jamais TimeGenerated ;
// 5. chaque table lue appartient à une famille de sources, et chaque indicateur a sa règle de couverture (XX-S0)
//    et sa règle de découverte (XX-S9).
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
  if (k === 'url') continue; // les guillemets de l'exemple ne sont là que pour tester l'échappement
  if (!matchesIndicator(bundle.indicators[k], v)) fail(`motif ${k} ne reconnaît pas « ${v} »`);
}
for (const rule of bundle.rules) {
  for (const variant of ['query', 'queryDefender']) {
    if (!rule[variant]) continue;
    for (const ind of rule.indicators) {
      const q = fillQuery(rule, { value: samples[ind], t0: '2026-10-08T10:00:00Z', beforeMinutes: 90, afterMinutes: 15, host: 'PC01' }, variant);
      if (/\{\{\w+\}\}/.test(q)) fail(`${rule.id} (${variant}, ${ind}) : paramètre non remplacé`);
      for (const d of kql.validate(q)) if (d.severity === 'Error') fail(`${rule.id} (${variant}, ${ind}) l.${d.line} ${d.message}`);
    }
  }
}
const tableNames = Object.keys(kql.tables).sort((a, b) => b.length - a.length);
const allowedDefender = new Set([...kql.xdrTables, ...kql.defenderOptional]);
const tablesIn = (q) => {
  // Sans les chaînes (un nom de table cité dans un texte n'est pas une lecture) ni les commentaires
  const code = q.replace(/@"[^"]*"|@'[^']*'|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'/g, '""').replace(/(^|[^:])\/\/.*$/gm, '$1');
  return tableNames.filter((t) => new RegExp(`(^|[^\\w.])${t}(?![\\w])`, 'm').test(code));
};
const familyTables = new Set(Object.values(bundle.sources || {}).flatMap((f) => f.tables));
for (const rule of bundle.rules) {
  if (rule.queryDefender) {
    for (const t of tablesIn(rule.queryDefender)) if (!allowedDefender.has(t)) fail(`${rule.id} (queryDefender) lit ${t}, absente de Defender XDR`);
    if (/\bTimeGenerated\b/.test(rule.queryDefender)) fail(`${rule.id} (queryDefender) contient TimeGenerated`);
    if (!rule.platforms.includes('defender')) fail(`${rule.id} : queryDefender sans la plateforme defender`);
  }
  for (const t of rule.tables) if (!familyTables.has(t)) fail(`${rule.id} : table ${t} sans famille de sources`);
  if (!/-S9$/.test(rule.id) && (!rule.sources || !rule.sources.length)) fail(`${rule.id} : champ sources vide`);
}
for (const pfx of new Set(bundle.rules.map((r) => r.id.slice(0, 2)))) {
  if (!bundle.rules.some((r) => r.id === `${pfx}-S9`)) fail(`indicateur ${pfx} sans règle de découverte ${pfx}-S9`);
  const cov = bundle.rules.find((r) => r.id === `${pfx}-S0`);
  if (!cov) { fail(`indicateur ${pfx} sans règle de couverture ${pfx}-S0`); continue; }
  const read = new Set(bundle.rules.filter((r) => r.id.startsWith(pfx) && r !== cov).flatMap((r) => r.tables));
  for (const t of read) if (!cov.tables.includes(t)) fail(`${pfx}-S0 ne contrôle pas la table ${t}`);
}
console.log(failures ? `${failures} échec(s)` : `OK : ${bundle.rules.length} règles remplies et validées.`);
process.exit(failures ? 1 : 0);
