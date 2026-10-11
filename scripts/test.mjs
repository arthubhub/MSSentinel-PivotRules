#!/usr/bin/env node
// Tests de bout en bout sur dist/pivot-rules.json :
// 1. chaque requête, une fois remplie avec une valeur d'exemple (y compris des guillemets), reste du KQL valide ;
// 2. la valeur d'exemple de chaque indicateur est reconnue par ses motifs ;
// 3. aucun paramètre {{…}} ne subsiste après remplissage.
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
console.log(failures ? `${failures} échec(s)` : `OK : ${bundle.rules.length} règles remplies et validées.`);
process.exit(failures ? 1 : 0);
