#!/usr/bin/env node
// Régénère schema/tables.json à partir de la référence officielle des tables Azure Monitor.
//
// Usage :
// 1. git clone --depth 1 --filter=blob:none --sparse https://github.com/MicrosoftDocs/azure-monitor-docs.git
// 2. cd azure-monitor-docs && git sparse-checkout set articles/azure-monitor/reference/tables && cd ..
// 3. node scripts/update-schemas.mjs azure-monitor-docs/articles/azure-monitor/reference/tables
import fs from 'node:fs';
import path from 'node:path';

const [dir, ...rest] = process.argv.slice(2);
if (!dir) {
  console.error('Usage: node scripts/update-schemas.mjs <dossier tables> [--add Table1,Table2]');
  process.exit(1);
}
const out = new URL('../schema/tables.json', import.meta.url);
const current = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, 'utf8')) : {};
const wanted = new Set(Object.keys(current));
const addIdx = rest.indexOf('--add');
if (addIdx >= 0) for (const t of (rest[addIdx + 1] || '').split(',')) if (t) wanted.add(t);

const tables = {};
for (const f of fs.readdirSync(dir)) {
  if (!f.endsWith('.md')) continue;
  const txt = fs.readFileSync(path.join(dir, f), 'utf8');
  const name = (txt.match(/^# (\w+)\s*$/m) || [])[1];
  if (!name || (wanted.size && !wanted.has(name))) continue;
  const section = txt.split(/^## Columns\s*$/m)[1] || '';
  const cols = {};
  for (const line of section.split('\n')) {
    if (/^## /.test(line)) break;
    const m = line.match(/^\|\s*([A-Za-z_]\w*)\s*\|\s*(\w+)\s*\|/);
    if (m && m[1] !== 'Column') cols[m[1]] = m[2];
  }
  tables[name] = cols;
}
const sorted = Object.fromEntries(Object.keys(tables).sort().map((k) => [k, tables[k]]));
fs.writeFileSync(out, JSON.stringify(sorted, null, 1) + '\n');
console.log(`${Object.keys(sorted).length} tables écrites dans schema/tables.json`);
