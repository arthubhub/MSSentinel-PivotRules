#!/usr/bin/env node
// Imports table schemas into schemas/<Table>.json, in one uniform format
// { table, fields: [{ name, type }] } (#30).
//
// Two sources, merged (not just a copy of schemas-import/) because they do not fully overlap:
// - schemas-import/*.json: tenant export provided by the user, already in this format.
//   Authoritative when a table exists in both (the export is fresher than the docs).
// - schema/tables.json: Microsoft Docs reference, flat format { Table: { Column: type } }.
//   Only used as a complement, for tables missing from schemas-import/ (normalized ASIM
//   tables, DnsEvents, Watchlist… still read by the rules; see docs/STATE.md 2a).
//
// Filters applied on import (no-op on the export provided on 21/10: 0 _CL table, 0 "source"
// field found; kept anyway for future imports, do not remove them as dead code):
// - drop every /_CL$/i table, from both sources;
// - drop any "source" field carried by the table object.
//
// Usage: node scripts/import-schemas.mjs (or npm run import-schemas), to run again after each
// new export dropped into schemas-import/.
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const IMPORT_DIR = path.join(ROOT, 'schemas-import');
const TABLES_JSON = path.join(ROOT, 'schema/tables.json');
const OUT_DIR = path.join(ROOT, 'schemas');

const isCustomLog = (name) => /_CL$/i.test(name);

fs.mkdirSync(OUT_DIR, { recursive: true });

// 1. Authoritative source: schemas-import/ (tenant export)
const merged = new Map();
let skippedCL = 0;
for (const file of fs.readdirSync(IMPORT_DIR).filter((f) => f.endsWith('.json'))) {
  const data = JSON.parse(fs.readFileSync(path.join(IMPORT_DIR, file), 'utf8'));
  if (isCustomLog(data.table)) { skippedCL++; continue; }
  delete data.source; // optional field not kept in schemas/ (filter kept for future imports)
  merged.set(data.table, { table: data.table, fields: data.fields });
}
const fromImportCount = merged.size;

// 2. Complement: schema/tables.json, only for tables missing from schemas-import/
const tablesJson = JSON.parse(fs.readFileSync(TABLES_JSON, 'utf8'));
const fromTablesJson = [];
for (const [table, cols] of Object.entries(tablesJson)) {
  if (merged.has(table)) continue;
  if (isCustomLog(table)) { skippedCL++; continue; }
  fromTablesJson.push(table);
  merged.set(table, { table, fields: Object.entries(cols).map(([name, type]) => ({ name, type })) });
}

// 3. Write one file per table
for (const [table, schema] of merged) {
  fs.writeFileSync(path.join(OUT_DIR, `${table}.json`), JSON.stringify(schema, null, 2) + '\n');
}

// 4. Report
console.log(`${merged.size} schemas written to schemas/:`);
console.log(`  - ${fromImportCount} from schemas-import/ (tenant export, authoritative)`);
console.log(`  - ${fromTablesJson.length} from schema/tables.json (missing from the export): ${fromTablesJson.sort().join(', ') || '—'}`);
console.log(`  - ${skippedCL} _CL table(s) excluded`);
