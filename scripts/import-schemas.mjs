#!/usr/bin/env node
// Importe les schémas de tables dans schemas/<Table>.json, au format uniforme
// { table, fields: [{ name, type }] } (#30).
//
// Deux sources, réunion (pas seulement une copie de schemas-import/) car elles ne se recouvrent
// pas totalement :
// - schemas-import/*.json : export du tenant fourni par l'utilisateur, déjà dans ce format.
//   Source faisant foi quand une table existe dans les deux (export plus frais que la doc).
// - schema/tables.json : référence Microsoft Docs, format plat { Table: { Colonne: type } }.
//   Utilisé seulement en complément, pour les tables absentes de schemas-import/ (tables ASIM
//   normalisées, DnsEvents, Watchlist… encore lues par les règles — voir docs/STATE.md 2a).
//
// Filtres appliqués à l'import (no-op sur l'export fourni le 21/10 : 0 table _CL, 0 champ
// "source" constatés — gardés quand même pour les imports futurs, ne pas les retirer en les
// croyant morts) :
// - exclusion de toute table /_CL$/i, des deux sources ;
// - suppression d'un éventuel champ "source" porté par l'objet de table.
//
// Usage : node scripts/import-schemas.mjs (ou npm run import-schemas), à relancer après chaque
// nouvel export déposé dans schemas-import/.
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const IMPORT_DIR = path.join(ROOT, 'schemas-import');
const TABLES_JSON = path.join(ROOT, 'schema/tables.json');
const OUT_DIR = path.join(ROOT, 'schemas');

const isCustomLog = (name) => /_CL$/i.test(name);

fs.mkdirSync(OUT_DIR, { recursive: true });

// 1. Source faisant foi : schemas-import/ (export du tenant)
const merged = new Map();
let skippedCL = 0;
for (const file of fs.readdirSync(IMPORT_DIR).filter((f) => f.endsWith('.json'))) {
  const data = JSON.parse(fs.readFileSync(path.join(IMPORT_DIR, file), 'utf8'));
  if (isCustomLog(data.table)) { skippedCL++; continue; }
  delete data.source; // champ éventuel non repris dans schemas/ (filtre gardé pour les imports futurs)
  merged.set(data.table, { table: data.table, fields: data.fields });
}
const fromImportCount = merged.size;

// 2. Complément : schema/tables.json, seulement pour les tables absentes de schemas-import/
const tablesJson = JSON.parse(fs.readFileSync(TABLES_JSON, 'utf8'));
const fromTablesJson = [];
for (const [table, cols] of Object.entries(tablesJson)) {
  if (merged.has(table)) continue;
  if (isCustomLog(table)) { skippedCL++; continue; }
  fromTablesJson.push(table);
  merged.set(table, { table, fields: Object.entries(cols).map(([name, type]) => ({ name, type })) });
}

// 3. Écriture, un fichier par table
for (const [table, schema] of merged) {
  fs.writeFileSync(path.join(OUT_DIR, `${table}.json`), JSON.stringify(schema, null, 2) + '\n');
}

// 4. Rapport
console.log(`${merged.size} schémas écrits dans schemas/ :`);
console.log(`  - ${fromImportCount} depuis schemas-import/ (export tenant, source faisant foi)`);
console.log(`  - ${fromTablesJson.length} depuis schema/tables.json (absentes de l'export) : ${fromTablesJson.sort().join(', ') || '—'}`);
console.log(`  - ${skippedCL} table(s) _CL exclue(s)`);
