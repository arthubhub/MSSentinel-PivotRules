#!/usr/bin/env node
// Guards on schemas/, run by npm run check / build / test.
//
//   #30: rejects any _CL custom table (by file name AND by the `table` field).
//   #37: rejects stray columns from a schema export: `IndexName` and names suffixed
//        with a type (`_dynamic`, `_string`, `_long`, `_datetime`, `_int`, `_real`,
//        `_bool`, `_guid`, `_OBJECT`).
//
// Independent of scripts/import-schemas.mjs: it must also reject a file dropped by hand, not only
// what the import produces. That is the point of 2c: the export provided on 22/10 was already clean
// (0 and 0), so the job is not cleaning but stopping a future dirty export from slipping in unnoticed.
// The 12 tables converted from schema/tables.json are checked like the others: they come from
// another source, so the upstream cleanup does not cover them.
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const dir = path.join(ROOT, 'schemas');

if (!fs.existsSync(dir)) {
  console.log('schemas/ missing: nothing to check.');
  process.exit(0);
}

// Type suffixes added by some exports: `TargetUserName_string`, `Duration_long`…
// The real KQL column has no such suffix, so a `Table.Column_string` pair would be wrong.
// Not to be confused with the Log Analytics suffixes `_s` / `_d` / `_t`, which ARE part of the real
// column name and are therefore legitimate (see stripSuffix in generate-locations.mjs).
const TYPE_SUFFIX = /_(dynamic|string|long|datetime|int|real|bool|guid|OBJECT)$/;
const NOISE_COLUMN = (name) => name === 'IndexName' || TYPE_SUFFIX.test(name);

const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
const customTables = [];
const noisy = []; // { file, columns[] }

for (const file of files) {
  if (/_CL/i.test(file)) { customTables.push(file); continue; }
  let data;
  try {
    data = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
  } catch {
    // unreadable JSON file: reported by build.mjs, not this guard's job
    continue;
  }
  if (data.table && /_CL$/i.test(data.table)) { customTables.push(file); continue; }

  const hits = (data.fields ?? []).map((f) => f.name).filter((n) => typeof n === 'string' && NOISE_COLUMN(n));
  if (hits.length) noisy.push({ file, columns: hits });
}

let failed = false;

if (customTables.length) {
  console.error(`X ${customTables.length} schemas/ file(s) rejected (_CL custom table not allowed): ${customTables.join(', ')}`);
  failed = true;
}

if (noisy.length) {
  const total = noisy.reduce((n, x) => n + x.columns.length, 0);
  console.error(`X ${total} stray column(s) in ${noisy.length} schemas/ file(s) (#37):`);
  for (const { file, columns } of noisy.slice(0, 10)) {
    console.error(`  ${file}: ${columns.slice(0, 6).join(', ')}${columns.length > 6 ? `, … (${columns.length})` : ''}`);
  }
  if (noisy.length > 10) console.error(`  … and ${noisy.length - 10} more file(s)`);
  console.error('  -> `IndexName` and type-suffixed names are not KQL columns.');
  console.error('     Remove them from the export, then run `npm run import-schemas` again.');
  failed = true;
}

if (failed) process.exit(1);
console.log(`schemas/: ${files.length} files, no _CL table, no stray column (#30, #37).`);
