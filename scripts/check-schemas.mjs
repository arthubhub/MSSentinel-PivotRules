#!/usr/bin/env node
// Garde-fous sur schemas/, appelés depuis npm run check / build / test.
//
//   #30 : refuse toute table personnalisée _CL (par nom de fichier ET par le champ `table`).
//   #37 : refuse les colonnes « parasites » d'un export de schéma — `IndexName` et les noms
//         suffixés par un type (`_dynamic`, `_string`, `_long`, `_datetime`, `_int`, `_real`,
//         `_bool`, `_guid`, `_OBJECT`).
//
// Indépendant de scripts/import-schemas.mjs : il doit aussi refuser un fichier déposé à la main, pas
// seulement ce que produit l'import. C'est tout l'intérêt de 2c — l'export fourni le 22/10 était déjà
// propre (0 et 0), donc le travail n'est pas de nettoyer mais d'empêcher un prochain export sale
// d'entrer sans qu'on le voie. Les 12 tables converties depuis schema/tables.json sont contrôlées
// comme les autres : elles viennent d'une autre source, donc non couvertes par le nettoyage amont.
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const dir = path.join(ROOT, 'schemas');

if (!fs.existsSync(dir)) {
  console.log('schemas/ absent : rien à vérifier.');
  process.exit(0);
}

// Suffixes de type ajoutés par certains exports : `TargetUserName_string`, `Duration_long`…
// La vraie colonne KQL n'a pas ce suffixe, donc une paire `Table.Colonne_string` serait fausse.
// À ne pas confondre avec les suffixes Log Analytics `_s` / `_d` / `_t`, qui FONT partie du nom réel
// de la colonne et sont donc légitimes (voir stripSuffix dans generate-locations.mjs).
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
    // fichier JSON illisible : signalé par build.mjs, pas le rôle de ce garde-fou
    continue;
  }
  if (data.table && /_CL$/i.test(data.table)) { customTables.push(file); continue; }

  const hits = (data.fields ?? []).map((f) => f.name).filter((n) => typeof n === 'string' && NOISE_COLUMN(n));
  if (hits.length) noisy.push({ file, columns: hits });
}

let failed = false;

if (customTables.length) {
  console.error(`X ${customTables.length} fichier(s) schemas/ refusé(s) (table personnalisée _CL interdite) : ${customTables.join(', ')}`);
  failed = true;
}

if (noisy.length) {
  const total = noisy.reduce((n, x) => n + x.columns.length, 0);
  console.error(`X ${total} colonne(s) parasite(s) dans ${noisy.length} fichier(s) schemas/ (#37) :`);
  for (const { file, columns } of noisy.slice(0, 10)) {
    console.error(`  ${file} : ${columns.slice(0, 6).join(', ')}${columns.length > 6 ? `, … (${columns.length})` : ''}`);
  }
  if (noisy.length > 10) console.error(`  … et ${noisy.length - 10} autre(s) fichier(s)`);
  console.error('  -> `IndexName` et les noms suffixés par un type ne sont pas des colonnes KQL.');
  console.error('     Les retirer de l\'export, puis relancer `npm run import-schemas`.');
  failed = true;
}

if (failed) process.exit(1);
console.log(`schemas/ : ${files.length} fichiers, aucune table _CL, aucune colonne parasite (#30, #37).`);
