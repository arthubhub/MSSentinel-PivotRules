# sentinel-pivot-rules

Ce répertoire contient des query KQL destinées à pivoter autour des indicateurs recensés lors d'investigations SOC sur Microsoft Sentinel.

Le fichier de sortie dist/pivot-rules.flat.json est destiné à être utilisé dans une extension comme Tampermonkey.

En créant de nouvelles règles dans le répertoire rules, vous pouvez contribuer au projet afin d'aider les utilisateurs à retrouver les informations essentielles en situation de crise.

Pour construire le répertoire de règles à partir des données du repo, commencez par installer les dépendances, puis lancez `npm run build` comme indiqué ci-dessous :

```
npm install
npm run build   # dist/pivot-rules.json, dist/pivot-rules.flat.json, dist/CATALOGUE.md
npm test        # build strict + remplissage des paramètres + revalidation de chaque requête
```

## Organisation

| Dossier | Contenu |
| --- | --- |
| `rules/<indicateur>/*.yaml` | Requètes KQL (une par fichier) |
| `fragments/*.kql` | Fonctions KQL communes, insérées dans les requêtes qui les déclarent dans `uses` |
| `fragments/indicators/*.kql` | Variables dérivées de la valeur sélectionnée (`ValueSam`, `ValueDomain`, `ValueShort`…) |
| `schema/tables.json` | Colonnes de 40 tables, générées depuis la référence officielle Azure Monitor |
| `schema/overrides.json` | Compléments : `AzureDiagnostics` (repris du dépôt Azure-Sentinel) et colonne `Timestamp` des tables Defender |
| `schema/rule.schema.json` | Schéma d'une règle YAML |
| `scripts/build.mjs` | Compilateur YAML -> JSON/md |
| `scripts/kql-validator.cjs` | Validation par la librairie Kusto officielle (`@kusto/language-service-next`) |
| `scripts/generate-win-security.mjs` | Génère `fragments/win_security.kql` |
| `scripts/update-schemas.mjs` | Régénère `schema/tables.json` |

## Format d'une règle

```yaml
id: IP-P2                      # préfixe d'indicateur + (S)tatistics/(P)ivot/(T)imeline + numéro
name: Comptes connectés depuis l'IP
indicators: [ip]
action: pivot                  # statistics | pivot | timeline
description: >
  Ce que montre la requête.
reading:                       # comment lire le résultat
  decisive: ce qui permet de trancher
  context: ce qui oriente sans conclure
  noise: ce qui est du bruit en production saine
v1: true                       # socle à livrer en premier
window: { before: 24h, after: 1h }   # fenêtre par défaut autour de T0
render: table                  # table | timechart | columnchart | barchart
context: [HOST]                # paramètre de contexte facultatif
uses: [signins, win_security]  # fragments nécessaires (leurs dépendances sont résolues)
query: |
  _Signins(StartTime, EndTime, Value, "")
  | ...
```

Dans `query`, les variables suivantes sont disponibles : `Value`, `T0`, `StartTime`, `EndTime`, les variables de l'indicateur (`ValueUpn`, `ValueSam`, `ValueMail`, `ValueDomain`, `ValueShort`, `ValueFile`, `ValuePath`, `ValueHash`, `ValueApp`), `HostFilter` si `context: [HOST]`, et les fonctions des fragments déclarés.

La macro `XMLFIELD(expr, Nom)` est développée à la compilation en `extract(@'<Data Name="Nom">([^<]*)</Data>', 1, expr)`.

## Paramètres des requêtes compilées

Chaque requête commence par un en-tête de paramètres. Avant substitution, la requête reste du KQL valide et s'exécute avec T0 = `now()` et la fenêtre par défaut.

| Paramètre | Contenu | Si vide ou non remplacé |
| --- | --- | --- |
| `{{VALUE}}` | La sélection, dans une chaîne `@"…"` | — |
| `{{T0}}` | ISO 8601, idéalement le `TimeGenerated` de la ligne sélectionnée | `now()` |
| `{{BEFORE_MIN}}`, `{{AFTER_MIN}}` | Fenêtre avant et après T0, en minutes | `window` de la règle |
| `{{HOST}}` | Machine de la même ligne (règles Processus et Hash) | toutes les machines |

`scripts/fill-query.mjs` fait la substitution, et `matchesIndicator()` vérifie la sélection contre les motifs de `indicators.<type>.patterns`.

## Sortie

- `dist/pivot-rules.json` contient `indicators` (libellés et motifs de détection), `actions`, `placeholders` et `rules`. Chaque règle porte `id`, `name`, `category`, `indicators`, `action`, `description`, `reading`, `scenarios`, `v1`, `window`, `render`, `tables`, `platforms`, `placeholders`, `query` et, si elle n'utilise que des tables Defender XDR, `queryDefender` (`Timestamp` au lieu de `TimeGenerated`).
- `dist/pivot-rules.flat.json` reprend le format historique de l'userscript : `[{ name, category, description, query }]`.
- `dist/CATALOGUE.md` est le catalogue lisible des règles.

## Contribution

Les contributions sont les bienvenues : une règle = un fichier YAML.

1. Forkez le dépôt, puis créez une branche (`git checkout -b regle-IP-P6`).
2. Installez les dépendances : `npm ci`.
3. Ajoutez ou modifiez un fichier en suivant le [format d'une règle](#format-dune-règle).
   - L'`id` est unique : préfixe de l'indicateur, lettre de l'action (`S` statistics, `P` pivot, `T` timeline) et numéro suivant. Le fichier porte le nom de l'`id` (`rules/ip/IP-P6.yaml`).
   - Remplissez `reading` (`decisive`, `context`, `noise`) afin d'aider l'analyste à interpréter le résultat.
   - Réutilisez les fragments (`uses`) et les variables (`Value`, `ValueSam`, `StartTime`, `EndTime`) afin d'éviter de dupliquer du KQL.
   - Les colonnes utilisées doivent exister dans `schema/tables.json` (ou override).
4. Vérifiez en local :
   ```
   node scripts/build.mjs --strict   # schéma YAML + validation KQL, doit afficher 0 erreur et 0 avertissement
   ```
   Consultez `dist/CATALOGUE.md` pour voir le rendu de votre règle.
5. **Ouvrez une Pull Request** vers `master` en décrivant le scénario d'investigation couvert. Ne mettez pas de donnée réelle dans les requêtes ni dans les exemples.

> À la fusion sur `master`, la CI reconstruit tout et publie une nouvelle release.

## Récupération de la sortie

Chaque push sur `master` déclenche le workflow [`Build & Release`](.github/workflows/release.yml), la release contient :

| Fichier | Usage |
| --- | --- |
| `pivot-rules.flat.json` | Format de l'userscript Tampermonkey : `[{ name, category, description, query }]` |
| `pivot-rules.json` | Format complet : indicateurs, motifs de détection, actions, paramètres, lecture des résultats, requêtes Sentinel et Defender XDR |
| `CATALOGUE.md` | Catalogue lisible des règles |

Les URL ci-dessous pointent toujours vers la dernière version :

```
https://github.com/arthubhub/MicrosoftSentinel-EasyPivot/releases/latest/download/pivot-rules.flat.json
https://github.com/arthubhub/MicrosoftSentinel-EasyPivot/releases/latest/download/pivot-rules.json
https://github.com/arthubhub/MicrosoftSentinel-EasyPivot/releases/latest/download/CATALOGUE.md
```

Par exemple, en ligne de commande : `curl -L -O https://github.com/arthubhub/MicrosoftSentinel-EasyPivot/releases/latest/download/pivot-rules.flat.json`.

Pour générer les fichiers vous-même : `npm ci && npm run build`, la sortie est dans `dist/`.