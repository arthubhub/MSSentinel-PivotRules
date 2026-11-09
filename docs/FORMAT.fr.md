# Format du catalogue `pivot-rules.json`

<sub>English version: [FORMAT.md](FORMAT.md)</sub>

Référence pour les contributeurs et pour tout outil qui lit le catalogue (EasyPivot en premier). Le fichier est produit par `npm run build` dans `dist/` et publié à chaque release.

## Racine

| Clé | Type | Contenu |
| --- | --- | --- |
| `name`, `version` | chaîne | Nom et version du paquet (`package.json`) |
| `formatVersion` | entier | Version du format. **Reste à 1** : EasyPivot rejette tout catalogue d'une autre version majeure. Pour la changer, élargir d'abord `SUPPORTED_FORMAT_VERSION` dans l'userscript, le publier, puis seulement bumper ici. Les ajouts optionnels (`targets`, `scenarios`) ne changent pas la version. |
| `generatedAt` | ISO 8601 | Date du build |
| `placeholders` | chaînes | Paramètres remplacés par l'outil : `VALUE`, `T0`, `BEFORE_MIN`, `AFTER_MIN`, `HOST` |
| `indicators` | objet | Par type (`ip`, `account`, `email`, `url`, `domain`, `device`, `process`, `application`, `hash`) : `label` et `patterns` (expressions régulières .NET, `(?i)` en tête pour ignorer la casse) |
| `actions` | objet | `statistics`, `pivot`, `timeline` : `label` |
| `locations` | objet | Par type d'indicateur : paires `Table.Colonne` où il peut apparaître. Les premières viennent du niveau « confirmé » (comparaison avec les règles, entité Defender), les suivantes du niveau « incertain » (nom de colonne). Jamais de table `_CL`. |
| `sources` | objet | Familles de sources (voir README, « Couverture des sources ») |
| `rules` | tableau | Les règles compilées (ci-dessous) |
| `scenarios` | tableau | Playbooks guidés (ci-dessous) |

## Règle compilée

| Clé | Contenu |
| --- | --- |
| `id` | `<préfixe>-<S\|P\|T><n>` : préfixe de l'indicateur (`IP`, `AC`, `EM`, `DM`, `MC`, `PR`, `AP`, `HS`), lettre de l'action. `XX-S0` (couverture) et `XX-S9` (découverte) sont générés. |
| `name`, `category`, `description` | Textes affichés |
| `indicators` | Types acceptés en entrée (le premier fixe le préfixe) |
| `action` | `statistics`, `pivot` ou `timeline` |
| `targets` | Facultatif. Types d'indicateurs présents dans le résultat : sert aux pivots croisés (IP → machine, compte → IP…) |
| `reading` | `decisive` (ce qui tranche), `context` (ce qui oriente), `noise` (bruit fréquent) |
| `window` | Fenêtre par défaut autour de T0 : `before`, `after` (`30m`, `24h`, `7d`) et leurs valeurs en minutes |
| `render` | `table`, `timechart`, `columnchart`, `barchart` |
| `tables`, `sources`, `enrichment`, `eventTables`, `columns`, `channels` | Tables et colonnes lues (contrôles de couverture, découverte) |
| `platforms` | `sentinel`, `defender-unified` et `defender` quand `queryDefender` existe |
| `placeholders` | Paramètres réellement utilisés par la requête |
| `scenarios` | Scénarios qui utilisent la règle |
| `query` | KQL Sentinel (Log Analytics), avec l'en-tête de paramètres |
| `queryDefender` | KQL Defender XDR : sans les blocs `@sentinel-only`, avec les blocs `@defender-only`, `Timestamp` au lieu de `TimeGenerated` |
| `source` | Fichier YAML d'origine |

### Paramètres

Chaque requête commence par `// [ID] nom`, puis un en-tête qui reste du KQL valide avant substitution :

| Paramètre | Remplacé par | Valeur par défaut |
| --- | --- | --- |
| `{{VALUE}}` | La valeur pivotée, dans une chaîne verbatim `@"…"` (guillemets doublés) | — |
| `{{T0}}` | Instant de l'événement, ISO 8601 | `now()` |
| `{{BEFORE_MIN}}`, `{{AFTER_MIN}}` | Fenêtre en minutes | `window` de la règle |
| `{{HOST}}` | Machine de la ligne (règles Processus et Hash) | toutes les machines |

La ligne `// [ID]` permet à EasyPivot de rattacher le résultat capturé à la règle et au pivot.

## Scénario

```json
{ "id": "S1", "name": "…", "description": "…", "indicator": "ip",
  "steps": [ { "ruleId": "IP-P6" }, { "ruleId": "IP-P2", "carry": "account" }, { "ruleId": "AC-S1" } ] }
```

`carry` : type de valeur repris du résultat de l'étape pour l'étape suivante. Le build garantit que chaque `ruleId` existe, accepte le type en cours, et que `carry` figure dans ses `targets`. Un outil qui reçoit un scénario citant une règle inconnue doit l'ignorer.

## Règles de confidentialité

- Aucune table personnalisée `_CL` dans `locations`, `tables` ou les schémas publiés.
- Aucune donnée réelle (valeur, client, tenant) dans les requêtes, les descriptions ou les exemples.
