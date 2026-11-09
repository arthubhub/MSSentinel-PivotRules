# `pivot-rules.json` catalog format

<sub>Version française : [FORMAT.fr.md](FORMAT.fr.md)</sub>

Reference for contributors and for any tool reading the catalog (EasyPivot first). The file is produced by `npm run build` in `dist/` and published with each release. All texts (names, descriptions, reading hints) are in English.

## Root

| Key | Type | Content |
| --- | --- | --- |
| `name`, `version` | string | Package name and version (`package.json`) |
| `formatVersion` | integer | Format version. **Stays at 1**: EasyPivot rejects any catalog with another major version. To change it, first widen `SUPPORTED_FORMAT_VERSION` in the userscript, release it, and only then bump it here. Optional additions (`targets`, `scenarios`) do not change the version. |
| `generatedAt` | ISO 8601 | Build date |
| `placeholders` | strings | Parameters replaced by the tool: `VALUE`, `T0`, `BEFORE_MIN`, `AFTER_MIN`, `HOST` |
| `indicators` | object | Per type (`ip`, `account`, `email`, `url`, `domain`, `device`, `process`, `application`, `hash`): `label` and `patterns` (.NET regular expressions, leading `(?i)` for case-insensitive) |
| `actions` | object | `statistics`, `pivot`, `timeline`: `label` |
| `locations` | object | Per indicator type: `Table.Column` pairs where it can appear. The first ones come from the "confirmed" level (compared with the rules, Defender entity), the next ones from the "uncertain" level (column name). Never a `_CL` table. |
| `sources` | object | Source families (see README, "Source coverage and discovery") |
| `rules` | array | Compiled rules (below) |
| `scenarios` | array | Guided playbooks (below) |

## Compiled rule

| Key | Content |
| --- | --- |
| `id` | `<prefix>-<S\|P\|T><n>`: indicator prefix (`IP`, `AC`, `EM`, `DM`, `MC`, `PR`, `AP`, `HS`), action letter. `XX-S0` (coverage) and `XX-S9` (discovery) are generated. |
| `name`, `category`, `description` | Displayed texts |
| `indicators` | Accepted input types (the first one sets the prefix) |
| `action` | `statistics`, `pivot` or `timeline` |
| `targets` | Optional. Indicator types present in the result: used for cross pivots (IP → device, account → IP…) |
| `reading` | `decisive` (what settles it), `context` (what points a direction), `noise` (common noise) |
| `window` | Default window around T0: `before`, `after` (`30m`, `24h`, `7d`) and their values in minutes |
| `render` | `table`, `timechart`, `columnchart`, `barchart` |
| `tables`, `sources`, `enrichment`, `eventTables`, `columns`, `channels` | Tables and columns read (coverage checks, discovery) |
| `platforms` | `sentinel`, `defender-unified`, and `defender` when `queryDefender` exists |
| `placeholders` | Parameters the query actually uses |
| `scenarios` | Scenarios using the rule |
| `query` | Sentinel (Log Analytics) KQL, with the parameter header |
| `queryDefender` | Defender XDR KQL: without the `@sentinel-only` blocks, with the `@defender-only` blocks, `Timestamp` instead of `TimeGenerated` |
| `source` | Source YAML file |

### Parameters

Each query starts with `// [ID] name`, then a header that stays valid KQL before substitution:

| Parameter | Replaced by | Default |
| --- | --- | --- |
| `{{VALUE}}` | The pivoted value, in a verbatim string `@"…"` (doubled quotes) | — |
| `{{T0}}` | Time of the event, ISO 8601 | `now()` |
| `{{BEFORE_MIN}}`, `{{AFTER_MIN}}` | Window in minutes | the rule's `window` |
| `{{HOST}}` | Device of the row (process and hash rules) | all devices |

The `// [ID]` line lets EasyPivot attach the captured result to the rule and the pivot.

## Scenario

```json
{ "id": "S1", "name": "…", "description": "…", "indicator": "ip",
  "steps": [ { "ruleId": "IP-P6" }, { "ruleId": "IP-P2", "carry": "account" }, { "ruleId": "AC-S1" } ] }
```

`carry`: type of value taken from the step's result for the next step. The build guarantees that each `ruleId` exists, accepts the current type, and that `carry` is in its `targets`. A tool receiving a scenario that cites an unknown rule must ignore it.

## Privacy rules

- No custom `_CL` table in `locations`, `tables` or the published schemas.
- No real data (value, customer, tenant) in queries, descriptions or examples.
