# MSSentinel-PivotRules

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
| `fragments/roles.kql` | Rôles des machines, IP et comptes (voir [Rôles des entités](#rôles-des-entités)) |
| `fragments/sysmon.kql` | `_Sysmon` : événements Sysmon normalisés, depuis `Event` (XML) ou `WindowsEvent` (JSON) |
| `schema/tables.json` | Colonnes de 54 tables, générées depuis la référence officielle Azure Monitor |
| `schema/overrides.json` | Compléments : `AzureDiagnostics` et tables propres à Defender XDR (`EntraIdSignInEvents`, `EntraIdSpnSignInEvents`, reprises du dépôt Azure-Sentinel), colonne `Timestamp` des tables Defender, tables tolérées dans la variante Defender (`defenderOptional`) |
| `schema/sources.json` | Familles de sources : quelles tables voient quels événements, et lesquelles se remplacent (voir [Couverture des sources](#couverture-des-sources)) |
| `watchlists/EasyPivotRoles.csv` | Modèle de la watchlist Sentinel des rôles (exemples fictifs) |
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
  _Signins(StartTimestampstamp, EndTimestampstamp, Value, "")
  | ...
```

Dans `query`, les variables suivantes sont disponibles : `Value`, `T0`, `StartTimestampstamp`, `EndTimestampstamp`, les variables de l'indicateur (`ValueUpn`, `ValueSam`, `ValueMail`, `ValueDomain`, `ValueShort`, `ValueFile`, `ValuePath`, `ValueHash`, `ValueApp`), `HostFilter` si `context: [HOST]`, et les fonctions des fragments déclarés.

La macro `XMLFIELD(expr, Nom)` est développée à la compilation en `extract(@'<Data Name="Nom">([^<]*)</Data>', 1, expr)`.

Les lignes comprises entre `// @sentinel-only:begin` et `// @sentinel-only:end` (dans une règle ou un fragment) sont retirées de la variante Defender (`queryDefender`). On y place les branches de `union` qui lisent une table absente de Defender XDR (ASIM, Syslog, SecurityEvent…) : la règle garde sa variante Defender et gagne la source dans Sentinel. Placer la virgule de séparation à l'intérieur du bloc (`, ( … )`) pour que la requête reste valide sans lui.

## Couverture des sources

Une table absente ne provoque aucune erreur : `union isfuzzy=true` ignore la branche, et la règle renvoie simplement moins de lignes. Trois mécanismes rendent ces trous visibles ou les comblent.

1. **Familles de sources** (`schema/sources.json`). Une famille (« Authentifications Windows et Active Directory », « Fichiers, partages et bibliothèques »…) liste des **membres** qui voient les mêmes événements, ou des points de vue complémentaires. Un membre est :
   - soit une table entière (`DeviceFileEvents`) ;
   - soit une partie d'une table journalisée : un canal et des EventID (`SecurityEvent` canal `security` 4656, 4660, 4663, 4670 ; `Event` canal `sysmon` 11, 23, 26 ; `Event` canal `system` 7045), ou un filtre `where` libre.

   Un membre peut porter son propre conseil de remédiation (stratégie d'audit, SACL, configuration Sysmon). Le build refuse une règle qui lit une table sans famille. Chaque règle publie ses familles dans `sources`, et les tables lues seulement pour annoter les rôles dans `enrichment`.
2. **Règles de couverture générées** (`IP-S0`, `AC-S0`, `EM-S0`, `DM-S0`, `MC-S0`, `PR-S0`, `AP-S0`, `HS-S0`). Une par indicateur, produite par le build à partir des règles de l'indicateur. Elle contrôle chaque membre réellement lu : le build relève les EventID passés à `_WinSecurity` et `_Sysmon` par chaque règle. Pour chaque membre, elle indique :
   - si la table existe, si elle est alimentée sur la fenêtre, et si les **événements du membre** sont collectés. Une table `SecurityEvent` alimentée sans aucun 4663 donne « Événements non collectés », avec la stratégie d'audit à activer ;
   - s'il lui manque des colonnes que les règles utilisent. Le build les détermine avec le service de langage Kusto, et la règle les compare au résultat de `getschema` sur l'environnement ;
   - si son absence est compensée par une autre table de la même famille, ou si la famille n'est plus couverte du tout, avec les règles touchées et le connecteur à activer.

   À lancer en premier sur un nouvel environnement.
3. **Sources équivalentes, sans doublon**. Les fragments lisent les tables qui se remplacent l'une l'autre :
   - `_Signins` : `SigninLogs` et `AADNonInteractiveUserSignInLogs`, ou `EntraIdSignInEvents` dans Defender XDR ;
   - `_SpnSignins` : `AADServicePrincipalSignInLogs` et `AADManagedIdentitySignInLogs`, ou `EntraIdSpnSignInEvents` ;
   - `AP-P1` : `AuditLogs`, ou `CloudAppEvents`.

   La table de remplacement n'est lue que pour le type d'événement que la table principale ne fournit pas sur la période : pas de doublon dans le portail unifié. Les règles lisent aussi, quand l'événement s'y trouve :
   - les tables ASIM (authentification, processus, fichiers, sessions réseau, web), Azure Firewall et Syslog (SSH) ;
   - le DNS vu par Defender for Endpoint, Microsoft Graph et Defender for Identity (`IdentityQueryEvents`, `IdentityDirectoryEvents`) ;
   - l'audit Windows de l'accès aux objets (fichiers 4656, 4660, 4663, 4670 ; partages 5140, 5145 ; registre 4657) ;
   - Sysmon via `_Sysmon` (1, 3, 7, 11 à 15, 22, 23, 26, 29) et le journal Système (7045).

`fragments/win_security.kql` et `fragments/sysmon.kql` sont entièrement `@sentinel-only`. Une règle qui les appelle hors d'un bloc `@sentinel-only` n'a pas de variante Defender : le build le détecte.

## Découverte : où apparaît la valeur

Le build génère aussi une règle par indicateur, `XX-S9` (`IP-S9`, `AC-S9`…). Elle cherche la valeur dans **toutes** les tables (`union * | where * has`), avec un terme adapté à l'indicateur :

| Indicateur | Terme recherché |
| --- | --- |
| Compte | Nom SAM |
| Machine | Nom court |
| Processus | Nom de fichier |
| URL | Domaine |

Elle rend une ligne par table et par emplacement :
- **`Path`** : la colonne, ou le chemin dans un JSON déplié sur 5 niveaux, par exemple `RawEventData['1']['parameters']['ip']` ;
- **`Role`** : rôle probable (source ou destination), déduit du nom du chemin ;
- **`ExactRows`** : valeur seule dans la cellule, ou noyée dans un texte ;
- **statistiques de la table** : volume, période, heures actives, machines, comptes et actions les plus fréquentes ;
- **`Status`** : comparaison avec les colonnes que les règles de l'indicateur lisent réellement (liste `Known` générée au build, avec les règles concernées).

Un emplacement « Non lu par les règles » est une source à ajouter au modèle. La recherche parcourt tout l'espace de travail : fenêtre par défaut de 4 h avant et 1 h après T0.

## Rôles des entités

Une même machine ou un même compte n'a pas le même sens selon son rôle. Un contrôleur de domaine journalise l'authentification de tout le domaine. Une IP de NAT porte des centaines de comptes. Un compte de service ouvre des sessions partout. Le fragment `roles` fournit :

| Fonction | Résultat |
| --- | --- |
| `_MachineRoles(at)` | `MachineKey` (nom court), `MachineRole`, `MachineRoleBasis` |
| `_IpRoles(at)`, `_IpRoleOf(ip, at)` | Rôles d'une IP, plages CIDR comprises |
| `_AccountRoles(at)` | `AccountKey` (SAM ou UPN), `AccountRole`, `AccountRoleBasis` |
| `_AccountKind(sam)` | Catégorie déduite du nom : compte machine, système, krbtgt, synchronisation Entra Connect, administrateur intégré |
| `_HostKey(h)`, `_SamOf(a)`, `_Labeled(nom, rôle)`, `_JoinRoles(a, b)` | Normalisation et annotation (`dc01 [DC]`) |

Ces fonctions combinent trois sources :
- **Contrôleurs de domaine détectés automatiquement** : machines qui émettent des 4768 (seul un KDC le fait), cibles LDAP vues par Defender for Identity, machines qui acceptent des connexions Kerberos sur le port 88 selon Defender for Endpoint.
- **IdentityInfo** : rôles Entra ID, groupes AD privilégiés, comptes de service, comptes sensibles ou leurres.
- **Watchlist Sentinel d'alias `EasyPivotRoles`**, facultative, avec les colonnes `Entity`, `Type` (`Machine`, `IP` ou `Compte`), `Role` et `Note`. Modèle : `watchlists/EasyPivotRoles.csv`. On y déclare ce qui ne se détecte pas : serveurs RDS, bastions, NAT, VPN, scanners, comptes de service, comptes d'administration.

Dans les journaux Windows, `_WinSecurity` ajoute trois colonnes pour ne plus confondre la machine qui journalise avec la machine utilisée :
- `TargetHost` : machine réellement visée (service demandé pour un 4769, serveur cible pour un 4648) ;
- `AuthAuthority` : DC qui a validé les identifiants (4768, 4769, 4771, 4776) ;
- `SourceHost` : poste d'origine.

Les règles s'en servent ainsi :
- `AC-P2` et `MC-P1` classent chaque ligne par nature du lien : session sur la machine, identifiants explicites, ticket Kerberos vu par le DC, poste d'origine, accès réseau au DC (GPO, SYSVOL) en dernier.
- Les règles qui listent des machines ou des comptes annotent leur rôle.
- `IP-P6`, `AC-P5` et `MC-P5` décrivent l'entité elle-même avant de pivoter dessus.

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

- `dist/pivot-rules.json` contient `indicators` (libellés et motifs de détection), `actions`, `placeholders`, `sources` (familles de sources) et `rules`. Chaque règle porte `id`, `name`, `category`, `indicators`, `action`, `description`, `reading`, `scenarios`, `v1`, `window`, `render`, `tables`, `sources`, `enrichment` (tables lues seulement pour les rôles), `platforms`, `placeholders`, `query` et, si elle peut tourner dans Defender XDR seul, `queryDefender` : sans les blocs `@sentinel-only`, avec `Timestamp` au lieu de `TimeGenerated`.
- `dist/pivot-rules.flat.json` reprend le format historique de l'userscript : `[{ name, category, description, query }]`.
- `dist/CATALOGUE.md` est le catalogue lisible des règles.

## Contribution

Les contributions sont les bienvenues : une règle = un fichier YAML.

1. Forkez le dépôt, puis créez une branche (`git checkout -b regle-IP-P7`).
2. Installez les dépendances : `npm ci`.
3. Ajoutez ou modifiez un fichier en suivant le [format d'une règle](#format-dune-règle).
   - L'`id` est unique : préfixe de l'indicateur, lettre de l'action (`S` statistics, `P` pivot, `T` timeline) et numéro suivant. Le fichier porte le nom de l'`id` (`rules/ip/IP-P7.yaml`). Les identifiants `XX-S0` sont réservés aux règles de couverture générées.
   - Une nouvelle table doit être ajoutée à une famille dans `schema/sources.json` (le build le vérifie).
   - Quand la règle liste des machines ou des comptes, annotez leur rôle avec le fragment `roles`. Dans les journaux Windows, utilisez `TargetHost` et `AuthAuthority` plutôt que `Computer`.
   - Remplissez `reading` (`decisive`, `context`, `noise`) afin d'aider l'analyste à interpréter le résultat.
   - Réutilisez les fragments (`uses`) et les variables (`Value`, `ValueSam`, `StartTimestampstamp`, `EndTimestampstamp`) afin d'éviter de dupliquer du KQL.
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
https://github.com/arthubhub/MSSentinel-PivotRules/releases/latest/download/pivot-rules.flat.json
https://github.com/arthubhub/MSSentinel-PivotRules/releases/latest/download/pivot-rules.json
https://github.com/arthubhub/MSSentinel-PivotRules/releases/latest/download/CATALOGUE.md
```

Par exemple, en ligne de commande : `curl -L -O https://github.com/arthubhub/MSSentinel-PivotRules/releases/latest/download/pivot-rules.flat.json`.

Pour générer les fichiers vous-même : `npm ci && npm run build`, la sortie est dans `dist/`.
