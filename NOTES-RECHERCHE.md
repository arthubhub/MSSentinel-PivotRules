# Notes de recherche : couverture des sources et rôles des entités

État de travail local, non commité. Il traite deux problèmes constatés en investigation :

1. **Des événements ratés.** Une table absente (par exemple les journaux de connexion Entra ID) ne produit aucune erreur. `union isfuzzy=true` ignore la branche en silence, et la règle renvoie moins de lignes.
2. **Des champs de sortie trompeurs.** Par exemple, les machines d'un compte ramènent surtout les contrôleurs de domaine. Les DC journalisent l'authentification (4768, 4769, 4776, ouvertures réseau de type 3) et Defender for Identity les voit comme destination. Les requêtes prenaient la machine qui journalise pour la machine utilisée.

`npm test` passe : build strict avec 0 erreur et 0 avertissement, puis remplissage et revalidation des 66 requêtes. Les requêtes n'ont **pas** été exécutées sur un vrai workspace (voir « À vérifier »).

## A. Couverture des sources

| Élément | Fichier | Rôle |
| --- | --- | --- |
| Familles de sources | `schema/sources.json` | Rattache chaque table à ce qu'elle permet de voir. Les tables d'une famille se remplacent. Le build refuse une table sans famille. |
| Règles de couverture | générées par `scripts/build.mjs` | `IP-S0`, `AC-S0`, `EM-S0`, `DM-S0`, `MC-S0`, `PR-S0`, `AP-S0`, `HS-S0` : une par indicateur, avec variante Defender. |
| Colonnes réellement lues | `scripts/kql-validator.cjs` (`columnsUsed`) | Le service de langage Kusto résout chaque colonne vers sa table. La règle de couverture compare cette liste au résultat de `getschema`. |
| Sources équivalentes sans doublon | `fragments/signins.kql`, `fragments/spn_signins.kql`, `AP-P1` | La table Defender XDR n'est lue que si la table Sentinel du même type est vide sur la période. |
| Variante Defender préservée | blocs `// @sentinel-only:begin … end` | Branches ASIM, Syslog, SecurityEvent retirées de `queryDefender`. Aucune des 22 variantes Defender existantes n'est perdue ; 8 s'ajoutent (règles de couverture). |
| Garde-fous | `scripts/test.mjs` | Une variante Defender ne lit que des tables XDR (ou `Watchlist`) et jamais `TimeGenerated`. Chaque table a une famille. Chaque indicateur a sa règle de couverture et elle contrôle toutes ses tables. |

Ce que dit une ligne de couverture : `Status` (Absente ou inaccessible / Colonnes manquantes / Vide sur la fenêtre / Alimentée), `Impact` (« Compensé par … » ou « Non couvert : famille, résultats incomplets pour les règles … »), `MissingColumns`, `Remediation` (connecteur à activer).

### Sources ajoutées, par indicateur

| Indicateur | Ajouts |
| --- | --- |
| IP | `EntraIdSignInEvents`, `EntraIdSpnSignInEvents` et connexions d'applications, `AuditLogs`, `MicrosoftGraphActivityLogs`, `IdentityQueryEvents`, `IdentityDirectoryEvents`, ASIM (authentification, sessions réseau, web), Azure Firewall (règles réseau et applicatives), `Syslog` (SSH), `Heartbeat` (IP de l'agent) |
| Compte | Windows 4624 à 4776 et Defender for Identity dans la timeline (avant : rien côté on-premises sans Defender for Endpoint), `MicrosoftGraphActivityLogs` (rattaché par l'identifiant d'objet de l'utilisateur), ASIM, SSH |
| Machine | 4769 journalisés par les DC pour les services de la machine (seule trace si la machine n'envoie pas ses journaux), Defender for Identity, ASIM, `Syslog`, `Event`, `Heartbeat`, CEF |
| Processus | `ASimProcessEventLogs` (Sysmon, Linux, EDR tiers) |
| Hash | `ASimFileEventLogs`, `ASimProcessEventLogs`, téléchargements vus par le proxy (`ASimWebSessionLogs`, `CommonSecurityLog.FileHash`) |
| Domaine / URL | Réponses DNS de Defender for Endpoint (`DeviceEvents`, `DnsQueryResponse`), `ASimWebSessionLogs`, `AZFWApplicationRule`, postes vus par le proxy dans DM-P3 |
| Application | `EntraIdSpnSignInEvents` via `_SpnSignins`, `CloudAppEvents` en secours d'`AuditLogs` |
| E-mail | Pas de source équivalente aux tables Defender for Office 365. Couverture et rôles des machines seulement. |

## B. Rôles des entités

`fragments/roles.kql` :
- **Machines** : DC détectés automatiquement (4768, cibles LDAP de Defender for Identity, écoute sur le port 88), plus la watchlist `EasyPivotRoles`.
- **IP** : DC, plus la watchlist (plages CIDR comprises).
- **Comptes** : IdentityInfo (rôle Entra ID, groupe AD privilégié, compte de service, compte sensible ou leurre), watchlist, catégorie déduite du nom.
- **Modèle de watchlist** : `watchlists/EasyPivotRoles.csv`.

`fragments/win_security.kql` ajoute :
- `TargetHost` : machine visée, par exemple le service d'un 4769 ou le serveur d'un 4648 ;
- `AuthAuthority` : DC qui a validé les identifiants ;
- `SourceHost` : poste d'origine.

| Règle | Changement |
| --- | --- |
| **AC-P2** (le cas signalé) | Colonne `Perspective` : session sur la machine, identifiants explicites, ticket Kerberos vu par le DC, poste d'origine vu par le DC, accès réseau au DC (GPO, SYSVOL, LDAP) en dernier. Colonnes `MachineRole` et `ValidatedBy`. |
| MC-P1 | Même découpage, vu depuis la machine. Les tickets 4769 des DC pour la machine sont ajoutés. Si la machine est un DC, ses ouvertures réseau sont mises à part. |
| IP-P2, IP-T2, `_IpEvents` (IP-S1 à IP-S4) | La cible est la machine réellement visée. Le DC qui valide est séparé (`ValidatedBy`, série « validation »). |
| IP-T1 | `LoggedOn` (qui journalise), `Target`, `ValidatedBy`, rôle. |
| Toutes les règles qui listent des machines ou des comptes | Rôle annoté (`dc01 [DC]`, `MachineRole`, `AccountRole`, `AccountKind`). Concerne IP, Compte, Machine, Processus, Hash, Domaine et E-mail. |
| IP-P6, AC-P5, MC-P5 (nouvelles) | Nature et rôle de l'entité avant de pivoter : IP partagée ou d'infrastructure, compte privilégié ou de service (y compris non déclaré), machine critique ou non couverte. |
| AP-S1, AP-P2 | `AppOrigin` : application Microsoft, du tenant, ou d'un autre tenant. |

## À vérifier sur un vrai workspace

Hypothèses prises sur la documentation, sans exécution :
- `EntraIdSignInEvents.LogonType` contient « nonInteractive » pour les connexions non interactives (le test est `contains "noninteractive"`, insensible à la casse).
- `DeviceEvents` / `DnsQueryResponse` : `AdditionalFields.DnsQueryString` et `DnsQueryResult`.
- `IdentityInfo` dans Defender XDR : les colonnes propres à l'UEBA de Sentinel (`AccountUPN`, `GroupMembership`, `IsServiceAccount`) sont lues avec `column_ifexists`, donc sans erreur si elles manquent, mais les rôles correspondants seront alors vides.
- `getschema` et `print` à l'intérieur d'un `union isfuzzy=true` dans le portail Defender (règles de couverture, variante Defender).
- Volume et coût :
  - la détection des DC lit une journée de 4768 et de `DeviceNetworkEvents` sur le port 88 ;
  - les règles de couverture comptent les événements de chaque table sur 4 jours.

## Limites connues et suites possibles

- `OfficeActivity` et `CloudAppEvents` se recoupent dans plusieurs règles (AC-P3, AC-P4, AC-T1, IP-P3, `_IpEvents`). C'était déjà le cas avant ce travail. Le même mécanisme « table de secours seulement si la principale manque » pourrait s'y appliquer, mais les deux tables ne portent pas exactement les mêmes charges.
- Pas de test d'exécution. L'étape suivante serait des scénarios exécutables : jeux de données synthétiques plus résultats attendus, dans l'émulateur ADX (Kustainer). Par exemple « WKS01 apparaît en session, DC01 seulement en ValidatedBy ».
- Côté extension EasyPivot, aucune modification n'est nécessaire : le catalogue reste accepté (`isFullCatalog`, 66 règles). Elle pourrait ensuite :
  - mettre en avant les règles XX-S0 ;
  - mémoriser leur résultat par workspace et barrer dans le panneau les règles dont une famille n'est pas couverte (champ `sources`).
- L'extension choisit `queryDefender` dès qu'elle est sur security.microsoft.com, y compris dans le portail unifié où les tables Sentinel existent. Les branches `@sentinel-only` y sont donc absentes, ce qui n'est pas une régression : ces règles ne lisaient avant que des tables XDR.

## Itération 2 : précision au niveau de l'événement

Après relecture, les familles étaient trop grossières. Elles disaient « SecurityEvent couvre les fichiers » alors que ça dépend de la stratégie d'audit et des SACL.

### Couverture par membre

`schema/sources.json` décrit des membres : table entière, ou canal + EventID. Les règles XX-S0 contrôlent chaque membre lu et ajoutent le statut « Événements non collectés » : table alimentée, mais pas ces EventID.

### Sources ajoutées

- **Audit Windows de l'accès aux objets**, dans `_WinSecurity` :
  - nouvelles colonnes `ObjectType`, `AccessList`, `HandleId`, `ObjectValueName`, `ShareLocalPath` ;
  - colonne `ObjectAccess` : lecture, écriture, suppression, permissions, exécution, déduite des codes `%%44xx` de `AccessList`.
- **Sysmon**, avec le fragment `_Sysmon` qui lit `Event` (XML) ou `WindowsEvent` (JSON) et calcule `ProcessFile`, `SHA256`, `UserSam`, etc. Événements utilisés : 1 processus, 3 connexion, 7 DLL, 11 fichier créé, 12 à 14 registre, 15 flux Zone.Identifier (URL d'origine), 22 DNS, 23 et 26 suppression, 29 exécutable détecté.
- **Journal Système** : 7045 (service installé).

### Nouvelles règles

| Règle | Contenu |
| --- | --- |
| **AC-P6** Fichiers et partages accédés par le compte | 4656, 4660, 4663, 4670, 5140, 5145, Defender for Endpoint, Sysmon, ASIM, SharePoint et OneDrive. Regroupé par machine, dossier et type d'accès. Les lectures ne sont visibles que dans l'audit Windows et SharePoint. |
| **MC-P6** Fichiers et partages accédés sur la machine | Qui a lu ou écrit quoi sur un serveur de fichiers, y compris les écritures SMB à distance vues par Defender for Endpoint. |

Le 4660 (suppression) ne porte pas le nom du fichier : il est rattaché au 4656 ou 4663 par `HandleId`.

### Règles enrichies

| Indicateur | Règles | Ajouts |
| --- | --- | --- |
| Processus | PR-P1, PR-S1, PR-T1 | Sysmon 1 |
| Processus | PR-P2 | Sysmon 3 |
| Processus | PR-P3 | 4656, 4660, 4663, 4670 et Sysmon 11, 15, 23, 26 |
| Processus | PR-P4 | Sysmon 12 à 14 et 4657 |
| Hash | HS-P1, HS-S1 | Sysmon 1, 7, 15, 23, 26, 29 |
| Hash | HS-P2 | Sysmon 15 (URL et référent du téléchargement) |
| IP | IP-P4, `_IpEvents` | Sysmon 3, détail des 5140 et 5145 |
| Domaine | DM-P3, DM-P4, `_DomainHits` | Sysmon 22 et 3, avec le processus qui résout ou se connecte |
| Machine | MC-P3 | 4657, Sysmon 12 à 14, 7045 |
| Machine | MC-T1 | Sysmon, 4660, 4663, 5145 |

Les 30 variantes Defender sont conservées : les branches Windows et Sysmon sont dans des blocs `@sentinel-only`.

### À vérifier sur un vrai workspace

- `AccessList` dans `SecurityEvent` : codes `%%4416…`, ou texte rendu ? Les deux sont testés.
- Format de `Event.EventData` pour Sysmon : `<Data Name="Image">…</Data>` attendu.
- Volume des 4663 : avec des SACL larges, les règles AC-P6 et MC-P6 peuvent être lourdes. Elles sont préfiltrées sur le compte ou la machine.

## Itération 3 : découverte des emplacements (XX-S9)

Une règle générée par indicateur cherche la valeur dans toutes les tables et rend une ligne par (table, emplacement) :
- colonne ou chemin JSON exact, sur 5 niveaux ;
- rôle probable (source, destination) ;
- valeur exacte ou contenue dans un texte ;
- statistiques de la table : volume, période, heures actives, machines, comptes, actions ;
- statut par rapport aux colonnes que les règles lisent (« Lu par les règles », « Colonne lue, chemin JSON à vérifier », « Non lu par les règles »).

Deux choix techniques, dictés par des contraintes de KQL :
- `search` exige un terme constant. J'utilise `union withsource=Table * | where * has Term`, qui accepte le terme normalisé par indicateur (SAM, nom court, nom de fichier, domaine).
- `extract_json` et `extract_all` exigent un chemin ou une regex constants. Le chemin est donc trouvé en dépliant le JSON niveau par niveau (`bag_keys`, indices de tableau). À chaque niveau, seules les branches qui contiennent la valeur sont gardées.

À vérifier sur un vrai workspace :
- le coût de `union *` sur la fenêtre ;
- la disponibilité de `union *` dans Defender (variante `Timestamp`).

Le statut compare à l'échelle de la **colonne** : une règle qui lit `RawEventData` ne lit pas forcément le chemin trouvé. D'où l'état intermédiaire « chemin JSON à vérifier », en attendant les `locations` du modèle déclaratif (partie C).
