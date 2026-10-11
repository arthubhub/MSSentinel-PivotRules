// Génère fragments/win_security.kql (normalisation SecurityEvent + WindowsEvent avec repli sur le XML brut).
// Usage : node scripts/generate-win-security.mjs — à relancer après modification de la liste F ci-dessous.
import fs from 'node:fs';
const se = JSON.parse(fs.readFileSync('schema/tables.json','utf8')).SecurityEvent;
// [nom normalisé, champs XML candidats (le premier sert de nom de colonne SecurityEvent s'il existe)]
const F = [
 ['SubjectUserSid',['SubjectUserSid']], ['SubjectUserName',['SubjectUserName']], ['SubjectDomainName',['SubjectDomainName']],
 ['SubjectLogonId',['SubjectLogonId']], ['TargetUserSid',['TargetUserSid','TargetSid']], ['TargetUserName',['TargetUserName']],
 ['TargetDomainName',['TargetDomainName']], ['TargetLogonId',['TargetLogonId']], ['LogonType',['LogonType']],
 ['LogonProcessName',['LogonProcessName']], ['AuthenticationPackageName',['AuthenticationPackageName','PackageName']],
 ['WorkstationName',['WorkstationName','Workstation']], ['IpAddress',['IpAddress','ClientAddress']], ['IpPort',['IpPort','ClientPort']],
 ['ProcessName',['ProcessName']], ['ElevatedToken',['ElevatedToken']], ['Status',['Status']], ['SubStatus',['SubStatus']],
 ['ServiceName',['ServiceName']], ['TicketEncryptionType',['TicketEncryptionType']], ['TicketOptions',['TicketOptions']],
 ['TargetServerName',['TargetServerName']], ['NewProcessName',['NewProcessName']], ['ParentProcessName',['ParentProcessName']],
 ['CommandLine',['CommandLine']], ['TaskName',['TaskName']], ['TaskContent',['TaskContent','TaskContentNew']],
 ['MemberName',['MemberName']], ['MemberSid',['MemberSid']], ['ServiceFileName',['ServiceFileName','ImagePath']],
 ['ShareName',['ShareName']], ['RelativeTargetName',['RelativeTargetName']], ['ObjectName',['ObjectName']],
 ['AccessMask',['AccessMask']], ['PrivilegeList',['PrivilegeList']],
];
const seExpr = ([n, xs]) => {
  const cols = xs.filter(x => se[x]).map(x => se[x] === 'string' ? x : `tostring(${x})`);
  const a = [...cols, ...xs.map(x => `XMLFIELD(_x, ${x})`)];
  return `${n} = ${a.length > 1 ? `coalesce(${a.join(', ')})` : a[0]}`;
};
const weExpr = ([n, xs]) => `${n} = coalesce(${[...xs.map(x => `tostring(EventData.${x})`), ...xs.map(x => `XMLFIELD(_x, ${x})`)].join(', ')})`;
const names = F.map(f => f[0]);
const ind = '            ';
const out = `// Événements de sécurité Windows normalisés, quelle que soit la table d'ingestion :
//   - SecurityEvent (agent AMA/MMA, connecteur « Windows Security Events ») ;
//   - WindowsEvent (Windows Event Forwarding, DCR personnalisée), restreint au fournisseur Security-Auditing.
// Contournement des défauts d'ingestion : quand une colonne est vide mais que le XML brut est présent
// (SecurityEvent.EventData, ou WindowsEvent.RawEventData quand l'analyse a échoué), la valeur est extraite
// du XML (<Data Name="…">). Toutes les colonnes normalisées sont des chaînes ; voir aussi TargetSam.
//
// Paramètres : start, end (fenêtre), ids (liste d'EventID, vide = tous), term (pré-filtre texte, vide = aucun ;
// recherché dans le XML brut et dans les colonnes de compte, de machine, d'IP et de processus).
// @requires: win_names
let _WinSecurity = (start:datetime, end:datetime, ids:dynamic, term:string) {
    union isfuzzy=true
    (
        SecurityEvent
        | where TimeGenerated between (start .. end)
        | where array_length(ids) == 0 or EventID in (ids)
        | where isempty(term) or EventData has term or Computer has term or IpAddress has term or TargetUserName has term
            or SubjectUserName has term or WorkstationName has term or NewProcessName has term or ParentProcessName has term
            or TargetServerName has term
        | extend _x = tostring(EventData)
        | extend
${F.map(f => ind + seExpr(f)).join(',\n')}
        | extend SourceTable = "SecurityEvent"
    ),
    (
        WindowsEvent
        | where TimeGenerated between (start .. end)
        | where Provider == "Microsoft-Windows-Security-Auditing"
        | where array_length(ids) == 0 or EventID in (ids)
        | where isempty(term) or tostring(EventData) has term or RawEventData has term or Computer has term
        | extend _x = tostring(RawEventData)
        | extend
${F.map(f => ind + weExpr(f)).join(',\n')}
        | extend SourceTable = "WindowsEvent"
    )
    | extend IpAddress = iff(IpAddress == "-", "", trim_start(@"::ffff:", IpAddress))
    | extend WorkstationName = iff(WorkstationName == "-", "", trim_start(@"\\\\\\\\", WorkstationName))
    | extend TargetSam = tolower(tostring(split(TargetUserName, "@")[0])), SubjectSam = tolower(SubjectUserName)
    | extend EventName = _WinEventName(EventID), LogonTypeName = _LogonTypeName(LogonType)
    | project TimeGenerated, SourceTable, Computer, EventID, EventName, ${names.join(', ')}, LogonTypeName, TargetSam, SubjectSam
};`;
fs.writeFileSync('fragments/win_security.kql', out + '\n');
