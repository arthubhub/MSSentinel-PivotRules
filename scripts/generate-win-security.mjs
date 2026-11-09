// Generates fragments/win_security.kql (SecurityEvent + WindowsEvent normalization with fallback to the raw XML).
// Usage: node scripts/generate-win-security.mjs (from the repository root), to run again after changing the F list below.
import fs from 'node:fs';
const se = JSON.parse(fs.readFileSync('schema/tables.json','utf8')).SecurityEvent;
// [normalized name, candidate XML fields (each one that is a SecurityEvent column is read first)]
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
 ['AccessMask',['AccessMask']], ['AccessList',['AccessList']], ['ObjectType',['ObjectType']], ['HandleId',['HandleId']],
 ['ObjectValueName',['ObjectValueName']], ['ShareLocalPath',['ShareLocalPath']], ['PrivilegeList',['PrivilegeList']],
];
const seExpr = ([n, xs]) => {
  const cols = xs.filter(x => se[x]).map(x => se[x] === 'string' ? x : `tostring(${x})`);
  const a = [...cols, ...xs.map(x => `XMLFIELD(_x, ${x})`)];
  return `${n} = ${a.length > 1 ? `coalesce(${a.join(', ')})` : a[0]}`;
};
const weExpr = ([n, xs]) => `${n} = coalesce(${[...xs.map(x => `tostring(EventData.${x})`), ...xs.map(x => `XMLFIELD(_x, ${x})`)].join(', ')})`;
// ObjectAccess (computed below) is projected just before PrivilegeList
const names = F.map(f => f[0]).flatMap(n => n === 'PrivilegeList' ? ['ObjectAccess', n] : [n]);
const ind = '            ';
const out = `// Windows security events normalized, whatever the ingestion table:
// for SecurityEvent, fields are re-parsed from the EventData XML when columns are empty (ingestion bugs), with a regex added at build time.
// Parameters: start, end (window), ids (EventID list, empty = all), term (text pre-filter, empty = none;
// searched in the raw XML and in the account, device, IP and process columns).
// Columns added so the logging device is not mistaken for the device actually used:
// - TargetHost: device actually targeted. 4769: the device of the requested service (ServiceName "FS01$"); 4648: TargetServerName;
//   4768, 4771, 4776: empty (credential validation only, the target is unknown); otherwise: Computer.
// - AuthAuthority: device that validated the credentials (DC, or the device itself for a local account over NTLM) for
//   4768, 4769, 4771 and 4776; empty otherwise.
// - SourceHost: declared source workstation (WorkstationName), otherwise the source IP.
// - ObjectAccess: rights requested on a file, key or share (read, write, delete, permissions,
//   execute) for 4656, 4657, 4660, 4663, 4670, 5140 and 5145 ("File System", "Registry", "Detailed File Share"
//   auditing: nothing is produced without an audit policy and, for files and registry, without a SACL).
// Sentinel-only fragment: removed from the Defender variant (rules call it inside @sentinel-only blocks).
// @requires: win_names
// @sentinel-only:begin
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
    | extend _svcAccount = tolower(tostring(split(ServiceName, "@")[0]))
    | extend TargetHost = tolower(case(
            EventID == 4769 and _svcAccount endswith "$", trim_end(@"\\$", _svcAccount),
            EventID in (4768, 4769, 4771, 4776), "",
            EventID == 4648 and isnotempty(TargetServerName) and TargetServerName !in~ ("-", "localhost", "127.0.0.1", "::1"), TargetServerName,
            Computer)),
        AuthAuthority = iff(EventID in (4768, 4769, 4771, 4776), tolower(Computer), ""),
        SourceHost = tolower(coalesce(WorkstationName, IpAddress))
    // Rights requested on an object (4656, 4663, 5145: AccessList %%44xx codes; 4660: delete; 4670: permissions)
    | extend ObjectAccess = iff(EventID in (4656, 4658, 4660, 4663, 4670, 5140, 5145, 4657), strcat_array(set_difference(pack_array(
            iff(AccessList has_any ("%%4416", "%%4419", "%%4423", "ReadData") or EventID == 5140, "read", ""),
            iff(AccessList has_any ("%%4417", "%%4418", "%%4420", "%%4424", "WriteData", "AppendData") or EventID == 4657, "write", ""),
            iff(AccessList has_any ("%%1537", "DELETE") or EventID == 4660, "delete", ""),
            iff(AccessList has_any ("%%1539", "%%1540", "WRITE_DAC", "WRITE_OWNER") or EventID == 4670, "permissions", ""),
            iff(AccessList has_any ("%%4421", "Execute"), "execute", "")), dynamic([""])), ", "), "")
    | project TimeGenerated, SourceTable, Computer, TargetHost, AuthAuthority, SourceHost, EventID, EventName, ${names.join(', ')}, LogonTypeName, TargetSam, SubjectSam
};
// @sentinel-only:end`;
fs.writeFileSync('fragments/win_security.kql', out + '\n');
