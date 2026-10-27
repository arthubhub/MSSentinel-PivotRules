# Correspondances incertaines — `locations` (#31)

Généré par `scripts/generate-locations.mjs`. **Rien ici n'est publié** dans `pivot-rules.json` : ce rapport sert à la relecture humaine avant intégration (consigne du plan, phase 2b).

Pour chaque paire `Table.Colonne`, le ou les types candidats, le niveau d'où vient le signal et la preuve. Classées par type, du signal le plus probable (comparaison de règle sur une sous-chaîne) au moins probable (motif de nom seul).

## Résumé

| Type | Confiant (publié dans locations.yml) | Incertain (ce rapport) |
| --- | --- | --- |
| ip | 47 | 90 |
| account | 47 | 112 |
| email | 18 | 24 |
| url | 11 | 33 |
| domain | 7 | 67 |
| device | 48 | 105 |
| process | 27 | 99 |
| application | 8 | 38 |
| hash | 30 | 40 |
| **Total** | **243** | **608** |

Conflits (même colonne confiante pour deux types différents) : **0** — voir section dédiée.
Arbitrages account/email appliqués (paire publiée dans les deux types) : **10** — voir section dédiée.

## ip (90)

| Table.Colonne | Niveau | Preuve | Source |
| --- | --- | --- | --- |
| `SecurityAlert.CompromisedEntity` | colonne polymorphe (écartée par audit) | Entité compromise d'une alerte : un nom d'hôte ou une IP selon l'alerte. Utilisée dans les deux sens par les règles — MC-S2 `CompromisedEntity has ValueShort` (device) et IP-P5 `CompromisedEntity == Value` (ip). | audit manuel (#31) |
| `ThreatIntelIndicators.ObservableValue` | colonne polymorphe (écartée par audit) | Colonne STIX polymorphe : contient une IP, un domaine, une URL ou un hash selon la ligne (discriminée par ObservableKey/Pattern/Data.pattern, pas par la colonne elle-même). ThreatIntelligenceIndicator (table historique) n'a pas ce problème : colonnes déjà séparées par type. | audit manuel (#31) |
| `SecurityAlert.Entities` | règle (comparaison faible/sous-chaîne) | Entities has … (SecurityAlert) | rules/ip/IP-P5.yaml [IP-P5] |
| `Syslog.SyslogMessage` | règle (comparaison faible/sous-chaîne) | SyslogMessage has … (Syslog) | rules/ip/IP-P2.yaml [IP-P2]; rules/ip/IP-T3.yaml [IP-T3]; fragments/ip_events.kql |
| `ThreatIntelIndicators.Pattern` | règle (comparaison faible/sous-chaîne) | Pattern has … (ThreatIntelIndicators) | rules/ip/IP-P5.yaml [IP-P5] |
| `AADGraphActivityLogs.CallerIpAddress` | motif de nom (schémas) | motif de nom (jetons : caller, ip, address) | schemas/ |
| `AADNonInteractiveUserSignInLogs.GlobalSecureAccessIpAddress` | motif de nom (schémas) | motif de nom (jetons : global, secure, access, ip, address) | schemas/ |
| `AADUserRiskEvents.IpAddress` | motif de nom (schémas) | motif de nom (jetons : ip, address) | schemas/ |
| `AppDependencies.ClientIP` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `AppExceptions.ClientIP` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `AppMetrics.ClientIP` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `AppPerformanceCounters.ClientIP` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `AppRequests.ClientIP` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `AppTraces.ClientIP` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `ASimAuthenticationEventLogs.DvcIpAddr` | motif de nom (schémas) | motif de nom (jetons : dvc, ip, addr) | schemas/ |
| `ASimAuthenticationEventLogs.ThreatIpAddr` | motif de nom (schémas) | motif de nom (jetons : threat, ip, addr) | schemas/ |
| `ASimDnsActivityLogs.DstIpAddr` | motif de nom (schémas) | motif de nom (jetons : dst, ip, addr) | schemas/ |
| `ASimDnsActivityLogs.DvcIpAddr` | motif de nom (schémas) | motif de nom (jetons : dvc, ip, addr) | schemas/ |
| `ASimDnsActivityLogs.SrcIpAddr` | motif de nom (schémas) | motif de nom (jetons : src, ip, addr) | schemas/ |
| `ASimDnsActivityLogs.ThreatIpAddr` | motif de nom (schémas) | motif de nom (jetons : threat, ip, addr) | schemas/ |
| `ASimFileEventLogs.DvcIpAddr` | motif de nom (schémas) | motif de nom (jetons : dvc, ip, addr) | schemas/ |
| `ASimFileEventLogs.SrcIpAddr` | motif de nom (schémas) | motif de nom (jetons : src, ip, addr) | schemas/ |
| `ASimNetworkSessionLogs.DvcIpAddr` | motif de nom (schémas) | motif de nom (jetons : dvc, ip, addr) | schemas/ |
| `ASimNetworkSessionLogs.ThreatIpAddr` | motif de nom (schémas) | motif de nom (jetons : threat, ip, addr) | schemas/ |
| `ASimProcessEventLogs.DvcIpAddr` | motif de nom (schémas) | motif de nom (jetons : dvc, ip, addr) | schemas/ |
| `AWSCloudTrail.SourceIpAddress` | motif de nom (schémas) | motif de nom (jetons : source, ip, address) | schemas/ |
| `AZFWDnsQuery.SourceIp` | motif de nom (schémas) | motif de nom (jetons : source, ip) | schemas/ |
| `AZFWNatRule.DestinationIp` | motif de nom (schémas) | motif de nom (jetons : destination, ip) | schemas/ |
| `AZFWNatRule.SourceIp` | motif de nom (schémas) | motif de nom (jetons : source, ip) | schemas/ |
| `AZFWNatRule.TranslatedIp` | motif de nom (schémas) | motif de nom (jetons : translated, ip) | schemas/ |
| `AZFWThreatIntel.DestinationIp` | motif de nom (schémas) | motif de nom (jetons : destination, ip) | schemas/ |
| `AZFWThreatIntel.SourceIp` | motif de nom (schémas) | motif de nom (jetons : source, ip) | schemas/ |
| `AzureDiagnostics.client_ip_s` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `AzureDiagnostics.clientIp_s` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `AzureDiagnostics.clientIP_s` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `AzureDiagnostics.clientIpXff_s` | motif de nom (schémas) | motif de nom (jetons : client, ip, xff) | schemas/ |
| `AzureDiagnostics.DestinationIp_s` | motif de nom (schémas) | motif de nom (jetons : destination, ip) | schemas/ |
| `AzureDiagnostics.originIp_s` | motif de nom (schémas) | motif de nom (jetons : origin, ip) | schemas/ |
| `AzureDiagnostics.originIP_s` | motif de nom (schémas) | motif de nom (jetons : origin, ip) | schemas/ |
| `AzureDiagnostics.ServerIp_s` | motif de nom (schémas) | motif de nom (jetons : server, ip) | schemas/ |
| `AzureDiagnostics.socketIp_s` | motif de nom (schémas) | motif de nom (jetons : socket, ip) | schemas/ |
| `AzureDiagnostics.socketIP_s` | motif de nom (schémas) | motif de nom (jetons : socket, ip) | schemas/ |
| `AzureDiagnostics.SourceIP` | motif de nom (schémas) | motif de nom (jetons : source, ip) | schemas/ |
| `AzureDiagnostics.TranslatedIp_s` | motif de nom (schémas) | motif de nom (jetons : translated, ip) | schemas/ |
| `BehaviorAnalytics.SourceIPAddress` | motif de nom (schémas) | motif de nom (jetons : source, ip, address) | schemas/ |
| `CloudAppEvents.IPCategory` | motif de nom (schémas) | motif de nom (jetons : ip, category) | schemas/ |
| `CloudAppEvents.IPTags` | motif de nom (schémas) | motif de nom (jetons : ip, tags) | schemas/ |
| `CommonSecurityLog.MaliciousIP` | motif de nom (schémas) | motif de nom (jetons : malicious, ip) | schemas/ |
| `CopilotActivity.SrcIpAddr` | motif de nom (schémas) | motif de nom (jetons : src, ip, addr) | schemas/ |
| `DataverseActivity.ClientIp` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `DeviceEvents.InitiatingProcessRemoteSessionIP` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, ip) | schemas/ |
| `DeviceEvents.ProcessRemoteSessionIP` | motif de nom (schémas) | motif de nom (jetons : process, remote, session, ip) | schemas/ |
| `DeviceFileEvents.InitiatingProcessRemoteSessionIP` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, ip) | schemas/ |
| `DeviceFileEvents.RequestSourceIP` | motif de nom (schémas) | motif de nom (jetons : request, source, ip) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessRemoteSessionIP` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, ip) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessRemoteSessionIP` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, ip) | schemas/ |
| `DeviceLogonEvents.RemoteIPType` | motif de nom (schémas) | motif de nom (jetons : remote, ip, type) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessRemoteSessionIP` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, ip) | schemas/ |
| `DeviceNetworkEvents.LocalIPType` | motif de nom (schémas) | motif de nom (jetons : local, ip, type) | schemas/ |
| `DeviceNetworkEvents.RemoteIPType` | motif de nom (schémas) | motif de nom (jetons : remote, ip, type) | schemas/ |
| `DeviceNetworkInfo.IPv4Dhcp` | motif de nom (schémas) | motif de nom (jetons : ip, dhcp) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessRemoteSessionIP` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, ip) | schemas/ |
| `DeviceProcessEvents.ProcessRemoteSessionIP` | motif de nom (schémas) | motif de nom (jetons : process, remote, session, ip) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessRemoteSessionIP` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, ip) | schemas/ |
| `DnsEvents.ClientIP` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `DnsEvents.IPAddresses` | motif de nom (schémas) | motif de nom (jetons : ip, addresses) | schemas/ |
| `DnsEvents.MaliciousIP` | motif de nom (schémas) | motif de nom (jetons : malicious, ip) | schemas/ |
| `Dynamics365Activity.ClientIP` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `McasShadowItReporting.IpAddress` | motif de nom (schémas) | motif de nom (jetons : ip, address) | schemas/ |
| `MicrosoftPurviewInformationProtection.ClientIP` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `OfficeActivity.Client_IPAddress` | motif de nom (schémas) | motif de nom (jetons : client, ip, address) | schemas/ |
| `OfficeActivity.ClientIP_` | motif de nom (schémas) | motif de nom (jetons : client, ip) | schemas/ |
| `ProtectionStatus.ComputerIP_Hidden` | motif de nom (schémas) | motif de nom (jetons : computer, ip, hidden) | schemas/ |
| `SecurityEvent.ClientIPAddress` | motif de nom (schémas) | motif de nom (jetons : client, ip, address) | schemas/ |
| `SecurityEvent.IpAddress` | motif de nom (schémas) | motif de nom (jetons : ip, address) | schemas/ |
| `SecurityEvent.IpPort` | motif de nom (schémas) | motif de nom (jetons : ip, port) | schemas/ |
| `SigninLogs.GlobalSecureAccessIpAddress` | motif de nom (schémas) | motif de nom (jetons : global, secure, access, ip, address) | schemas/ |
| `SigninLogs.IPAddressFromResourceProvider` | motif de nom (schémas) | motif de nom (jetons : ip, address, from, resource, provider) | schemas/ |
| `ThreatIntelligenceIndicator.EmailSourceIpAddress` | motif de nom (schémas) | motif de nom (jetons : email, source, ip, address) | schemas/ |
| `ThreatIntelligenceIndicator.NetworkDestinationIP` | motif de nom (schémas) | motif de nom (jetons : network, destination, ip) | schemas/ |
| `ThreatIntelligenceIndicator.NetworkIP` | motif de nom (schémas) | motif de nom (jetons : network, ip) | schemas/ |
| `ThreatIntelligenceIndicator.NetworkSourceIP` | motif de nom (schémas) | motif de nom (jetons : network, source, ip) | schemas/ |
| `VMBoundPort.Ip` | motif de nom (schémas) | motif de nom (jetons : ip) | schemas/ |
| `VMComputer.Ipv4Addresses` | motif de nom (schémas) | motif de nom (jetons : ip, addresses) | schemas/ |
| `VMComputer.Ipv4DefaultGateways` | motif de nom (schémas) | motif de nom (jetons : ip, default, gateways) | schemas/ |
| `VMComputer.Ipv4SubnetMasks` | motif de nom (schémas) | motif de nom (jetons : ip, subnet, masks) | schemas/ |
| `VMComputer.Ipv6Addresses` | motif de nom (schémas) | motif de nom (jetons : ip, addresses) | schemas/ |
| `VMConnection.DestinationIp` | motif de nom (schémas) | motif de nom (jetons : destination, ip) | schemas/ |
| `VMConnection.RemoteIp` | motif de nom (schémas) | motif de nom (jetons : remote, ip) | schemas/ |
| `VMConnection.SourceIp` | motif de nom (schémas) | motif de nom (jetons : source, ip) | schemas/ |

## account (112)

| Table.Colonne | Niveau | Preuve | Source |
| --- | --- | --- | --- |
| `CloudAppEvents.RawEventData` | règle (comparaison faible/sous-chaîne) | RawEventData has … (CloudAppEvents) | rules/account/AC-P4.yaml [AC-P4] |
| `OfficeActivity.Parameters` | règle (comparaison faible/sous-chaîne) | Parameters has … (OfficeActivity) | rules/account/AC-P4.yaml [AC-P4] |
| `Syslog.SyslogMessage` | règle (comparaison faible/sous-chaîne) | SyslogMessage has … (Syslog) | rules/account/AC-P2.yaml [AC-P2]; rules/account/AC-S2.yaml [AC-S2]; rules/account/AC-T1.yaml [AC-T1] |
| `AADNonInteractiveUserSignInLogs.UserDisplayName` | motif de nom (schémas) | motif de nom (jetons : user, display, name) | schemas/ |
| `AADRiskyUsers.UserDisplayName` | motif de nom (schémas) | motif de nom (jetons : user, display, name) | schemas/ |
| `AADRiskyUsers.UserPrincipalName` | motif de nom (schémas) | motif de nom (jetons : user, principal, name) | schemas/ |
| `AADUserRiskEvents.UserDisplayName` | motif de nom (schémas) | motif de nom (jetons : user, display, name) | schemas/ |
| `AADUserRiskEvents.UserPrincipalName` | motif de nom (schémas) | motif de nom (jetons : user, principal, name) | schemas/ |
| `ADFSSignInLogs.UserDisplayName` | motif de nom (schémas) | motif de nom (jetons : user, display, name) | schemas/ |
| `ADFSSignInLogs.UserPrincipalName` | motif de nom (schémas) | motif de nom (jetons : user, principal, name) | schemas/ |
| `AlertEvidence.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `AlertEvidence.AccountName` | motif de nom (schémas) | motif de nom (jetons : account, name) | schemas/ |
| `Anomalies.UserName` | motif de nom (schémas) | motif de nom (jetons : user, name) | schemas/ |
| `Anomalies.UserPrincipalName` | motif de nom (schémas) | motif de nom (jetons : user, principal, name) | schemas/ |
| `ASimFileEventLogs.ActorUserSid` | motif de nom (schémas) | motif de nom (jetons : actor, user, sid) | schemas/ |
| `AWSCloudTrail.RecipientAccountId` | motif de nom (schémas) | motif de nom (jetons : recipient, account, id) | schemas/ |
| `AWSCloudTrail.SessionIssuerAccountId` | motif de nom (schémas) | motif de nom (jetons : session, issuer, account, id) | schemas/ |
| `AWSCloudTrail.SessionIssuerUserName` | motif de nom (schémas) | motif de nom (jetons : session, issuer, user, name) | schemas/ |
| `AWSCloudTrail.UserIdentityAccountId` | motif de nom (schémas) | motif de nom (jetons : user, identity, account, id) | schemas/ |
| `AWSCloudTrail.UserIdentityUserName` | motif de nom (schémas) | motif de nom (jetons : user, identity, user, name) | schemas/ |
| `AWSGuardDuty.AccountId` | motif de nom (schémas) | motif de nom (jetons : account, id) | schemas/ |
| `AzureDiagnostics.server_principal_sid_s` | motif de nom (schémas) | motif de nom (jetons : server, principal, sid) | schemas/ |
| `BehaviorAnalytics.UserName` | motif de nom (schémas) | motif de nom (jetons : user, name) | schemas/ |
| `BehaviorAnalytics.UserPrincipalName` | motif de nom (schémas) | motif de nom (jetons : user, principal, name) | schemas/ |
| `CloudAppEvents.AccountDisplayName` | motif de nom (schémas) | motif de nom (jetons : account, display, name) | schemas/ |
| `CloudAppEvents.AccountId` | motif de nom (schémas) | motif de nom (jetons : account, id) | schemas/ |
| `CommonSecurityLog.DestinationUserName` | motif de nom (schémas) | motif de nom (jetons : destination, user, name) | schemas/ |
| `CommonSecurityLog.SourceUserName` | motif de nom (schémas) | motif de nom (jetons : source, user, name) | schemas/ |
| `DataverseActivity.UserUpn` | motif de nom (schémas) | motif de nom (jetons : user, upn) | schemas/ |
| `DeviceEvents.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `DeviceEvents.AccountName` | motif de nom (schémas) | motif de nom (jetons : account, name) | schemas/ |
| `DeviceEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `DeviceEvents.InitiatingProcessAccountName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, name) | schemas/ |
| `DeviceEvents.InitiatingProcessAccountObjectId` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, object, id) | schemas/ |
| `DeviceEvents.InitiatingProcessAccountUpn` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, upn) | schemas/ |
| `DeviceFileEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `DeviceFileEvents.InitiatingProcessAccountObjectId` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, object, id) | schemas/ |
| `DeviceFileEvents.InitiatingProcessAccountUpn` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, upn) | schemas/ |
| `DeviceFileEvents.RequestAccountDomain` | motif de nom (schémas) | motif de nom (jetons : request, account, domain) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessAccountName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, name) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessAccountObjectId` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, object, id) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessAccountUpn` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, upn) | schemas/ |
| `DeviceLogonEvents.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessAccountName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, name) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessAccountObjectId` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, object, id) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessAccountUpn` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, upn) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessAccountName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, name) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessAccountObjectId` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, object, id) | schemas/ |
| `DeviceProcessEvents.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `DeviceProcessEvents.AccountName` | motif de nom (schémas) | motif de nom (jetons : account, name) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessAccountName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, name) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessAccountObjectId` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, object, id) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessAccountUpn` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, upn) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessAccountName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, name) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessAccountObjectId` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, object, id) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessAccountUpn` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, upn) | schemas/ |
| `Event.UserName` | motif de nom (schémas) | motif de nom (jetons : user, name) | schemas/ |
| `IdentityDirectoryEvents.AccountDisplayName` | motif de nom (schémas) | motif de nom (jetons : account, display, name) | schemas/ |
| `IdentityDirectoryEvents.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `IdentityDirectoryEvents.AccountName` | motif de nom (schémas) | motif de nom (jetons : account, name) | schemas/ |
| `IdentityDirectoryEvents.TargetAccountDisplayName` | motif de nom (schémas) | motif de nom (jetons : target, account, display, name) | schemas/ |
| `IdentityDirectoryEvents.TargetAccountUpn` | motif de nom (schémas) | motif de nom (jetons : target, account, upn) | schemas/ |
| `IdentityInfo.AccountDisplayName` | motif de nom (schémas) | motif de nom (jetons : account, display, name) | schemas/ |
| `IdentityInfo.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `IdentityInfo.AccountSID` | motif de nom (schémas) | motif de nom (jetons : account, sid) | schemas/ |
| `IdentityInfo.AccountTenantId` | motif de nom (schémas) | motif de nom (jetons : account, tenant, id) | schemas/ |
| `IdentityInfo.AccountUPN` | motif de nom (schémas) | motif de nom (jetons : account, upn) | schemas/ |
| `IdentityInfo.OnPremisesAccountObjectId` | motif de nom (schémas) | motif de nom (jetons : on, premises, account, object, id) | schemas/ |
| `IdentityInfo.SAMAccountName` | motif de nom (schémas) | motif de nom (jetons : sam, account, name) | schemas/ |
| `IdentityLogonEvents.AccountDisplayName` | motif de nom (schémas) | motif de nom (jetons : account, display, name) | schemas/ |
| `IdentityLogonEvents.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `IdentityLogonEvents.TargetAccountDisplayName` | motif de nom (schémas) | motif de nom (jetons : target, account, display, name) | schemas/ |
| `IdentityQueryEvents.AccountDisplayName` | motif de nom (schémas) | motif de nom (jetons : account, display, name) | schemas/ |
| `IdentityQueryEvents.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `IdentityQueryEvents.AccountName` | motif de nom (schémas) | motif de nom (jetons : account, name) | schemas/ |
| `IdentityQueryEvents.TargetAccountDisplayName` | motif de nom (schémas) | motif de nom (jetons : target, account, display, name) | schemas/ |
| `IdentityQueryEvents.TargetAccountUpn` | motif de nom (schémas) | motif de nom (jetons : target, account, upn) | schemas/ |
| `McasShadowItReporting.EnrichedUserName` | motif de nom (schémas) | motif de nom (jetons : enriched, user, name) | schemas/ |
| `OfficeActivity.LogonUserDisplayName` | motif de nom (schémas) | motif de nom (jetons : logon, user, display, name) | schemas/ |
| `OfficeActivity.LogonUserSid` | motif de nom (schémas) | motif de nom (jetons : logon, user, sid) | schemas/ |
| `OfficeActivity.MailboxOwnerMasterAccountSid` | motif de nom (schémas) | motif de nom (jetons : mailbox, owner, master, account, sid) | schemas/ |
| `OfficeActivity.MailboxOwnerSid` | motif de nom (schémas) | motif de nom (jetons : mailbox, owner, sid) | schemas/ |
| `OfficeActivity.MailboxOwnerUPN` | motif de nom (schémas) | motif de nom (jetons : mailbox, owner, upn) | schemas/ |
| `OfficeActivity.TargetUserOrGroupName` | motif de nom (schémas) | motif de nom (jetons : target, user, or, group, name) | schemas/ |
| `SecurityEvent.Account` | motif de nom (schémas) | motif de nom (jetons : account) | schemas/ |
| `SecurityEvent.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `SecurityEvent.AccountName` | motif de nom (schémas) | motif de nom (jetons : account, name) | schemas/ |
| `SecurityEvent.AccountSessionIdentifier` | motif de nom (schémas) | motif de nom (jetons : account, session, identifier) | schemas/ |
| `SecurityEvent.FullyQualifiedSubjectUserName` | motif de nom (schémas) | motif de nom (jetons : fully, qualified, subject, user, name) | schemas/ |
| `SecurityEvent.MemberSid` | motif de nom (schémas) | motif de nom (jetons : member, sid) | schemas/ |
| `SecurityEvent.SamAccountName` | motif de nom (schémas) | motif de nom (jetons : sam, account, name) | schemas/ |
| `SecurityEvent.ServiceAccount` | motif de nom (schémas) | motif de nom (jetons : service, account) | schemas/ |
| `SecurityEvent.SidHistory` | motif de nom (schémas) | motif de nom (jetons : sid, history) | schemas/ |
| `SecurityEvent.SubjectAccount` | motif de nom (schémas) | motif de nom (jetons : subject, account) | schemas/ |
| `SecurityEvent.SubjectMachineSID` | motif de nom (schémas) | motif de nom (jetons : subject, machine, sid) | schemas/ |
| `SecurityEvent.SubjectUserName` | motif de nom (schémas) | motif de nom (jetons : subject, user, name) | schemas/ |
| `SecurityEvent.SubjectUserSid` | motif de nom (schémas) | motif de nom (jetons : subject, user, sid) | schemas/ |
| `SecurityEvent.TargetAccount` | motif de nom (schémas) | motif de nom (jetons : target, account) | schemas/ |
| `SecurityEvent.TargetOutboundUserName` | motif de nom (schémas) | motif de nom (jetons : target, outbound, user, name) | schemas/ |
| `SecurityEvent.TargetSid` | motif de nom (schémas) | motif de nom (jetons : target, sid) | schemas/ |
| `SecurityEvent.TargetUserName` | motif de nom (schémas) | motif de nom (jetons : target, user, name) | schemas/ |
| `SecurityEvent.TargetUserSid` | motif de nom (schémas) | motif de nom (jetons : target, user, sid) | schemas/ |
| `SecurityEvent.UserPrincipalName` | motif de nom (schémas) | motif de nom (jetons : user, principal, name) | schemas/ |
| `SigninLogs.UserDisplayName` | motif de nom (schémas) | motif de nom (jetons : user, display, name) | schemas/ |
| `StorageBlobLogs.AccountName` | motif de nom (schémas) | motif de nom (jetons : account, name) | schemas/ |
| `StorageBlobLogs.RequesterUpn` | motif de nom (schémas) | motif de nom (jetons : requester, upn) | schemas/ |
| `VMProcess.UserName` | motif de nom (schémas) | motif de nom (jetons : user, name) | schemas/ |

## email (24)

| Table.Colonne | Niveau | Preuve | Source |
| --- | --- | --- | --- |
| `CloudAppEvents.RawEventData` | règle (comparaison faible/sous-chaîne) | RawEventData has … (CloudAppEvents) | rules/email/EM-P7.yaml [EM-P7] |
| `MessageEvents.RecipientDetails` | règle (comparaison faible/sous-chaîne) | RecipientDetails has … (MessageEvents) | rules/email/EM-P7.yaml [EM-P7] |
| `OfficeActivity.Members` | règle (comparaison faible/sous-chaîne) | Members has … (OfficeActivity) | rules/email/EM-P7.yaml [EM-P7] |
| `AlertEvidence.EmailSubject` | motif de nom (schémas) | motif de nom (jetons : email, subject) | schemas/ |
| `EmailEvents.EmailAction` | motif de nom (schémas) | motif de nom (jetons : email, action) | schemas/ |
| `EmailEvents.EmailActionPolicy` | motif de nom (schémas) | motif de nom (jetons : email, action, policy) | schemas/ |
| `EmailEvents.EmailActionPolicyGuid` | motif de nom (schémas) | motif de nom (jetons : email, action, policy, guid) | schemas/ |
| `EmailEvents.EmailClusterId` | motif de nom (schémas) | motif de nom (jetons : email, cluster, id) | schemas/ |
| `EmailEvents.EmailDirection` | motif de nom (schémas) | motif de nom (jetons : email, direction) | schemas/ |
| `EmailEvents.EmailLanguage` | motif de nom (schémas) | motif de nom (jetons : email, language) | schemas/ |
| `EmailEvents.EmailSize` | motif de nom (schémas) | motif de nom (jetons : email, size) | schemas/ |
| `GCPAuditLogs.PrincipalEmail` | motif de nom (schémas) | motif de nom (jetons : principal, email) | schemas/ |
| `IdentityInfo.MailAddress` | motif de nom (schémas) | motif de nom (jetons : mail, address) | schemas/ |
| `LAQueryLogs.AADEmail` | motif de nom (schémas) | motif de nom (jetons : aad, email) | schemas/ |
| `MicrosoftPurviewInformationProtection.EmailInfo` | motif de nom (schémas) | motif de nom (jetons : email, info) | schemas/ |
| `ThreatIntelligenceIndicator.EmailEncoding` | motif de nom (schémas) | motif de nom (jetons : email, encoding) | schemas/ |
| `ThreatIntelligenceIndicator.EmailLanguage` | motif de nom (schémas) | motif de nom (jetons : email, language) | schemas/ |
| `ThreatIntelligenceIndicator.EmailRecipient` | motif de nom (schémas) | motif de nom (jetons : email, recipient) | schemas/ |
| `ThreatIntelligenceIndicator.EmailSenderAddress` | motif de nom (schémas) | motif de nom (jetons : email, sender, address) | schemas/ |
| `ThreatIntelligenceIndicator.EmailSenderName` | motif de nom (schémas) | motif de nom (jetons : email, sender, name) | schemas/ |
| `ThreatIntelligenceIndicator.EmailSourceDomain` | motif de nom (schémas) | motif de nom (jetons : email, source, domain) | schemas/ |
| `ThreatIntelligenceIndicator.EmailSourceIpAddress` | motif de nom (schémas) | motif de nom (jetons : email, source, ip, address) | schemas/ |
| `ThreatIntelligenceIndicator.EmailSubject` | motif de nom (schémas) | motif de nom (jetons : email, subject) | schemas/ |
| `ThreatIntelligenceIndicator.EmailXMailer` | motif de nom (schémas) | motif de nom (jetons : email, x, mailer) | schemas/ |

## url (33)

| Table.Colonne | Niveau | Preuve | Source |
| --- | --- | --- | --- |
| `AADGraphActivityLogs.RequestUri` | motif de nom (schémas) | motif de nom (jetons : request, uri) | schemas/ |
| `ASimAuthenticationEventLogs.EventReportUrl` | motif de nom (schémas) | motif de nom (jetons : event, report, url) | schemas/ |
| `ASimAuthenticationEventLogs.TargetUrl` | motif de nom (schémas) | motif de nom (jetons : target, url) | schemas/ |
| `ASimDnsActivityLogs.EventReportUrl` | motif de nom (schémas) | motif de nom (jetons : event, report, url) | schemas/ |
| `ASimFileEventLogs.EventReportUrl` | motif de nom (schémas) | motif de nom (jetons : event, report, url) | schemas/ |
| `ASimFileEventLogs.TargetUrl` | motif de nom (schémas) | motif de nom (jetons : target, url) | schemas/ |
| `ASimNetworkSessionLogs.EventReportUrl` | motif de nom (schémas) | motif de nom (jetons : event, report, url) | schemas/ |
| `ASimProcessEventLogs.EventReportUrl` | motif de nom (schémas) | motif de nom (jetons : event, report, url) | schemas/ |
| `ASimWebSessionLogs.UrlOriginal` | motif de nom (schémas) | motif de nom (jetons : url, original) | schemas/ |
| `AZFWApplicationRule.TargetUrl` | motif de nom (schémas) | motif de nom (jetons : target, url) | schemas/ |
| `AZKVAuditLogs.RequestUri` | motif de nom (schémas) | motif de nom (jetons : request, uri) | schemas/ |
| `AzureDiagnostics.originalRequestUriWithArgs_s` | motif de nom (schémas) | motif de nom (jetons : original, request, uri, with, args) | schemas/ |
| `AzureDiagnostics.originUrl_s` | motif de nom (schémas) | motif de nom (jetons : origin, url) | schemas/ |
| `AzureDiagnostics.probeUrl_s` | motif de nom (schémas) | motif de nom (jetons : probe, url) | schemas/ |
| `AzureDiagnostics.requestUri_s` | motif de nom (schémas) | motif de nom (jetons : request, uri) | schemas/ |
| `AzureDiagnostics.TargetUrl_s` | motif de nom (schémas) | motif de nom (jetons : target, url) | schemas/ |
| `CommonSecurityLog.RequestURL` | motif de nom (schémas) | motif de nom (jetons : request, url) | schemas/ |
| `DataverseActivity.InstanceUrl` | motif de nom (schémas) | motif de nom (jetons : instance, url) | schemas/ |
| `DataverseActivity.ItemUrl` | motif de nom (schémas) | motif de nom (jetons : item, url) | schemas/ |
| `Dynamics365Activity.InstanceUrl` | motif de nom (schémas) | motif de nom (jetons : instance, url) | schemas/ |
| `Dynamics365Activity.ItemUrl` | motif de nom (schémas) | motif de nom (jetons : item, url) | schemas/ |
| `EmailUrlInfo.UrlLocation` | motif de nom (schémas) | motif de nom (jetons : url, location) | schemas/ |
| `MicrosoftGraphActivityLogs.RequestUri` | motif de nom (schémas) | motif de nom (jetons : request, uri) | schemas/ |
| `OfficeActivity.DestinationRelativeUrl` | motif de nom (schémas) | motif de nom (jetons : destination, relative, url) | schemas/ |
| `OfficeActivity.Site_Url` | motif de nom (schémas) | motif de nom (jetons : site, url) | schemas/ |
| `OfficeActivity.Site_Url_` | motif de nom (schémas) | motif de nom (jetons : site, url) | schemas/ |
| `OfficeActivity.SourceRelativeUrl` | motif de nom (schémas) | motif de nom (jetons : source, relative, url) | schemas/ |
| `OfficeActivity.SourceRelativeUrl_` | motif de nom (schémas) | motif de nom (jetons : source, relative, url) | schemas/ |
| `SecurityIncident.IncidentUrl` | motif de nom (schémas) | motif de nom (jetons : incident, url) | schemas/ |
| `StorageBlobLogs.DestinationUri` | motif de nom (schémas) | motif de nom (jetons : destination, uri) | schemas/ |
| `StorageBlobLogs.SourceUri` | motif de nom (schémas) | motif de nom (jetons : source, uri) | schemas/ |
| `StorageBlobLogs.Uri` | motif de nom (schémas) | motif de nom (jetons : uri) | schemas/ |
| `Usage.ResourceUri` | motif de nom (schémas) | motif de nom (jetons : resource, uri) | schemas/ |

## domain (67)

| Table.Colonne | Niveau | Preuve | Source |
| --- | --- | --- | --- |
| `ASimDnsActivityLogs.AdditionalFields` | règle (comparaison faible/sous-chaîne) | AdditionalFields has … (ASimDnsActivityLogs) | rules/domain/DM-P4.yaml [DM-P4]; fragments/domain_hits.kql |
| `ASimDnsActivityLogs.DstHostname` | règle (comparaison faible/sous-chaîne) | DstHostname has … (ASimDnsActivityLogs) | fragments/domain_hits.kql |
| `ASimWebSessionLogs.DstHostname` | règle (comparaison faible/sous-chaîne) | DstHostname has … (ASimWebSessionLogs) | rules/domain/DM-P3.yaml [DM-P3]; fragments/domain_hits.kql |
| `AZFWApplicationRule.TargetUrl` | règle (comparaison faible/sous-chaîne) | TargetUrl has … (AZFWApplicationRule) | fragments/domain_hits.kql |
| `CommonSecurityLog.RequestURL` | règle (comparaison faible/sous-chaîne) | RequestURL has … (CommonSecurityLog) | rules/domain/DM-P3.yaml [DM-P3]; fragments/domain_hits.kql |
| `DeviceEvents.AdditionalFields` | règle (comparaison faible/sous-chaîne) | AdditionalFields has … (DeviceEvents) | rules/domain/DM-P4.yaml [DM-P4]; fragments/domain_hits.kql |
| `DeviceFileEvents.AdditionalFields` | règle (comparaison faible/sous-chaîne) | AdditionalFields has … (DeviceFileEvents) | fragments/domain_hits.kql |
| `DeviceNetworkEvents.AdditionalFields` | règle (comparaison faible/sous-chaîne) | AdditionalFields has … (DeviceNetworkEvents) | rules/domain/DM-P4.yaml [DM-P4]; fragments/domain_hits.kql |
| `DeviceProcessEvents.ProcessCommandLine` | règle (comparaison faible/sous-chaîne) | ProcessCommandLine has … (DeviceProcessEvents) | rules/domain/DM-P3.yaml [DM-P3]; rules/domain/DM-T1.yaml [DM-T1] |
| `EmailEvents.AdditionalFields` | règle (comparaison faible/sous-chaîne) | AdditionalFields has … (EmailEvents) | fragments/domain_hits.kql |
| `AlertEvidence.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `ASimAuthenticationEventLogs.DvcDomain` | motif de nom (schémas) | motif de nom (jetons : dvc, domain) | schemas/ |
| `ASimAuthenticationEventLogs.DvcFQDN` | motif de nom (schémas) | motif de nom (jetons : dvc, fqdn) | schemas/ |
| `ASimAuthenticationEventLogs.SrcDomain` | motif de nom (schémas) | motif de nom (jetons : src, domain) | schemas/ |
| `ASimAuthenticationEventLogs.SrcFQDN` | motif de nom (schémas) | motif de nom (jetons : src, fqdn) | schemas/ |
| `ASimAuthenticationEventLogs.TargetDomain` | motif de nom (schémas) | motif de nom (jetons : target, domain) | schemas/ |
| `ASimAuthenticationEventLogs.TargetFQDN` | motif de nom (schémas) | motif de nom (jetons : target, fqdn) | schemas/ |
| `ASimDnsActivityLogs.DstDomain` | motif de nom (schémas) | motif de nom (jetons : dst, domain) | schemas/ |
| `ASimDnsActivityLogs.DstFQDN` | motif de nom (schémas) | motif de nom (jetons : dst, fqdn) | schemas/ |
| `ASimDnsActivityLogs.DvcDomain` | motif de nom (schémas) | motif de nom (jetons : dvc, domain) | schemas/ |
| `ASimDnsActivityLogs.DvcFQDN` | motif de nom (schémas) | motif de nom (jetons : dvc, fqdn) | schemas/ |
| `ASimDnsActivityLogs.SrcDomain` | motif de nom (schémas) | motif de nom (jetons : src, domain) | schemas/ |
| `ASimDnsActivityLogs.SrcFQDN` | motif de nom (schémas) | motif de nom (jetons : src, fqdn) | schemas/ |
| `ASimFileEventLogs.DvcDomain` | motif de nom (schémas) | motif de nom (jetons : dvc, domain) | schemas/ |
| `ASimFileEventLogs.DvcFQDN` | motif de nom (schémas) | motif de nom (jetons : dvc, fqdn) | schemas/ |
| `ASimFileEventLogs.SrcDomain` | motif de nom (schémas) | motif de nom (jetons : src, domain) | schemas/ |
| `ASimFileEventLogs.SrcFQDN` | motif de nom (schémas) | motif de nom (jetons : src, fqdn) | schemas/ |
| `ASimNetworkSessionLogs.DstDomain` | motif de nom (schémas) | motif de nom (jetons : dst, domain) | schemas/ |
| `ASimNetworkSessionLogs.DstFQDN` | motif de nom (schémas) | motif de nom (jetons : dst, fqdn) | schemas/ |
| `ASimNetworkSessionLogs.DvcDomain` | motif de nom (schémas) | motif de nom (jetons : dvc, domain) | schemas/ |
| `ASimNetworkSessionLogs.DvcFQDN` | motif de nom (schémas) | motif de nom (jetons : dvc, fqdn) | schemas/ |
| `ASimNetworkSessionLogs.SrcDomain` | motif de nom (schémas) | motif de nom (jetons : src, domain) | schemas/ |
| `ASimNetworkSessionLogs.SrcFQDN` | motif de nom (schémas) | motif de nom (jetons : src, fqdn) | schemas/ |
| `ASimProcessEventLogs.DvcDomain` | motif de nom (schémas) | motif de nom (jetons : dvc, domain) | schemas/ |
| `ASimProcessEventLogs.DvcFQDN` | motif de nom (schémas) | motif de nom (jetons : dvc, fqdn) | schemas/ |
| `AzureDiagnostics.domain_s` | motif de nom (schémas) | motif de nom (jetons : domain) | schemas/ |
| `AzureDiagnostics.Fqdn_s` | motif de nom (schémas) | motif de nom (jetons : fqdn) | schemas/ |
| `CommonSecurityLog.DestinationNTDomain` | motif de nom (schémas) | motif de nom (jetons : destination, nt, domain) | schemas/ |
| `CommonSecurityLog.DeviceNtDomain` | motif de nom (schémas) | motif de nom (jetons : device, nt, domain) | schemas/ |
| `CommonSecurityLog.SourceNTDomain` | motif de nom (schémas) | motif de nom (jetons : source, nt, domain) | schemas/ |
| `DeviceEvents.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `DeviceEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `DeviceFileEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `DeviceFileEvents.RequestAccountDomain` | motif de nom (schémas) | motif de nom (jetons : request, account, domain) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `DeviceLogonEvents.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `DeviceProcessEvents.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessAccountDomain` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, domain) | schemas/ |
| `EmailEvents.RecipientDomain` | motif de nom (schémas) | motif de nom (jetons : recipient, domain) | schemas/ |
| `IdentityDirectoryEvents.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `IdentityInfo.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `IdentityLogonEvents.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `IdentityQueryEvents.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `MDCDetectionDNSEvents.Domain` | motif de nom (schémas) | motif de nom (jetons : domain) | schemas/ |
| `OfficeActivity.MachineDomainInfo` | motif de nom (schémas) | motif de nom (jetons : machine, domain, info) | schemas/ |
| `SecurityEvent.AccountDomain` | motif de nom (schémas) | motif de nom (jetons : account, domain) | schemas/ |
| `SecurityEvent.SubjectDomainName` | motif de nom (schémas) | motif de nom (jetons : subject, domain, name) | schemas/ |
| `SecurityEvent.TargetDomainName` | motif de nom (schémas) | motif de nom (jetons : target, domain, name) | schemas/ |
| `SecurityEvent.TargetOutboundDomainName` | motif de nom (schémas) | motif de nom (jetons : target, outbound, domain, name) | schemas/ |
| `ThreatIntelligenceIndicator.DomainName` | motif de nom (schémas) | motif de nom (jetons : domain, name) | schemas/ |
| `ThreatIntelligenceIndicator.EmailSourceDomain` | motif de nom (schémas) | motif de nom (jetons : email, source, domain) | schemas/ |
| `VMComputer.AzureFaultDomain` | motif de nom (schémas) | motif de nom (jetons : azure, fault, domain) | schemas/ |
| `VMComputer.AzureUpdateDomain` | motif de nom (schémas) | motif de nom (jetons : azure, update, domain) | schemas/ |
| `VMProcess.UserDomain` | motif de nom (schémas) | motif de nom (jetons : user, domain) | schemas/ |

## device (105)

| Table.Colonne | Niveau | Preuve | Source |
| --- | --- | --- | --- |
| `SecurityAlert.CompromisedEntity` | colonne polymorphe (écartée par audit) | Entité compromise d'une alerte : un nom d'hôte ou une IP selon l'alerte. Utilisée dans les deux sens par les règles — MC-S2 `CompromisedEntity has ValueShort` (device) et IP-P5 `CompromisedEntity == Value` (ip). | audit manuel (#31) |
| `SecurityAlert.Entities` | règle (comparaison faible/sous-chaîne) | Entities has … (SecurityAlert) | rules/device/MC-S2.yaml [MC-S2] |
| `Anomalies.SourceDevice` | motif de nom (schémas) | motif de nom (jetons : source, device) | schemas/ |
| `ASimAuthenticationEventLogs.SrcHostname` | motif de nom (schémas) | motif de nom (jetons : src, hostname) | schemas/ |
| `ASimDnsActivityLogs.DstHostname` | motif de nom (schémas) | motif de nom (jetons : dst, hostname) | schemas/ |
| `ASimDnsActivityLogs.DvcHostname` | motif de nom (schémas) | motif de nom (jetons : dvc, hostname) | schemas/ |
| `ASimDnsActivityLogs.SrcHostname` | motif de nom (schémas) | motif de nom (jetons : src, hostname) | schemas/ |
| `ASimFileEventLogs.SrcHostname` | motif de nom (schémas) | motif de nom (jetons : src, hostname) | schemas/ |
| `ASimNetworkSessionLogs.DstHostname` | motif de nom (schémas) | motif de nom (jetons : dst, hostname) | schemas/ |
| `ASimNetworkSessionLogs.DvcHostname` | motif de nom (schémas) | motif de nom (jetons : dvc, hostname) | schemas/ |
| `ASimNetworkSessionLogs.SrcHostname` | motif de nom (schémas) | motif de nom (jetons : src, hostname) | schemas/ |
| `ASimWebSessionLogs.DstHostname` | motif de nom (schémas) | motif de nom (jetons : dst, hostname) | schemas/ |
| `AVSSyslog.HostName` | motif de nom (schémas) | motif de nom (jetons : host, name) | schemas/ |
| `AzureDiagnostics.host_name_s` | motif de nom (schémas) | motif de nom (jetons : host, name) | schemas/ |
| `AzureDiagnostics.hostname_s` | motif de nom (schémas) | motif de nom (jetons : hostname) | schemas/ |
| `AzureDiagnostics.hostName_s` | motif de nom (schémas) | motif de nom (jetons : host, name) | schemas/ |
| `BehaviorAnalytics.DestinationDevice` | motif de nom (schémas) | motif de nom (jetons : destination, device) | schemas/ |
| `BehaviorAnalytics.Device` | motif de nom (schémas) | motif de nom (jetons : device) | schemas/ |
| `BehaviorAnalytics.SourceDevice` | motif de nom (schémas) | motif de nom (jetons : source, device) | schemas/ |
| `CommonSecurityLog.CollectorHostName` | motif de nom (schémas) | motif de nom (jetons : collector, host, name) | schemas/ |
| `CommonSecurityLog.DeviceAddress` | motif de nom (schémas) | motif de nom (jetons : device, address) | schemas/ |
| `CommonSecurityLog.DeviceEventCategory` | motif de nom (schémas) | motif de nom (jetons : device, event, category) | schemas/ |
| `CommonSecurityLog.DeviceEventClassID` | motif de nom (schémas) | motif de nom (jetons : device, event, class, id) | schemas/ |
| `CommonSecurityLog.DeviceExternalID` | motif de nom (schémas) | motif de nom (jetons : device, external, id) | schemas/ |
| `CommonSecurityLog.DeviceMacAddress` | motif de nom (schémas) | motif de nom (jetons : device, mac, address) | schemas/ |
| `CommonSecurityLog.DeviceNtDomain` | motif de nom (schémas) | motif de nom (jetons : device, nt, domain) | schemas/ |
| `CommonSecurityLog.DeviceTimeZone` | motif de nom (schémas) | motif de nom (jetons : device, time, zone) | schemas/ |
| `DeviceEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceEvents.MachineGroup` | motif de nom (schémas) | motif de nom (jetons : machine, group) | schemas/ |
| `DeviceEvents.ProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : process, remote, session, device, name) | schemas/ |
| `DeviceFileCertificateInfo.MachineGroup` | motif de nom (schémas) | motif de nom (jetons : machine, group) | schemas/ |
| `DeviceFileEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceFileEvents.MachineGroup` | motif de nom (schémas) | motif de nom (jetons : machine, group) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceImageLoadEvents.MachineGroup` | motif de nom (schémas) | motif de nom (jetons : machine, group) | schemas/ |
| `DeviceInfo.AadDeviceId` | motif de nom (schémas) | motif de nom (jetons : aad, device, id) | schemas/ |
| `DeviceInfo.DeviceCategory` | motif de nom (schémas) | motif de nom (jetons : device, category) | schemas/ |
| `DeviceInfo.DeviceDynamicTags` | motif de nom (schémas) | motif de nom (jetons : device, dynamic, tags) | schemas/ |
| `DeviceInfo.DeviceManualTags` | motif de nom (schémas) | motif de nom (jetons : device, manual, tags) | schemas/ |
| `DeviceInfo.DeviceSubtype` | motif de nom (schémas) | motif de nom (jetons : device, subtype) | schemas/ |
| `DeviceInfo.HostDeviceId` | motif de nom (schémas) | motif de nom (jetons : host, device, id) | schemas/ |
| `DeviceInfo.MachineGroup` | motif de nom (schémas) | motif de nom (jetons : machine, group) | schemas/ |
| `DeviceInfo.MergedDeviceIds` | motif de nom (schémas) | motif de nom (jetons : merged, device, ids) | schemas/ |
| `DeviceInfo.MergedToDeviceId` | motif de nom (schémas) | motif de nom (jetons : merged, to, device, id) | schemas/ |
| `DeviceInfo.RegistryDeviceTag` | motif de nom (schémas) | motif de nom (jetons : registry, device, tag) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceLogonEvents.MachineGroup` | motif de nom (schémas) | motif de nom (jetons : machine, group) | schemas/ |
| `DeviceLogonEvents.RemoteDeviceName` | motif de nom (schémas) | motif de nom (jetons : remote, device, name) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceNetworkEvents.MachineGroup` | motif de nom (schémas) | motif de nom (jetons : machine, group) | schemas/ |
| `DeviceNetworkInfo.MachineGroup` | motif de nom (schémas) | motif de nom (jetons : machine, group) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceProcessEvents.MachineGroup` | motif de nom (schémas) | motif de nom (jetons : machine, group) | schemas/ |
| `DeviceProcessEvents.ProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : process, remote, session, device, name) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceRegistryEvents.MachineGroup` | motif de nom (schémas) | motif de nom (jetons : machine, group) | schemas/ |
| `DnsEvents.Computer` | motif de nom (schémas) | motif de nom (jetons : computer) | schemas/ |
| `Heartbeat.ComputerEnvironment` | motif de nom (schémas) | motif de nom (jetons : computer, environment) | schemas/ |
| `Heartbeat.SourceComputerId` | motif de nom (schémas) | motif de nom (jetons : source, computer, id) | schemas/ |
| `InsightsMetrics.Computer` | motif de nom (schémas) | motif de nom (jetons : computer) | schemas/ |
| `McasShadowItReporting.MachineId` | motif de nom (schémas) | motif de nom (jetons : machine, id) | schemas/ |
| `McasShadowItReporting.MachineName` | motif de nom (schémas) | motif de nom (jetons : machine, name) | schemas/ |
| `OfficeActivity.DeviceInformation` | motif de nom (schémas) | motif de nom (jetons : device, information) | schemas/ |
| `OfficeActivity.IsManagedDevice` | motif de nom (schémas) | motif de nom (jetons : is, managed, device) | schemas/ |
| `OfficeActivity.MachineDomainInfo` | motif de nom (schémas) | motif de nom (jetons : machine, domain, info) | schemas/ |
| `OfficeActivity.MachineId` | motif de nom (schémas) | motif de nom (jetons : machine, id) | schemas/ |
| `Operation.Computer` | motif de nom (schémas) | motif de nom (jetons : computer) | schemas/ |
| `Operation.SourceComputerId` | motif de nom (schémas) | motif de nom (jetons : source, computer, id) | schemas/ |
| `ProtectionStatus.Computer` | motif de nom (schémas) | motif de nom (jetons : computer) | schemas/ |
| `ProtectionStatus.ComputerEnvironment` | motif de nom (schémas) | motif de nom (jetons : computer, environment) | schemas/ |
| `ProtectionStatus.ComputerIP_Hidden` | motif de nom (schémas) | motif de nom (jetons : computer, ip, hidden) | schemas/ |
| `ProtectionStatus.SourceComputerId` | motif de nom (schémas) | motif de nom (jetons : source, computer, id) | schemas/ |
| `SecurityBaseline.Computer` | motif de nom (schémas) | motif de nom (jetons : computer) | schemas/ |
| `SecurityBaseline.ComputerEnvironment` | motif de nom (schémas) | motif de nom (jetons : computer, environment) | schemas/ |
| `SecurityBaseline.SourceComputerId` | motif de nom (schémas) | motif de nom (jetons : source, computer, id) | schemas/ |
| `SecurityBaselineSummary.Computer` | motif de nom (schémas) | motif de nom (jetons : computer) | schemas/ |
| `SecurityBaselineSummary.ComputerEnvironment` | motif de nom (schémas) | motif de nom (jetons : computer, environment) | schemas/ |
| `SecurityBaselineSummary.SourceComputerId` | motif de nom (schémas) | motif de nom (jetons : source, computer, id) | schemas/ |
| `SecurityEvent.DeviceDescription` | motif de nom (schémas) | motif de nom (jetons : device, description) | schemas/ |
| `SecurityEvent.FullyQualifiedSubjectMachineName` | motif de nom (schémas) | motif de nom (jetons : fully, qualified, subject, machine, name) | schemas/ |
| `SecurityEvent.SourceComputerId` | motif de nom (schémas) | motif de nom (jetons : source, computer, id) | schemas/ |
| `SecurityEvent.SubjectMachineName` | motif de nom (schémas) | motif de nom (jetons : subject, machine, name) | schemas/ |
| `SecurityEvent.SubjectMachineSID` | motif de nom (schémas) | motif de nom (jetons : subject, machine, sid) | schemas/ |
| `Syslog.CollectorHostName` | motif de nom (schémas) | motif de nom (jetons : collector, host, name) | schemas/ |
| `Syslog.HostName` | motif de nom (schémas) | motif de nom (jetons : host, name) | schemas/ |
| `Update.Computer` | motif de nom (schémas) | motif de nom (jetons : computer) | schemas/ |
| `Update.ComputerEnvironment` | motif de nom (schémas) | motif de nom (jetons : computer, environment) | schemas/ |
| `Update.SourceComputerId` | motif de nom (schémas) | motif de nom (jetons : source, computer, id) | schemas/ |
| `UpdateSummary.Computer` | motif de nom (schémas) | motif de nom (jetons : computer) | schemas/ |
| `UpdateSummary.ComputerEnvironment` | motif de nom (schémas) | motif de nom (jetons : computer, environment) | schemas/ |
| `UpdateSummary.SourceComputerId` | motif de nom (schémas) | motif de nom (jetons : source, computer, id) | schemas/ |
| `Usage.Computer` | motif de nom (schémas) | motif de nom (jetons : computer) | schemas/ |
| `VMBoundPort.Computer` | motif de nom (schémas) | motif de nom (jetons : computer) | schemas/ |
| `VMBoundPort.Machine` | motif de nom (schémas) | motif de nom (jetons : machine) | schemas/ |
| `VMComputer.Computer` | motif de nom (schémas) | motif de nom (jetons : computer) | schemas/ |
| `VMComputer.HostName` | motif de nom (schémas) | motif de nom (jetons : host, name) | schemas/ |
| `VMComputer.Machine` | motif de nom (schémas) | motif de nom (jetons : machine) | schemas/ |
| `VMComputer.VirtualMachineHypervisorId` | motif de nom (schémas) | motif de nom (jetons : virtual, machine, hypervisor, id) | schemas/ |
| `VMComputer.VirtualMachineNativeId` | motif de nom (schémas) | motif de nom (jetons : virtual, machine, native, id) | schemas/ |
| `VMComputer.VirtualMachineNativeName` | motif de nom (schémas) | motif de nom (jetons : virtual, machine, native, name) | schemas/ |
| `VMComputer.VirtualMachineType` | motif de nom (schémas) | motif de nom (jetons : virtual, machine, type) | schemas/ |
| `VMConnection.Computer` | motif de nom (schémas) | motif de nom (jetons : computer) | schemas/ |
| `VMConnection.Machine` | motif de nom (schémas) | motif de nom (jetons : machine) | schemas/ |
| `VMProcess.Computer` | motif de nom (schémas) | motif de nom (jetons : computer) | schemas/ |
| `VMProcess.Machine` | motif de nom (schémas) | motif de nom (jetons : machine) | schemas/ |

## process (99)

| Table.Colonne | Niveau | Preuve | Source |
| --- | --- | --- | --- |
| `AlertEvidence.ProcessCommandLine` | motif de nom (schémas) | motif de nom (jetons : process, command, line) | schemas/ |
| `ASimDnsActivityLogs.SrcProcessName` | motif de nom (schémas) | motif de nom (jetons : src, process, name) | schemas/ |
| `ASimFileEventLogs.ActingProcessCommandLine` | motif de nom (schémas) | motif de nom (jetons : acting, process, command, line) | schemas/ |
| `ASimFileEventLogs.ActingProcessName` | motif de nom (schémas) | motif de nom (jetons : acting, process, name) | schemas/ |
| `ASimFileEventLogs.SrcFileName` | motif de nom (schémas) | motif de nom (jetons : src, file, name) | schemas/ |
| `ASimFileEventLogs.TargetFileName` | motif de nom (schémas) | motif de nom (jetons : target, file, name) | schemas/ |
| `ASimProcessEventLogs.ActingProcessCommandLine` | motif de nom (schémas) | motif de nom (jetons : acting, process, command, line) | schemas/ |
| `ASimProcessEventLogs.ActingProcessFileInternalName` | motif de nom (schémas) | motif de nom (jetons : acting, process, file, internal, name) | schemas/ |
| `ASimProcessEventLogs.ActingProcessFileOriginalName` | motif de nom (schémas) | motif de nom (jetons : acting, process, file, original, name) | schemas/ |
| `ASimProcessEventLogs.ParentProcessName` | motif de nom (schémas) | motif de nom (jetons : parent, process, name) | schemas/ |
| `ASimProcessEventLogs.TargetProcessCommandLine` | motif de nom (schémas) | motif de nom (jetons : target, process, command, line) | schemas/ |
| `ASimProcessEventLogs.TargetProcessFileInternalName` | motif de nom (schémas) | motif de nom (jetons : target, process, file, internal, name) | schemas/ |
| `ASimProcessEventLogs.TargetProcessFileOriginalName` | motif de nom (schémas) | motif de nom (jetons : target, process, file, original, name) | schemas/ |
| `AzureDiagnostics.AppImage_s` | motif de nom (schémas) | motif de nom (jetons : app, image) | schemas/ |
| `CommonSecurityLog.ProcessName` | motif de nom (schémas) | motif de nom (jetons : process, name) | schemas/ |
| `CommonSecurityLog.SourceProcessName` | motif de nom (schémas) | motif de nom (jetons : source, process, name) | schemas/ |
| `DeviceEvents.InitiatingProcessAccountName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, name) | schemas/ |
| `DeviceEvents.InitiatingProcessCommandLine` | motif de nom (schémas) | motif de nom (jetons : initiating, process, command, line) | schemas/ |
| `DeviceEvents.InitiatingProcessParentFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, parent, file, name) | schemas/ |
| `DeviceEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceEvents.InitiatingProcessVersionInfoCompanyName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, company, name) | schemas/ |
| `DeviceEvents.InitiatingProcessVersionInfoInternalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, internal, file, name) | schemas/ |
| `DeviceEvents.InitiatingProcessVersionInfoOriginalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, original, file, name) | schemas/ |
| `DeviceEvents.InitiatingProcessVersionInfoProductName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, product, name) | schemas/ |
| `DeviceEvents.ProcessCommandLine` | motif de nom (schémas) | motif de nom (jetons : process, command, line) | schemas/ |
| `DeviceEvents.ProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : process, remote, session, device, name) | schemas/ |
| `DeviceFileEvents.InitiatingProcessCommandLine` | motif de nom (schémas) | motif de nom (jetons : initiating, process, command, line) | schemas/ |
| `DeviceFileEvents.InitiatingProcessParentFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, parent, file, name) | schemas/ |
| `DeviceFileEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceFileEvents.InitiatingProcessVersionInfoCompanyName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, company, name) | schemas/ |
| `DeviceFileEvents.InitiatingProcessVersionInfoInternalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, internal, file, name) | schemas/ |
| `DeviceFileEvents.InitiatingProcessVersionInfoOriginalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, original, file, name) | schemas/ |
| `DeviceFileEvents.InitiatingProcessVersionInfoProductName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, product, name) | schemas/ |
| `DeviceFileEvents.PreviousFileName` | motif de nom (schémas) | motif de nom (jetons : previous, file, name) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessAccountName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, name) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessCommandLine` | motif de nom (schémas) | motif de nom (jetons : initiating, process, command, line) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, file, name) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessFolderPath` | motif de nom (schémas) | motif de nom (jetons : initiating, process, folder, path) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessParentFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, parent, file, name) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessVersionInfoCompanyName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, company, name) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessVersionInfoInternalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, internal, file, name) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessVersionInfoOriginalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, original, file, name) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessVersionInfoProductName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, product, name) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessAccountName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, name) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessCommandLine` | motif de nom (schémas) | motif de nom (jetons : initiating, process, command, line) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, file, name) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessFolderPath` | motif de nom (schémas) | motif de nom (jetons : initiating, process, folder, path) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessParentFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, parent, file, name) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessVersionInfoCompanyName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, company, name) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessVersionInfoInternalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, internal, file, name) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessVersionInfoOriginalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, original, file, name) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessVersionInfoProductName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, product, name) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessAccountName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, name) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessCommandLine` | motif de nom (schémas) | motif de nom (jetons : initiating, process, command, line) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessParentFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, parent, file, name) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessVersionInfoCompanyName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, company, name) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessVersionInfoInternalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, internal, file, name) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessVersionInfoOriginalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, original, file, name) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessVersionInfoProductName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, product, name) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessAccountName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, name) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessCommandLine` | motif de nom (schémas) | motif de nom (jetons : initiating, process, command, line) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessParentFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, parent, file, name) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessVersionInfoCompanyName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, company, name) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessVersionInfoInternalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, internal, file, name) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessVersionInfoOriginalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, original, file, name) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessVersionInfoProductName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, product, name) | schemas/ |
| `DeviceProcessEvents.ProcessCommandLine` | motif de nom (schémas) | motif de nom (jetons : process, command, line) | schemas/ |
| `DeviceProcessEvents.ProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : process, remote, session, device, name) | schemas/ |
| `DeviceProcessEvents.ProcessVersionInfoCompanyName` | motif de nom (schémas) | motif de nom (jetons : process, version, info, company, name) | schemas/ |
| `DeviceProcessEvents.ProcessVersionInfoInternalFileName` | motif de nom (schémas) | motif de nom (jetons : process, version, info, internal, file, name) | schemas/ |
| `DeviceProcessEvents.ProcessVersionInfoOriginalFileName` | motif de nom (schémas) | motif de nom (jetons : process, version, info, original, file, name) | schemas/ |
| `DeviceProcessEvents.ProcessVersionInfoProductName` | motif de nom (schémas) | motif de nom (jetons : process, version, info, product, name) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessAccountName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, account, name) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessCommandLine` | motif de nom (schémas) | motif de nom (jetons : initiating, process, command, line) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessParentFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, parent, file, name) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessRemoteSessionDeviceName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, remote, session, device, name) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessVersionInfoCompanyName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, company, name) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessVersionInfoInternalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, internal, file, name) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessVersionInfoOriginalFileName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, original, file, name) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessVersionInfoProductName` | motif de nom (schémas) | motif de nom (jetons : initiating, process, version, info, product, name) | schemas/ |
| `MDCDetectionDNSEvents.ImageName` | motif de nom (schémas) | motif de nom (jetons : image, name) | schemas/ |
| `OfficeActivity.ClientProcessName` | motif de nom (schémas) | motif de nom (jetons : client, process, name) | schemas/ |
| `OfficeActivity.DestinationFileName` | motif de nom (schémas) | motif de nom (jetons : destination, file, name) | schemas/ |
| `OfficeActivity.SourceFileName` | motif de nom (schémas) | motif de nom (jetons : source, file, name) | schemas/ |
| `OfficeActivity.SourceFileName_` | motif de nom (schémas) | motif de nom (jetons : source, file, name) | schemas/ |
| `SecurityEvent.CallerProcessName` | motif de nom (schémas) | motif de nom (jetons : caller, process, name) | schemas/ |
| `SecurityEvent.LogonProcessName` | motif de nom (schémas) | motif de nom (jetons : logon, process, name) | schemas/ |
| `SecurityEvent.NewProcessName` | motif de nom (schémas) | motif de nom (jetons : new, process, name) | schemas/ |
| `SecurityEvent.ParentProcessName` | motif de nom (schémas) | motif de nom (jetons : parent, process, name) | schemas/ |
| `SecurityEvent.ProcessName` | motif de nom (schémas) | motif de nom (jetons : process, name) | schemas/ |
| `SecurityEvent.ServiceFileName` | motif de nom (schémas) | motif de nom (jetons : service, file, name) | schemas/ |
| `Syslog.ProcessName` | motif de nom (schémas) | motif de nom (jetons : process, name) | schemas/ |
| `ThreatIntelligenceIndicator.FileMutexName` | motif de nom (schémas) | motif de nom (jetons : file, mutex, name) | schemas/ |
| `VMBoundPort.ProcessName` | motif de nom (schémas) | motif de nom (jetons : process, name) | schemas/ |
| `VMConnection.ProcessName` | motif de nom (schémas) | motif de nom (jetons : process, name) | schemas/ |

## application (38)

| Table.Colonne | Niveau | Preuve | Source |
| --- | --- | --- | --- |
| `AuditLogs.AdditionalDetails` | règle (comparaison faible/sous-chaîne) | AdditionalDetails has … (AuditLogs) | rules/application/AP-P1.yaml [AP-P1] |
| `CloudAppEvents.RawEventData` | règle (comparaison faible/sous-chaîne) | RawEventData has … (CloudAppEvents) | rules/application/AP-P1.yaml [AP-P1] |
| `AADGraphActivityLogs.AppId` | motif de nom (schémas) | motif de nom (jetons : app, id) | schemas/ |
| `AADNonInteractiveUserSignInLogs.AppDisplayName` | motif de nom (schémas) | motif de nom (jetons : app, display, name) | schemas/ |
| `AADNonInteractiveUserSignInLogs.AppId` | motif de nom (schémas) | motif de nom (jetons : app, id) | schemas/ |
| `ADFSSignInLogs.AppDisplayName` | motif de nom (schémas) | motif de nom (jetons : app, display, name) | schemas/ |
| `ADFSSignInLogs.AppId` | motif de nom (schémas) | motif de nom (jetons : app, id) | schemas/ |
| `ASimAuthenticationEventLogs.ActingAppId` | motif de nom (schémas) | motif de nom (jetons : acting, app, id) | schemas/ |
| `ASimAuthenticationEventLogs.ActingAppName` | motif de nom (schémas) | motif de nom (jetons : acting, app, name) | schemas/ |
| `ASimAuthenticationEventLogs.TargetAppId` | motif de nom (schémas) | motif de nom (jetons : target, app, id) | schemas/ |
| `ASimAuthenticationEventLogs.TargetAppName` | motif de nom (schémas) | motif de nom (jetons : target, app, name) | schemas/ |
| `ASimFileEventLogs.TargetAppId` | motif de nom (schémas) | motif de nom (jetons : target, app, id) | schemas/ |
| `ASimFileEventLogs.TargetAppName` | motif de nom (schémas) | motif de nom (jetons : target, app, name) | schemas/ |
| `ASimNetworkSessionLogs.DstAppId` | motif de nom (schémas) | motif de nom (jetons : dst, app, id) | schemas/ |
| `ASimNetworkSessionLogs.DstAppName` | motif de nom (schémas) | motif de nom (jetons : dst, app, name) | schemas/ |
| `ASimNetworkSessionLogs.SrcAppId` | motif de nom (schémas) | motif de nom (jetons : src, app, id) | schemas/ |
| `ASimNetworkSessionLogs.SrcAppName` | motif de nom (schémas) | motif de nom (jetons : src, app, name) | schemas/ |
| `AVSSyslog.AppName` | motif de nom (schémas) | motif de nom (jetons : app, name) | schemas/ |
| `AzureDiagnostics.application_name_s` | motif de nom (schémas) | motif de nom (jetons : application, name) | schemas/ |
| `CloudAppEvents.ApplicationId` | motif de nom (schémas) | motif de nom (jetons : application, id) | schemas/ |
| `CloudAppEvents.OAuthAppId` | motif de nom (schémas) | motif de nom (jetons : o, auth, app, id) | schemas/ |
| `DeviceEvents.AppGuardContainerId` | motif de nom (schémas) | motif de nom (jetons : app, guard, container, id) | schemas/ |
| `DeviceFileEvents.AppGuardContainerId` | motif de nom (schémas) | motif de nom (jetons : app, guard, container, id) | schemas/ |
| `DeviceLogonEvents.AppGuardContainerId` | motif de nom (schémas) | motif de nom (jetons : app, guard, container, id) | schemas/ |
| `DeviceNetworkEvents.AppGuardContainerId` | motif de nom (schémas) | motif de nom (jetons : app, guard, container, id) | schemas/ |
| `DeviceProcessEvents.AppGuardContainerId` | motif de nom (schémas) | motif de nom (jetons : app, guard, container, id) | schemas/ |
| `McasShadowItReporting.AppId` | motif de nom (schémas) | motif de nom (jetons : app, id) | schemas/ |
| `McasShadowItReporting.AppName` | motif de nom (schémas) | motif de nom (jetons : app, name) | schemas/ |
| `MicrosoftServicePrincipalSignInLogs.AppId` | motif de nom (schémas) | motif de nom (jetons : app, id) | schemas/ |
| `OfficeActivity.AppId` | motif de nom (schémas) | motif de nom (jetons : app, id) | schemas/ |
| `OfficeActivity.ApplicationId` | motif de nom (schémas) | motif de nom (jetons : application, id) | schemas/ |
| `OfficeActivity.AppPoolName` | motif de nom (schémas) | motif de nom (jetons : app, pool, name) | schemas/ |
| `OfficeActivity.AzureADAppId` | motif de nom (schémas) | motif de nom (jetons : azure, ad, app, id) | schemas/ |
| `OfficeActivity.ClientAppId` | motif de nom (schémas) | motif de nom (jetons : client, app, id) | schemas/ |
| `SigninLogs.AppDisplayName` | motif de nom (schémas) | motif de nom (jetons : app, display, name) | schemas/ |
| `SigninLogs.AppId` | motif de nom (schémas) | motif de nom (jetons : app, id) | schemas/ |
| `StorageBlobLogs.RequesterAppId` | motif de nom (schémas) | motif de nom (jetons : requester, app, id) | schemas/ |
| `UrlClickEvents.AppName` | motif de nom (schémas) | motif de nom (jetons : app, name) | schemas/ |

## hash (40)

| Table.Colonne | Niveau | Preuve | Source |
| --- | --- | --- | --- |
| `ASimFileEventLogs.HashType` | motif de nom (schémas) | motif de nom (jetons : hash, type) | schemas/ |
| `ASimFileEventLogs.SrcFileMD5` | motif de nom (schémas) | motif de nom (jetons : src, file, md, 5) | schemas/ |
| `ASimFileEventLogs.SrcFileSHA1` | motif de nom (schémas) | motif de nom (jetons : src, file, sha, 1) | schemas/ |
| `ASimFileEventLogs.SrcFileSHA256` | motif de nom (schémas) | motif de nom (jetons : src, file, sha, 256) | schemas/ |
| `ASimFileEventLogs.SrcFileSHA512` | motif de nom (schémas) | motif de nom (jetons : src, file, sha, 512) | schemas/ |
| `ASimFileEventLogs.TargetFileSHA512` | motif de nom (schémas) | motif de nom (jetons : target, file, sha, 512) | schemas/ |
| `ASimProcessEventLogs.ActingProcessMD5` | motif de nom (schémas) | motif de nom (jetons : acting, process, md, 5) | schemas/ |
| `ASimProcessEventLogs.ActingProcessSHA1` | motif de nom (schémas) | motif de nom (jetons : acting, process, sha, 1) | schemas/ |
| `ASimProcessEventLogs.ActingProcessSHA256` | motif de nom (schémas) | motif de nom (jetons : acting, process, sha, 256) | schemas/ |
| `ASimProcessEventLogs.ActingProcessSHA512` | motif de nom (schémas) | motif de nom (jetons : acting, process, sha, 512) | schemas/ |
| `ASimProcessEventLogs.ParentProcessMD5` | motif de nom (schémas) | motif de nom (jetons : parent, process, md, 5) | schemas/ |
| `ASimProcessEventLogs.ParentProcessSHA1` | motif de nom (schémas) | motif de nom (jetons : parent, process, sha, 1) | schemas/ |
| `ASimProcessEventLogs.ParentProcessSHA256` | motif de nom (schémas) | motif de nom (jetons : parent, process, sha, 256) | schemas/ |
| `ASimProcessEventLogs.ParentProcessSHA512` | motif de nom (schémas) | motif de nom (jetons : parent, process, sha, 512) | schemas/ |
| `ASimProcessEventLogs.TargetProcessSHA512` | motif de nom (schémas) | motif de nom (jetons : target, process, sha, 512) | schemas/ |
| `AzureDiagnostics.query_hash_s` | motif de nom (schémas) | motif de nom (jetons : query, hash) | schemas/ |
| `AzureDiagnostics.query_plan_hash_s` | motif de nom (schémas) | motif de nom (jetons : query, plan, hash) | schemas/ |
| `AzureDiagnostics.statement_key_hash_s` | motif de nom (schémas) | motif de nom (jetons : statement, key, hash) | schemas/ |
| `DeviceEvents.InitiatingProcessMD5` | motif de nom (schémas) | motif de nom (jetons : initiating, process, md, 5) | schemas/ |
| `DeviceEvents.InitiatingProcessSHA1` | motif de nom (schémas) | motif de nom (jetons : initiating, process, sha, 1) | schemas/ |
| `DeviceFileCertificateInfo.IssuerHash` | motif de nom (schémas) | motif de nom (jetons : issuer, hash) | schemas/ |
| `DeviceFileCertificateInfo.SignerHash` | motif de nom (schémas) | motif de nom (jetons : signer, hash) | schemas/ |
| `DeviceFileEvents.InitiatingProcessMD5` | motif de nom (schémas) | motif de nom (jetons : initiating, process, md, 5) | schemas/ |
| `DeviceFileEvents.InitiatingProcessSHA1` | motif de nom (schémas) | motif de nom (jetons : initiating, process, sha, 1) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessMD5` | motif de nom (schémas) | motif de nom (jetons : initiating, process, md, 5) | schemas/ |
| `DeviceImageLoadEvents.InitiatingProcessSHA1` | motif de nom (schémas) | motif de nom (jetons : initiating, process, sha, 1) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessMD5` | motif de nom (schémas) | motif de nom (jetons : initiating, process, md, 5) | schemas/ |
| `DeviceLogonEvents.InitiatingProcessSHA1` | motif de nom (schémas) | motif de nom (jetons : initiating, process, sha, 1) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessMD5` | motif de nom (schémas) | motif de nom (jetons : initiating, process, md, 5) | schemas/ |
| `DeviceNetworkEvents.InitiatingProcessSHA1` | motif de nom (schémas) | motif de nom (jetons : initiating, process, sha, 1) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessMD5` | motif de nom (schémas) | motif de nom (jetons : initiating, process, md, 5) | schemas/ |
| `DeviceProcessEvents.InitiatingProcessSHA1` | motif de nom (schémas) | motif de nom (jetons : initiating, process, sha, 1) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessMD5` | motif de nom (schémas) | motif de nom (jetons : initiating, process, md, 5) | schemas/ |
| `DeviceRegistryEvents.InitiatingProcessSHA1` | motif de nom (schémas) | motif de nom (jetons : initiating, process, sha, 1) | schemas/ |
| `SecurityEvent.FileHash` | motif de nom (schémas) | motif de nom (jetons : file, hash) | schemas/ |
| `StorageBlobLogs.AuthenticationHash` | motif de nom (schémas) | motif de nom (jetons : authentication, hash) | schemas/ |
| `StorageBlobLogs.RequestMd5` | motif de nom (schémas) | motif de nom (jetons : request, md5) | schemas/ |
| `StorageBlobLogs.ResponseMd5` | motif de nom (schémas) | motif de nom (jetons : response, md5) | schemas/ |
| `ThreatIntelligenceIndicator.FileHashType` | motif de nom (schémas) | motif de nom (jetons : file, hash, type) | schemas/ |
| `ThreatIntelligenceIndicator.FileHashValue` | motif de nom (schémas) | motif de nom (jetons : file, hash, value) | schemas/ |

## Arbitrage account/email (publié dans les DEUX types)

Décision du 22/10 : les colonnes `*Upn`, `UserPrincipalName`, `AccountName`, `UserId` confiantes pour `email` sont **account d'abord, puis email** — publiées dans les deux `locations.yml` au lieu d'être écartées des deux. L'ordre de présélection est porté par `INDICATOR_PRIORITY` côté userscript (à revoir en 3a). Les colonnes de la même famille confiantes pour `account` **seulement** ne sont volontairement pas promues en `email` (`StorageBlobLogs.AccountName` est un compte de stockage, `SigninLogs.UserId` un GUID).

| Table.Colonne | Types confiants d'origine | Détail |
| --- | --- | --- |
| `AADNonInteractiveUserSignInLogs.UserPrincipalName` | account | account: UserPrincipalName =~ … (AADNonInteractiveUserSignInLogs) / UserPrincipalName =~ … (AADNonInteractiveUserSignInLogs) / motif de nom (jetons : user, principal, name) |
| `AlertEvidence.AccountUpn` | account | account: Entity Defender : colonne AccountUpn / motif de nom (jetons : account, upn) |
| `DeviceNetworkEvents.InitiatingProcessAccountUpn` | email | email: InitiatingProcessAccountUpn =~ … (DeviceNetworkEvents) |
| `DeviceProcessEvents.AccountUpn` | email, account | email: AccountUpn =~ … (DeviceProcessEvents) — account: Entity Defender : colonne AccountUpn / motif de nom (jetons : account, upn) |
| `IdentityDirectoryEvents.AccountUpn` | account | account: Entity Defender : colonne AccountUpn / motif de nom (jetons : account, upn) |
| `IdentityLogonEvents.AccountUpn` | account | account: AccountUpn =~ … (IdentityLogonEvents) / AccountUpn =~ … (IdentityLogonEvents) / AccountUpn =~ … (IdentityLogonEvents) / AccountUpn =~ … (IdentityLogonEvents) / Entity Defender : colonne AccountUpn / motif de nom (jetons : account, upn) |
| `IdentityQueryEvents.AccountUpn` | account | account: Entity Defender : colonne AccountUpn / motif de nom (jetons : account, upn) |
| `OfficeActivity.UserId` | account, email | account: UserId =~ … (OfficeActivity) / UserId =~ … (OfficeActivity) / UserId =~ … (OfficeActivity) / UserId =~ … (OfficeActivity) — email: UserId =~ … (OfficeActivity) |
| `SigninLogs.UserPrincipalName` | account | account: UserPrincipalName =~ … (SigninLogs) / UserPrincipalName =~ … (SigninLogs) / motif de nom (jetons : user, principal, name) |
| `UrlClickEvents.AccountUpn` | account, email | account: AccountUpn =~ … (UrlClickEvents) / AccountUpn =~ … (UrlClickEvents) / Entity Defender : colonne AccountUpn / motif de nom (jetons : account, upn) — email: AccountUpn =~ … (UrlClickEvents) / AccountUpn =~ … (UrlClickEvents) |
