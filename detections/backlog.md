# Detection backlog

Every planned detection for the `cyberhawks.lab` range, by category. See
the [README](../README.md) for what "status" means here — `ready` is a
design status, not an implementation status.

Log sources assume the add-ons documented in `defense-tooling`'s
`docs/add-ons.md`.

## Implemented

Detections that have graduated out of this backlog — real SPL, run and
verified against the live range, per the README's "Contributing a
detection" process. Each has its own YAML file under `detections/<category>/`
(the actual source of truth — full SPL, false-positive notes, verification
details), compiled into `app/default/savedsearches.conf`. Removed from their
category table below.

| Detection | Verified | YAML | Notes |
|---|---|---|---|
| Ping Sweep | 2026-09-27 | [reconnaissance/ping_sweep.yml](reconnaissance/ping_sweep.yml) | Live `nmap -sn` sweep from john-kali against all 7 range hosts, fired exactly once, no false positives over 1h |
| Port Scan | 2026-09-27 | [reconnaissance/port_scan.yml](reconnaissance/port_scan.yml) | Live `nmap -p 445` sweep + `nmap -p 1-1000` single-host scan from john-kali, each fired exactly once; needed scoping to the range subnet + an NTP exclusion to kill false positives |
| Relayed SMB or LDAP connection | 2026-09-27 | [ntlm/ntlm_authentication.yml](ntlm/ntlm_authentication.yml) | Named "NTLM Authentication" per the Alert Embed Planner — detects any anomalous-source NTLM auth, not just completed relays. Live Responder+ntlmrelayx relay (HTTP trigger -> LDAP on dc1) from the `test` box, plus a direct netexec SMB auth from john-kali; baseline NTLM frequency investigated first (zero in 3h+ of idle range operation) — needed an exclusion for this control host's own admin traffic (NAT'd to the gateway IP, 10.0.2.1) |
| Attacker-added DNS record | 2026-09-27 | [ntlm/dns_record_creation.yml](ntlm/dns_record_creation.yml) | Named "DNS Record Creation". Required a bigger infra fix than expected: "Directory Service Changes" auditing alone doesn't produce any 5136/5137 events without an object-level SACL, and the only existing SACL (on the Default Domain Policy GPO, for ACL/DACL Modification) doesn't cascade — added a new SACL scoped to the DNS zone partition object. **This same root cause likely blocks RBCD Configuration, Shadow Credential Creation, and ScriptPath Attribute Tampering too** — each needs its own object SACL, don't assume any of them already work. Live `dnstool.py` record creation from john-kali, fired exactly once. **Documented gap:** the planner's `ip` field isn't obtainable — Windows logs the DNS record's actual value as opaque `<Binary>`; also no source IP exists on this event type at all, `user` is the only attribution available |
| `xp_cmdshell` execution | 2026-09-27 | [sql-server/xp_cmdshell_execution.yml](sql-server/xp_cmdshell_execution.yml) | Live `EXECUTE AS LOGIN='sa'` + `sp_configure`-enabled `xp_cmdshell` on sql1 as dsmith, real command output confirmed, fired exactly once. Hit a real operational issue mid-session (not a design flaw): repeated `splunk restart`s reset DB Connect's checkpoints, forcing a re-scan of accumulated XE trace files that then timed out indefinitely — fixed by clearing the old `.xel` files and restarting the XE session |
| `xp_dirtree` execution | 2026-09-27 | [sql-server/xp_dirtree_execution.yml](sql-server/xp_dirtree_execution.yml) | Same escalation chain and same XE data source as xp_cmdshell. Live directory enumeration on sql1, fired exactly once |
| `EXECUTE AS` impersonation | 2026-09-27 | [sql-server/execute_as_impersonation.yml](sql-server/execute_as_impersonation.yml) | The actual escalation step the other 3 SQL Server detections chain off of. Needed a filter for SQL Agent's own internal `sa`-context-switch noise (action_id=IMP with no statement text) — required a literal `EXECUTE AS` statement to be present. Live `dsmith` -> `sa` impersonation, fired exactly once per test, correctly deduplicated per-minute |
| Linked server command execution | 2026-09-27 | [sql-server/linked_server_execution.yml](sql-server/linked_server_execution.yml) | Live `OPENQUERY` pivot from sql1 to sql2 as `sa`, fired exactly once, `linked` correctly extracted as `sql2` |
| Coercion trigger (PetitPotam / DFSCoerce / ShadowCoerce / PrinterBug) | 2026-09-27 | [ntlm/forced_authentication.yml](ntlm/forced_authentication.yml) | Named "Forced Authentication". Sysmon pipe events and Zeek's dce_rpc.log both confirmed dead ends (see git history for the full investigation) — the working signal is the coerced DC's own resulting outbound SMB connection via Zeek conn.log. Getting this to fire for a same-subnet listener required a real, significant infra fix: cyber-range's mirroring only ever covered pfSense's own per-vnet tap, never same-vnet host-to-host traffic — fixed with a new `defense-tooling` script, `mirror-vnet-guests.sh`, mirroring every guest's own tap on the `ad` vnet. This same fix also unblocked Name Resolution Poisoning below |
| Name resolution poisoning (LLMNR / NBT-NS / mDNS) | 2026-09-27 | [reconnaissance/name_resolution_poisoning.yml](reconnaissance/name_resolution_poisoning.yml) | Unblocked by the same vnet-mirroring fix as Coercion trigger above. Live Responder poisoning round now fully visible in Zeek conn.log (broadcast queries, poisoned unicast answers, both IPv4 and IPv6), fired correctly. **Documented gap:** Zeek's DNS analyzer still doesn't decode LLMNR/mDNS content even with the traffic now reaching it, so `name`/`ip` fields aren't obtainable — `host`/`target` (which two hosts were involved) is what's available |
| SAM hive dumping | 2026-09-27 | Split into two: [credential-dumping/sam_lsa_dump_registry_export.yml](credential-dumping/sam_lsa_dump_registry_export.yml) (as "SAM/LSA Dump: Registry Export") and [credential-dumping/sam_dump_registry_query.yml](credential-dumping/sam_dump_registry_query.yml) (as "SAM Dump: Registry Query") | Two independent local dumping techniques, each with different telemetry. `reg save` (export) needed a 3-part infra fix (Sensitive Privilege Use auditing + FullPrivilegeAuditing LSA value + a forwarder whitelist gap for 4673/4674) and still can't name which hive was read — merged with LSA into one alert. Direct registry query (as SYSTEM) worked as originally designed and correctly names the hive, so it stays a separate alert per hive. Live-tested both ways on workstation with Defender real-time monitoring disabled. |
| LSA hive dumping (incl. LSA secrets) | 2026-09-27 | See SAM hive dumping row above — same split applies (Registry Export merged with SAM; [credential-dumping/lsa_dump_registry_query.yml](credential-dumping/lsa_dump_registry_query.yml) as "LSA Dump: Registry Query" for the distinguishable technique) | — |
| DPAPI masterkey / credential file theft | 2026-09-27 | [credential-dumping/dpapi_dump.yml](credential-dumping/dpapi_dump.yml) | Live masterkey + credential-blob file reads on workstation, fired exactly once, no false positives over 4h — worked as originally designed |
| NETLOGON script creds | 2026-09-27 | [credential-exposure/netlogon_share_read.yml](credential-exposure/netlogon_share_read.yml) | Named "NETLOGON Share Read" per the Alert Embed Planner. Needed a real infra fix: "Detailed File Share" auditing (needed for 5145) was not enabled anywhere in the range despite 5145 already being in the forwarder whitelist — fixed in cyber-range's `detection_logging` role, applied live to dc1/dc2/sql1. Live `smbclient` retrieval of skumar's leaked-cred NETLOGON script, fired exactly once |
| GPP cpassword (SYSVOL) | 2026-09-27 | [credential-exposure/sysvol_share_read.yml](credential-exposure/sysvol_share_read.yml) | Named "SYSVOL Share Read". Same infra fix as above. Live `smbclient` retrieval of the GPP `Groups.xml`, fired exactly once. This GPO is genuinely linked to the Workstations OU, so real GPP client refresh traffic exists as machine-account ($) noise — excluded, and confirmed not just theoretical (this session's own `Get-GPOReport` diagnostic calls incidentally touched the same file) |
| File share dump | 2026-09-27 | [credential-exposure/smb_share_dump.yml](credential-exposure/smb_share_dump.yml) | Named "SMB Share Dump". Same infra fix as above. Live `smbclient` retrieval of the leaked-cred file on sql1's Shared share, fired exactly once, no threshold needed |
| ASREPRoast | 2026-09-27 | [weak-auth/asreproast.yml](weak-auth/asreproast.yml) | Named "AS-REP Roast" per the Alert Embed Planner. Live `impacket-GetNPUsers` against asmith (the range's dedicated no-preauth account) from john-kali, fired exactly once (2 4768s 11ms apart merged by a 1m bucket); worked as originally designed, no infra fix needed — confirmed zero Pre-Authentication-Type=0 events in 24h of background traffic beforehand |
| Kerberoast | 2026-09-27 | [weak-auth/kerberoast.yml](weak-auth/kerberoast.yml) | Live `impacket-GetUserSPNs` against both real user-SPN accounts (crackme, svc-mssql) using asmith's cracked password, fired exactly once. Needed a real fix mid-design: filtering by the *requesting* account (`NOT Account_Name="*$@*"`) still false-positived on a human admin's normal logon triggering machine-account service tickets — switched to filtering by the *target* Service_Name (`NOT Service_Name="*$"`) instead, since machine accounts requesting tickets to each other is the actual baseline noise pattern, not who's asking |
| Zone transfer (AXFR) | 2026-09-27 | [weak-auth/zone_transfer.yml](weak-auth/zone_transfer.yml) | Live `dig axfr cyberhawks.lab @10.0.2.2` (dc1's real IP — a prior memory snapshot had this wrong as 10.0.2.4), full unauthenticated zone dump retrieved, fired exactly once, worked as originally designed |
| Password spray / guessable password | 2026-09-27 | [weak-auth/password_spray.yml](weak-auth/password_spray.yml) | Live `netexec smb` (NTLM vector) and `kerbrute passwordspray` (Kerberos vector), both against a 20-name wordlist with the real weak-cred pool password `Summer2026`, each fired exactly once. Needed an exclusion for netexec's own ANONYMOUS LOGON null-session probe. **Documented, not fixed:** asmith (the no-preauth account) always shows as a false "success" for any Kerberos-vector spray that includes it, since a no-preauth account's AS-REQ always looks successful regardless of the guessed password |
| Pre-2000 / blank password | 2026-09-27 | [weak-auth/computer_password_spray.yml](weak-auth/computer_password_spray.yml) | Named "Computer Password Spray" per the Alert Embed Planner. Live `impacket-getTGT` against computer4 (pre-2k default password) and `netexec smb` against computer5 (blank password), fired exactly once. No threshold needed — computer4/computer5 are placeholder AD objects with no real host, so any successful auth at all is the signal |
| NetNTLMv1 permitted | 2026-09-27 | [weak-auth/netntlmv1_authentication.yml](weak-auth/netntlmv1_authentication.yml) | Live `smbclient` with NTLMv2 disabled client-side, forcing a real NTLMv1 auth to dc1, fired exactly once. Needed real exclusions: NTLMv1 turned out to be common baseline noise in this range (routine dc2$-to-dc1 inter-DC traffic and anonymous/null-session logons both use it, a side effect of the domain-wide `LmCompatibilityLevel=1` weakening) — scoped to named non-machine accounts only |
| Anonymous logon / null session | 2026-09-27 | [weak-auth/smb_anonymous_object_enumeration.yml](weak-auth/smb_anonymous_object_enumeration.yml) | Named "SMB Anonymous Object Enumeration" per the Alert Embed Planner. Live `netexec --users` and `impacket-samrdump` (zero credentials), both fired. **Design deviation from the original backlog wording, verified not just assumed:** MS-LSAT `LsarLookupSids` returns STATUS_ACCESS_DENIED anonymously in this range (confirmed via `impacket-lookupsid`) even though MS-SAMR's enumeration calls work anonymously with no restriction — scoped to the SAMR calls that are actually reachable, dropped the LSA leg |
| Rogue machine account creation | 2026-09-27 | [ad-persistence/machine_account_creation.yml](ad-persistence/machine_account_creation.yml) | Named "Machine Account Creation". No infra fix needed — 4741 auditing was already on and forwarded. Live `impacket-addcomputer` from john-kali as a plain domain user (dsmith), relying only on the default MachineAccountQuota, fired exactly once. **Documented gap:** 4741 carries no source IP field, same as DNS Record Creation |
| New Domain Admin / privileged group membership change | 2026-09-27 | [ad-persistence/privileged_group_membership.yml](ad-persistence/privileged_group_membership.yml) | Named "Privileged Group Membership". Required a real infra fix: 4728/4732/4756 ("add member") were already forwarded, but their removal counterparts 4729/4733/4757 were not in defense-tooling's Security-channel whitelist — confirmed the removal event genuinely fires locally on dc1 (via `Get-WinEvent`) but was silently dropped at the forwarder stage. Fixed in `monitor.yml`, applied live to dc1/dc2. Live add+remove of skumar to/from Domain Admins via WinRM, both directions fired exactly once after the fix. **Documented gap:** no source IP field, same pattern |
| DCSync | 2026-09-27 | [credential-dumping/dcsync.yml](credential-dumping/dcsync.yml) | Named "Domain Replication (DCSync)". No infra fix needed. Found and worked around a real Splunk field-extraction quirk instead: 4662's raw text renders "Subject :" with a space, breaking the standard Account_Name extraction — used `rex` against `_raw` directly. Live `impacket-secretsdump -just-dc-user krbtgt` as the range's DCSync-privileged "user" account, fired exactly once, correctly excluding DC1$'s simultaneous legitimate replication. **Scoping decision:** skipped the originally-planned conn.log IP correlation — DRSUAPI arrives over the RPC endpoint mapper (TCP/135), too high-volume/generic to reliably attribute |
| Pass-the-ticket / ticket reuse | 2026-09-27 | [credential-dumping/pass_the_ticket.yml](credential-dumping/pass_the_ticket.yml) | Named "Pass-the-Ticket". Detects a TGS-REQ from an IP that never itself issued the corresponding AS-REQ for that client principal. **Real infra finding, not fixed:** any guest-to-guest traffic on the `ad` vnet shows as `conn_state=OTH`/undetected protocol in Zeek (confirmed via workstation's own routine DC traffic, not just the test technique) — likely the per-guest vnet-mirroring fix double-capturing same-vnet flows and corrupting protocol-analyzer stream reassembly (conn.log's own metadata is unaffected, only deep decode). Worked around by testing from two IPs on john-kali (cross-vnet, single capture point) instead of the `test` box. **Flagged for a dedicated defense-tooling/cyber-range investigation** before any future detection needs Zeek-decoded content for host-to-host range traffic specifically |
| WinRM logon | 2026-09-27 | [lateral-movement/winrm_logon.yml](lateral-movement/winrm_logon.yml) | Named "Lateral Movement: WinRM". No infra fix needed. Live `evil-winrm` session from john-kali to workstation, fired exactly once, correctly attributing the real client IP embedded in the WinRM Operational log's EventCode 91 message text (not auto-extracted by Splunk) |
| LDAP query content | 2026-09-27 | [enumeration/ldap_query.yml](enumeration/ldap_query.yml) | Named "LDAP Query". Required two real infra fixes: (1) the domain-root LDAP-query-logging registry thresholds were already 0 but NTDS had never been restarted to pick them up — `net stop/start ntds` on dc1 fixed it; (2) Zeek's `ldap.log` had no field extraction configured at all (deliberately deferred in an earlier session pending a real header) — read the real header live and added it. Live LDAP query fired correctly, correlated by source port to the DC's own 1644 log for the real filter/bind account. **Verified real gap, not a bug:** LDAPS produces zero 1644 events even after the NTDS fix, so `user`/`query` are empty for that protocol — matches the original design's own expectation that Zeek can't decrypt LDAPS content. **ADWS not yet implemented** in this alert (no easy way to live-test it from the Linux attacker boxes this session) |

## Zeek logs actually needed

`defense-tooling`'s Zeek sensor forwards logs to Splunk on an **explicit
allowlist**, not everything Zeek produces — see that repo's
`splunk_uf_log_names` variable. This is the canonical list of which Zeek
logs the detections below actually depend on; keep it in sync here whenever
a detection's log source changes.

| Log | Used by |
|---|---|
| `conn.log` | Network scanning, DCSync (IP), ADCS RPC/ICPR (IP), pass-the-ticket correlation |
| `dns.log` | Zone transfer, name resolution poisoning (LLMNR/mDNS portion) |
| `dce_rpc.log` | SAM/LSA remote enumeration |
| `kerberos.log` | Pass-the-ticket / ticket reuse |
| `ldap.log` | LDAP enumeration alerting (source-IP flagging, correlated back to Windows 1644) |

If you add a detection here that needs a Zeek log not in this table, add it
to the table **and** update `splunk_uf_log_names` in `defense-tooling` (both
the role default and `group_vars/all.yml.example`) — otherwise the data
simply won't arrive in Splunk.

---

## Reconnaissance & discovery

All detections in this category have graduated — see the "Implemented"
section above.

## Credential exposure

> Description-field password lives under **Enumeration** below — it's an LDAP read, not a file share.

All 3 detections in this category have graduated — see the "Implemented"
section above.

## Weak / missing authentication

All 7 detections in this category have graduated — see the "Implemented"
section above.

## NTLM relay & coercion

All detections in this category have graduated — see the "Implemented"
section above.

## SQL Server

All 4 detections in this category have graduated — see the "Implemented"
section above. (The SQL Server Audit/Extended Events source this category
needed was wired up by `defense-tooling` in an earlier session; see that
repo's CLAUDE.md, "IIS, SQL Server, and CA ingestion".)

## Web application

> These two used to be one row ("Portal DB readable / weak admin password").
> Splitting them because they're independently exploitable: a leaked
> credential in a stray backup file, and a separate DB permission
> misconfiguration. "Weak admin password" isn't its own row — see the note
> below the table for why.

| Detection | Log source | Status |
|---|---|---|
| `Web.config.bak` credential leak | App / IIS log — `Web.config` is deployed alongside a byte-identical `Web.config.bak` on `web` (left behind from a manual edit, per this range's design), and IIS's static-content handler was given a MIME-type mapping for `.bak` so it actually serves the file instead of 404ing. Alert on any HTTP GET of `Web.config.bak` (or any `.bak`/config-backup-looking path) returning 200 — nothing legitimate ever requests it. The file itself contains the real `svc-web` SQL Server connection string, plaintext password included. | **needs work — live-tested 2026-09-27, real forwarding gap found in defense-tooling, not yet resolved.** The attack itself works fine (confirmed live: `curl http://10.0.2.5/Web.config.bak` returns 200 with the real `svc-web` connection string). But the `iis` index has zero events, ever, despite `defense-tooling`'s own CLAUDE.md claiming this was "confirmed live" in an earlier session. Root-caused as far as time allowed: the forwarder's `[monitor://C:\inetpub\logs\LogFiles\W3SVC1\*.log]` stanza on `web` is correctly configured (verified via `splunk btool inputs list --debug`, `disabled=0`), and a *raw Windows service restart* never even attempts to watch that path (`TailingProcessor` log shows zero mentions) — but a proper `splunk.exe restart` (not just `Restart-Service`) DOES register `Adding watch on path: C:\inetpub\logs\LogFiles\W3SVC1`, confirmed present across several restarts going back further than this session, including ones before this session started. Despite the watch being registered, the actual log file inside that directory (`u_ex260928.log`) is never opened/read (`WatchedFile` never mentions it) and nothing lands in the `iis` index even minutes after a fresh request. Granting the forwarder's service account (`NT SERVICE\SplunkForwarder`) explicit read access to the log folder (it previously had no ACE there at all, only SYSTEM/Administrators) did not fix it either. Root cause not found before time ran out on this investigation — worth a fresh, dedicated pass in `defense-tooling` rather than guessing further here. |
| Portal database read via leaked or permissive credentials | SQL Server Audit / Extended Events (not wired up yet — same gap as the SQL Server category below). Two independent paths land here: (1) the leaked `svc-web` SQL login from the row above, used to query `CyberHawksPortal` directly, and (2) `CyberHawksPortal` being readable via Windows Auth by any domain user, independent of the leak. Alert on either principal — anything other than the web app's own expected service context — reading the `Users` table. | ready |

**Why "weak admin password" isn't its own row:** it's a static property (the
portal admin's password hash, `SHA1('abc123')`, is crackable once read),
not a live event with its own telemetry — it's the *consequence* of the DB
read above, not a separate detectable action. If the portal ever gains its
own authentication logging, "admin login from an unexpected source" would
be the row to add then; nothing to alert on for it yet.

## ADCS

| Detection | Log source | Status |
|---|---|---|
| RPC/ICPR issuance (ESC1-4, 6, 7, 9, 10, 13, 15-17) | CA operational log (action) + Zeek `conn.log` (IP), excluding normal auto-enrollment where the requesting principal is the machine account of the host the certificate is issued to | ready |
| HTTP web enrollment (ESC8) | IIS log on the CA | ready |

## Credential & ticket dumping

| Detection | Log source | Status |
|---|---|---|
| SAM/LSA hive dumping — shadow-copy read path | WMI-Activity operational log for VSS creation (`Win32_ShadowCopy` `Create` method invocation), correlated to a subsequent read of the shadow-copied `config\SAM`/`config\SECURITY`. Split out 2026-09-27 when the `reg save`/registry-query paths for this same finding graduated (see backlog.md's "Implemented" section) — this specific sub-technique (reading the *offline* hive off a shadow copy, rather than the live hive directly) hasn't been live-tested yet | ready |
| SAM — remote via SAMR | Zeek — `dce_rpc.log`, SAMR interface (account enumeration only — doesn't touch the registry, so this is its only detection surface and can go dark under SMB encryption); a remote SAM *hive* dump (`netexec --sam`, `secretsdump`) goes through Remote Registry/MS-RRP instead, which trips the host-side SAM registry SACL above regardless of encryption | ready |
| LSA — remote via LSARPC | Zeek — `dce_rpc.log`, LSARPC interface (policy/secrets enumeration — doesn't touch the registry, can go dark under SMB encryption); a remote SECURITY hive dump goes through Remote Registry/MS-RRP instead, which trips the host-side SECURITY registry SACL above regardless of encryption | ready |
| LSASS memory access (mimikatz `sekurlsa`) | Sysmon Event 10 (ProcessAccess, target = `lsass.exe`), filtered to `GrantedAccess` masks associated with credential reading (`0x1010`, `0x1038`, `0x1400`, `0x1438`, `0x143a`) and an allowlist of legitimate accessors (Defender/`MsMpEng`, WMI provider host) + 4624/4697 for source IP — these access levels aren't part of normal Windows operation outside that allowlist | ready — **caveat:** PsExec running as SYSTEM breaks the account-name join to `SourceUser`; fall back to 4697 (service install) + process lineage in that case. **Resolved research question, mimikatz-only confirmed:** Rubeus's own-session ticket ops (`triage`/`dump`/`klist`) go through the legitimate `LsaCallAuthenticationPackage` LSA API against the Kerberos SSP — the same mechanism native `klist.exe` uses — rather than a memory-read handle on `lsass.exe`, so this row never catches them. **Open item, deliberately undocumented as a designed detection:** there's no native Windows telemetry for that LSA API call itself (confirmed via research — see EDR vendors' own writeups on `LsaCallAuthenticationPackage`/the `lsasspirpc` ALPC port), and the realistic fallback surfaces (Sysmon Event 1 command-line matching, PowerShell Script Block Logging for a reflectively-loaded copy) are all narrow and evadable enough that none of them earned a `ready` row yet. Revisit if a stronger signal turns up; extracting *other* users' tickets needs prior SYSTEM-level privilege escalation first, which is already covered under Lateral movement / Host persistence below. |
| NTDS.dit extraction (IFM / shadow copy on a DC) | WMI-Activity operational log (`Win32_ShadowCopy` `Create` method invocation — catches `vssadmin`/`wmic`/PowerShell uniformly, no command-line auditing needed) + 4663 SACL on `%SystemRoot%\NTDS\ntds.dit`. **Note (2026-09-27):** if the actual extraction step also uses backup/restore-privilege APIs (as `ntdsutil`'s IFM does, and as `reg save` was confirmed to for SAM/SECURITY — see "Implemented" section), the 4663 half of this may not fire at all without the same fix that finding needed (Sensitive Privilege Use auditing + the `FullPrivilegeAuditing` LSA value + a forwarder whitelist entry for 4673/4674) — verify this live before assuming the SACL alone is sufficient | ready |
| Shadow Credentials (KeyCredentialLink abuse) | Windows Events — 5136 (directory service object modified, `msDS-KeyCredentialLink`) | ready |

## Enumeration (info pulled)

LDAP/LDAPS query content graduated 2026-09-27 -- see the "Implemented"
section above (**ADWS is not yet implemented in that alert's SPL**, only
plain LDAP and LDAPS -- left as a known gap, see the YAML's
`how_to_implement` for why).

## Lateral movement

| Detection | Log source | Status |
|---|---|---|
| WMI remote execution | WMI-Activity operational log + Sysmon Event 1 (child process of `WmiPrvSE.exe`) | ready |
| Remote scheduled task creation | Windows Events — 4698 (scheduled task created) correlated with a 4624 Logon Type 3 on the target in the preceding window — that correlation is what distinguishes this from the local-persistence variant below | ready |
| Remote service creation (including PsExec) | Windows Events — 7045 (service installed) + 4697 on the target, correlated with a preceding remote logon (4624 Logon Type 3, or Type 10 for PsExec-style remote admin sessions) — that correlation is what distinguishes this from the local-persistence variant below | ready |

## AD persistence & privilege escalation

| Detection | Log source | Status |
|---|---|---|
| RBCD configuration write | Windows Events — 5136 (directory service object modified, `msDS-AllowedToActOnBehalfOfOtherIdentity`) | ready |
| ACL / delegation abuse (DACL rights granted) | Windows Events — 5136 (directory service object modified, `nTSecurityDescriptor`), monitored on **every** occurrence — legitimate ACL edits in this range should be effectively zero after initial provisioning (no ongoing AD administration), so filtering to specific rights/GUIDs isn't necessary the way it would be in a live production domain | ready |
| Logon script tampering | Windows Events — 4663 (SACL, write to a NETLOGON script) | ready |
| ScriptPath attribute tampering | Windows Events — 5136 (`scriptPath` attribute modified) | ready |

## Defense evasion

| Detection | Log source | Status |
|---|---|---|
| Event log clearing | Windows Events — 1102 (audit log cleared) + System log 104 (log file cleared) — both fire only on an explicit clear action (`wevtutil cl`, Event Viewer's "Clear Log"), not on normal size-based log rotation/overwrite, so no exclusions are needed | ready |
| Security software tampering (stop service, modify registry, uninstall) | Windows Events — 7040 (service start-type changed) + 4657 (SACL on the `WinDefend`/`WdNisSvc`/`Sense` registry keys) + Defender's own tamper-protection events (5001-5013) — scoped to Defender only, since that's the only security product in this range | ready |

## Host persistence

| Detection | Log source | Status |
|---|---|---|
| Local scheduled task persistence | Windows Events — 4698 (scheduled task created) with no correlated remote logon (4624 Logon Type 3) in the preceding window — see Lateral movement above for the distinguishing correlation | ready |
| Malicious local service creation | Windows Events — 7045 (service installed) + 4697, with no correlated remote logon — see Lateral movement above for the distinguishing correlation | ready |
| WMI event subscription persistence | Sysmon — Events 19/20/21 (WmiEvent: filter/consumer/binding created) — requires the WMI event tracing subscriptions to be turned on in the Sysmon config | ready |

## Linux (service-abuse host)

| Detection | Log source | Status |
|---|---|---|
| `/etc/shadow` read | auditd — file watch + PAM `USER_LOGIN`, tied by `auid`/`ses` | ready — **note:** ingestion not wired up yet; auditd's plain-text format mostly auto-extracts in Splunk without an add-on, see `defense-tooling`'s open items for what a dedicated add-on would still improve |
