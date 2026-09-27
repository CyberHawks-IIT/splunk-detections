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
| SAM hive dumping | 2026-09-27 | Split into two: [credential-dumping/sam_lsa_dump_registry_export.yml](credential-dumping/sam_lsa_dump_registry_export.yml) (as "SAM/LSA Dump: Registry Export") and [credential-dumping/sam_dump_registry_query.yml](credential-dumping/sam_dump_registry_query.yml) (as "SAM Dump: Registry Query") | Two independent local dumping techniques, each with different telemetry. `reg save` (export) needed a 3-part infra fix (Sensitive Privilege Use auditing + FullPrivilegeAuditing LSA value + a forwarder whitelist gap for 4673/4674) and still can't name which hive was read — merged with LSA into one alert. Direct registry query (as SYSTEM) worked as originally designed and correctly names the hive, so it stays a separate alert per hive. Live-tested both ways on workstation with Defender real-time monitoring disabled. |
| LSA hive dumping (incl. LSA secrets) | 2026-09-27 | See SAM hive dumping row above — same split applies (Registry Export merged with SAM; [credential-dumping/lsa_dump_registry_query.yml](credential-dumping/lsa_dump_registry_query.yml) as "LSA Dump: Registry Query" for the distinguishable technique) | — |
| DPAPI masterkey / credential file theft | 2026-09-27 | [credential-dumping/dpapi_dump.yml](credential-dumping/dpapi_dump.yml) | Live masterkey + credential-blob file reads on workstation, fired exactly once, no false positives over 4h — worked as originally designed |
| ASREPRoast | 2026-09-27 | [weak-auth/asreproast.yml](weak-auth/asreproast.yml) | Named "AS-REP Roast" per the Alert Embed Planner. Live `impacket-GetNPUsers` against asmith (the range's dedicated no-preauth account) from john-kali, fired exactly once (2 4768s 11ms apart merged by a 1m bucket); worked as originally designed, no infra fix needed — confirmed zero Pre-Authentication-Type=0 events in 24h of background traffic beforehand |
| Kerberoast | 2026-09-27 | [weak-auth/kerberoast.yml](weak-auth/kerberoast.yml) | Live `impacket-GetUserSPNs` against both real user-SPN accounts (crackme, svc-mssql) using asmith's cracked password, fired exactly once. Needed a real fix mid-design: filtering by the *requesting* account (`NOT Account_Name="*$@*"`) still false-positived on a human admin's normal logon triggering machine-account service tickets — switched to filtering by the *target* Service_Name (`NOT Service_Name="*$"`) instead, since machine accounts requesting tickets to each other is the actual baseline noise pattern, not who's asking |
| Zone transfer (AXFR) | 2026-09-27 | [weak-auth/zone_transfer.yml](weak-auth/zone_transfer.yml) | Live `dig axfr cyberhawks.lab @10.0.2.2` (dc1's real IP — a prior memory snapshot had this wrong as 10.0.2.4), full unauthenticated zone dump retrieved, fired exactly once, worked as originally designed |
| Password spray / guessable password | 2026-09-27 | [weak-auth/password_spray.yml](weak-auth/password_spray.yml) | Live `netexec smb` (NTLM vector) and `kerbrute passwordspray` (Kerberos vector), both against a 20-name wordlist with the real weak-cred pool password `Summer2026`, each fired exactly once. Needed an exclusion for netexec's own ANONYMOUS LOGON null-session probe. **Documented, not fixed:** asmith (the no-preauth account) always shows as a false "success" for any Kerberos-vector spray that includes it, since a no-preauth account's AS-REQ always looks successful regardless of the guessed password |
| Pre-2000 / blank password | 2026-09-27 | [weak-auth/computer_password_spray.yml](weak-auth/computer_password_spray.yml) | Named "Computer Password Spray" per the Alert Embed Planner. Live `impacket-getTGT` against computer4 (pre-2k default password) and `netexec smb` against computer5 (blank password), fired exactly once. No threshold needed — computer4/computer5 are placeholder AD objects with no real host, so any successful auth at all is the signal |
| NetNTLMv1 permitted | 2026-09-27 | [weak-auth/netntlmv1_authentication.yml](weak-auth/netntlmv1_authentication.yml) | Live `smbclient` with NTLMv2 disabled client-side, forcing a real NTLMv1 auth to dc1, fired exactly once. Needed real exclusions: NTLMv1 turned out to be common baseline noise in this range (routine dc2$-to-dc1 inter-DC traffic and anonymous/null-session logons both use it, a side effect of the domain-wide `LmCompatibilityLevel=1` weakening) — scoped to named non-machine accounts only |
| Anonymous logon / null session | 2026-09-27 | [weak-auth/smb_anonymous_object_enumeration.yml](weak-auth/smb_anonymous_object_enumeration.yml) | Named "SMB Anonymous Object Enumeration" per the Alert Embed Planner. Live `netexec --users` and `impacket-samrdump` (zero credentials), both fired. **Design deviation from the original backlog wording, verified not just assumed:** MS-LSAT `LsarLookupSids` returns STATUS_ACCESS_DENIED anonymously in this range (confirmed via `impacket-lookupsid`) even though MS-SAMR's enumeration calls work anonymously with no restriction — scoped to the SAMR calls that are actually reachable, dropped the LSA leg |

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

| Detection | Log source | Status |
|---|---|---|
| Name resolution poisoning (LLMNR / NBT-NS / mDNS) | Zeek `dns.log` — LLMNR (5355) and mDNS (5353) are DNS-formatted on the wire, so Zeek's DNS analyzer picks them up there via protocol detection regardless of port; nothing on this network legitimately answers these broadcast queries, so any response at all is suspicious. **NBT-NS (137) is a different, non-DNS protocol and Zeek's base distribution has no analyzer for it** — that part of this detection is unconfirmed and may need a community Zeek package or a different data source entirely | ready — NBT-NS coverage flagged as unconfirmed |

## Credential exposure

> Description-field password lives under **Enumeration** below — it's an LDAP read, not a file share.

| Detection | Log source | Status |
|---|---|---|
| NETLOGON script creds | Windows Events — 5145 | ready |
| GPP cpassword (SYSVOL) | Windows Events — 5145 | ready |
| File share dump | Windows Events — 5145 | ready |

## Weak / missing authentication

All 7 detections in this category have graduated — see the "Implemented"
section above.

## NTLM relay & coercion

| Detection | Log source | Status |
|---|---|---|
| Coercion trigger (PetitPotam / DFSCoerce / ShadowCoerce / PrinterBug) | Sysmon — Events 17/18 (named pipe created/connected) on the DC, filtered to `\PIPE\efsrpc` and `\PIPE\lsarpc` (MS-EFSR/PetitPotam — it binds over either pipe), `\PIPE\netdfs` (MS-DFSNM/DFSCoerce), `\PIPE\FssagentRpc` (MS-FSRVP/ShadowCoerce), and `\PIPE\spoolss` (MS-RPRN/PrinterBug — the same Print Spooler primitive already used elsewhere in the range for the delegation and ESC8 scenarios). Host-side, so it doesn't go dark under SMB-encrypted named-pipe traffic the way a network-based version would. | ready |
| Attacker-added DNS record | Windows Events — 5137 (directory service object created, DNS zone partition) | ready |

## SQL Server

> All four of these need the SQL Server Audit/Extended Events source, which isn't wired up yet — see `defense-tooling`'s open items (SQL Server Audit/Extended Events aren't plain text, need the Splunkbase SQL Server add-on or custom scripting).

| Detection | Log source | Status |
|---|---|---|
| `xp_cmdshell` execution | SQL Server Audit / Extended Events | ready |
| `xp_dirtree` execution | SQL Server Audit / Extended Events | ready |
| `EXECUTE AS` impersonation | SQL Server Audit / Extended Events | ready |
| Linked server command execution | SQL Server Audit / Extended Events | ready |

## Web application

> These two used to be one row ("Portal DB readable / weak admin password").
> Splitting them because they're independently exploitable: a leaked
> credential in a stray backup file, and a separate DB permission
> misconfiguration. "Weak admin password" isn't its own row — see the note
> below the table for why.

| Detection | Log source | Status |
|---|---|---|
| `Web.config.bak` credential leak | App / IIS log — `Web.config` is deployed alongside a byte-identical `Web.config.bak` on `web` (left behind from a manual edit, per this range's design), and IIS's static-content handler was given a MIME-type mapping for `.bak` so it actually serves the file instead of 404ing. Alert on any HTTP GET of `Web.config.bak` (or any `.bak`/config-backup-looking path) returning 200 — nothing legitimate ever requests it. The file itself contains the real `svc-web` SQL Server connection string, plaintext password included. | ready |
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
| Pass-the-ticket / ticket reuse | Zeek — `kerberos.log`, same ticket from a different source IP | ready |
| DCSync | Windows Events — 4662 (action) + Zeek `conn.log` (IP), excluding DS-Replication-Get-Changes* activity performed by the domain controllers' own machine accounts (legitimate inter-DC replication) | ready |
| WinRM logon | Windows Events — 4624 (Logon Type 3) + `Microsoft-Windows-WinRM/Operational` log for session establishment (PsExec and remote scheduled tasks are covered separately under Lateral movement below — don't conflate this with those) | ready |
| NTDS.dit extraction (IFM / shadow copy on a DC) | WMI-Activity operational log (`Win32_ShadowCopy` `Create` method invocation — catches `vssadmin`/`wmic`/PowerShell uniformly, no command-line auditing needed) + 4663 SACL on `%SystemRoot%\NTDS\ntds.dit`. **Note (2026-09-27):** if the actual extraction step also uses backup/restore-privilege APIs (as `ntdsutil`'s IFM does, and as `reg save` was confirmed to for SAM/SECURITY — see "Implemented" section), the 4663 half of this may not fire at all without the same fix that finding needed (Sensitive Privilege Use auditing + the `FullPrivilegeAuditing` LSA value + a forwarder whitelist entry for 4673/4674) — verify this live before assuming the SACL alone is sufficient | ready |
| Shadow Credentials (KeyCredentialLink abuse) | Windows Events — 5136 (directory service object modified, `msDS-KeyCredentialLink`) | ready |

## Enumeration (info pulled)

| Detection | Log source | Status |
|---|---|---|
| LDAP query content (users, groups, description, etc.) — one alert, `protocol` field set to `ldap`/`ldaps`/`adws` depending on which one fired | Windows Events — 1644 with both Field Engineering thresholds (Search Time Threshold, Expensive Search Results Threshold) set to 0, logging the filter, base DN, attributes, and client IP for **every** LDAP query, not just expensive ones — all three protocols land here, since LDAPS and ADWS both ultimately hand off to the same local LDAP engine on the DC. No alerting on 1644 by itself — it's the log-everything layer. Alerting: Zeek `ldap.log` for plain LDAP, flagging any bind/search from a non-domain-joined IP; `conn.log` (TCP/636) for LDAPS, since Zeek can't decrypt the wire traffic; `conn.log` (TCP/9389) for ADWS. Whichever fires, correlate its timestamp/source IP back to the matching 1644 event to pull the actual query and set `protocol` accordingly. **Volume management:** cap the local `Directory Service` log (`wevtutil sl`, fixed max size, overwrite-oldest retention) so it never fills, and forward 1644 off the DC promptly (WEF or a log shipper) — the local copy only needs a short correlation window, not permanent history. **known gap:** for the ADWS case, the 1644 event's client IP may show the ADWS service process itself rather than the true remote caller, so correlate by timestamp rather than IP match there; not yet confirmed against a real ADWS query on this build | ready |

## Lateral movement

| Detection | Log source | Status |
|---|---|---|
| WMI remote execution | WMI-Activity operational log + Sysmon Event 1 (child process of `WmiPrvSE.exe`) | ready |
| Remote scheduled task creation | Windows Events — 4698 (scheduled task created) correlated with a 4624 Logon Type 3 on the target in the preceding window — that correlation is what distinguishes this from the local-persistence variant below | ready |
| Remote service creation (including PsExec) | Windows Events — 7045 (service installed) + 4697 on the target, correlated with a preceding remote logon (4624 Logon Type 3, or Type 10 for PsExec-style remote admin sessions) — that correlation is what distinguishes this from the local-persistence variant below | ready |

## AD persistence & privilege escalation

| Detection | Log source | Status |
|---|---|---|
| Rogue machine account creation | Windows Events — 4741 (computer account created) — legitimate machine account creation doesn't happen in this range post-provisioning, same reasoning as the ACL/delegation row below, so alert on every occurrence with no filtering | ready |
| New Domain Admin / privileged group membership change | Windows Events — 4720 (user created) + 4728/4732/4756 (member added to a security-enabled group) | ready |
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
