# Detection backlog

Every planned detection for the `cyberhawks.lab` range, by category. See
the [README](../README.md) for what "status" means here — `ready` is a
design status, not an implementation status. None of these have real,
verified SPL yet.

Log sources assume the add-ons documented in `defense-tooling`'s
`docs/add-ons.md`.

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
| Network port/host scanning (ICMP, TCP, UDP sweeps) | Zeek `conn.log` — Zeek has no dedicated `icmp.log` (an earlier draft of this entry wrongly assumed one; ICMP shows up in `conn.log` with `proto=icmp`, same as everything else). One source pinging 5+ distinct hosts within ~10s (host discovery sweep); same file, analogous heuristic for TCP/UDP port scans (many distinct ports or hosts touched by one source in a short window) | ready |
| Name resolution poisoning (LLMNR / NBT-NS / mDNS) | Zeek `dns.log` — LLMNR (5355) and mDNS (5353) are DNS-formatted on the wire, so Zeek's DNS analyzer picks them up there via protocol detection regardless of port; nothing on this network legitimately answers these broadcast queries, so any response at all is suspicious. **NBT-NS (137) is a different, non-DNS protocol and Zeek's base distribution has no analyzer for it** — that part of this detection is unconfirmed and may need a community Zeek package or a different data source entirely | ready — NBT-NS coverage flagged as unconfirmed |

## Credential exposure

> Description-field password lives under **Enumeration** below — it's an LDAP read, not a file share.

| Detection | Log source | Status |
|---|---|---|
| NETLOGON script creds | Windows Events — 5145 | ready |
| GPP cpassword (SYSVOL) | Windows Events — 5145 | ready |
| File share dump | Windows Events — 5145 | ready |

## Weak / missing authentication

| Detection | Log source | Status |
|---|---|---|
| ASREPRoast | Windows Events — 4768 | ready |
| Kerberoast | Windows Events — 4769 | ready |
| Password spray / guessable password | Windows Events — 4771 + 4625 | ready |
| Pre-2000 / blank password | Windows Events — 4624 | ready |
| Anonymous logon / null session | Windows Events — 4624 (anonymous) | ready |
| NetNTLMv1 permitted | Windows Events — 4624, the `Package Name (NTLM only)` field = `NTLM V1` (corrected from an earlier draft that referenced 8004, which doesn't reliably break out NTLM version) | ready |
| Zone transfer (AXFR) | Zeek — `dns.log` | ready |

## NTLM relay & coercion

| Detection | Log source | Status |
|---|---|---|
| Coercion trigger (PetitPotam / DFSCoerce / ShadowCoerce / PrinterBug) | Sysmon — Events 17/18 (named pipe created/connected) on the DC, filtered to `\PIPE\efsrpc` and `\PIPE\lsarpc` (MS-EFSR/PetitPotam — it binds over either pipe), `\PIPE\netdfs` (MS-DFSNM/DFSCoerce), `\PIPE\FssagentRpc` (MS-FSRVP/ShadowCoerce), and `\PIPE\spoolss` (MS-RPRN/PrinterBug — the same Print Spooler primitive already used elsewhere in the range for the delegation and ESC8 scenarios). Host-side, so it doesn't go dark under SMB-encrypted named-pipe traffic the way a network-based version would. | ready |
| Relayed SMB or LDAP connection | Windows Events — 4624 at the target, `Authentication Package Name = NTLM`, for either a user or a computer principal (a relay victim can be either — poisoning captures a user's hash, coercion captures a computer's). Kerberos is this domain's default/preferred protocol when both sides support it, so NTLM at all is already a weaker signal on its own — flag it specifically when `SourceNetworkAddress` isn't one of the range's known domain-joined host IPs, since every legitimate host here has a fixed, known IP. | ready |
| Attacker-added DNS record | Windows Events — 5137 (directory service object created, DNS zone partition) | ready |

## SQL Server

| Detection | Log source | Status |
|---|---|---|
| Svc reuse / Windows Auth open / EXECUTE AS / linked server | SQL Server Audit / Extended Events | ready — **note:** this data source isn't wired up yet; see `defense-tooling`'s open items (SQL Server Audit/Extended Events aren't plain text, need the Splunkbase SQL Server add-on or custom scripting) |

## Web application

| Detection | Log source | Status |
|---|---|---|
| Portal DB readable / weak admin password | App / IIS log | ready |

## ADCS

| Detection | Log source | Status |
|---|---|---|
| RPC/ICPR issuance (ESC1-4, 6, 7, 9, 10, 13, 15-17) | CA operational log (action) + Zeek `conn.log` (IP) | ready |
| HTTP web enrollment (ESC8) | IIS log on the CA | ready |

## Credential & ticket dumping

| Detection | Log source | Status |
|---|---|---|
| SAM hive dumping | Windows Events — 4656/4663 SACL on `HKLM\SAM` + a File System SACL on `%SystemRoot%\System32\config\SAM`, filtered to process ≠ `lsass.exe`, plus the WMI-Activity operational log for VSS creation (`Win32_ShadowCopy` `Create` method invocation) to catch the shadow-copy-read path | ready |
| LSA hive dumping (incl. LSA secrets) | Windows Events — 4656/4663 SACL on `HKLM\SECURITY` + a File System SACL on `%SystemRoot%\System32\config\SECURITY`, filtered to process ≠ `lsass.exe`, plus the WMI-Activity operational log for VSS creation, same as SAM above | ready |
| SAM — remote via SAMR | Zeek — `dce_rpc.log`, SAMR interface (account enumeration only — doesn't touch the registry, so this is its only detection surface and can go dark under SMB encryption); a remote SAM *hive* dump (`netexec --sam`, `secretsdump`) goes through Remote Registry/MS-RRP instead, which trips the host-side SAM registry SACL above regardless of encryption | ready |
| LSA — remote via LSARPC | Zeek — `dce_rpc.log`, LSARPC interface (policy/secrets enumeration — doesn't touch the registry, can go dark under SMB encryption); a remote SECURITY hive dump goes through Remote Registry/MS-RRP instead, which trips the host-side SECURITY registry SACL above regardless of encryption | ready |
| LSASS memory access (mimikatz `sekurlsa`, Rubeus ticket dumping) | Sysmon Event 10 (ProcessAccess, target = `lsass.exe`), filtered to `GrantedAccess` masks associated with credential reading (`0x1010`, `0x1038`, `0x1400`, `0x1438`, `0x143a`) and an allowlist of legitimate accessors (Defender/`MsMpEng`, WMI provider host) + 4624/4697 for source IP — these access levels aren't part of normal Windows operation outside that allowlist | ready — **caveat:** PsExec running as SYSTEM breaks the account-name join to `SourceUser`; fall back to 4697 (service install) + process lineage in that case |
| DPAPI masterkey / credential file theft | Windows Events — 4663, SACL on the Protect and Credentials folders | ready |
| Pass-the-ticket / ticket reuse | Zeek — `kerberos.log`, same ticket from a different source IP | ready |
| DCSync | Windows Events — 4662 (action) + Zeek `conn.log` (IP) | ready |
| WinRM logon | Windows Events — 4624 (Logon Type 3) + `Microsoft-Windows-WinRM/Operational` log for session establishment (PsExec and remote scheduled tasks are covered separately under Lateral movement below — don't conflate this with those) | ready |
| NTDS.dit extraction (IFM / shadow copy on a DC) | WMI-Activity operational log (`Win32_ShadowCopy` `Create` method invocation — catches `vssadmin`/`wmic`/PowerShell uniformly, no command-line auditing needed) + 4663 SACL on `%SystemRoot%\NTDS\ntds.dit` | ready |
| Shadow Credentials (KeyCredentialLink abuse) | Windows Events — 5136 (directory service object modified, `msDS-KeyCredentialLink`) | ready |

## Enumeration (info pulled)

| Detection | Log source | Status |
|---|---|---|
| LDAP query content (users, groups, description, etc.) | Windows Events — 1644 with both Field Engineering thresholds (Search Time Threshold, Expensive Search Results Threshold) set to 0, logging the filter, base DN, attributes, and client IP for **every** LDAP query, not just expensive ones. No alerting on 1644 by itself — it's the log-everything layer. Alerting comes from Zeek `ldap.log` flagging any bind/search from an IP that isn't one of the domain-joined systems; when that fires, correlate its timestamp/source IP back to the matching 1644 event to pull the actual query. **Volume management:** cap the local `Directory Service` log (`wevtutil sl`, fixed max size, overwrite-oldest retention) so it never fills, and forward 1644 off the DC promptly (WEF or a log shipper) — the local copy only needs a short correlation window, not permanent history. Same forwarding/rotation approach applies to LDAPS and ADWS below. | ready |
| LDAPS query content | Same two-layer design as LDAP above — 1644 logs every query's content (fires server-side after decryption, so wire encryption doesn't blind it); since Zeek can't decrypt LDAPS, the alerting layer is `conn.log` flagging any TCP/636 connection from a non-domain-joined IP, then correlating to 1644 for the content | ready |
| ADWS query content | Same two-layer design as LDAP — ADWS ultimately hands its translated queries to the same local DS/LDAP engine on the DC, so 1644 should capture the content there too; alerting is Zeek `conn.log` flagging a non-domain-joined IP touching TCP/9389, correlated to 1644 by timestamp | ready — **known gap:** the 1644 event's client IP may show the ADWS service process itself rather than the true remote caller, so correlate by timestamp rather than IP match here; not yet confirmed against a real ADWS query on this build |

## Lateral movement

| Detection | Log source | Status |
|---|---|---|
| WMI remote execution | WMI-Activity operational log + Sysmon Event 1 (child process of `WmiPrvSE.exe`) | ready |
| Remote scheduled task creation | Windows Events — 4698 (scheduled task created) + 4624 (Logon Type 3) on the target | ready |
| Remote service creation (including PsExec) | Windows Events — 7045 (service installed) + 4697 on the target | ready |

## AD persistence & privilege escalation

| Detection | Log source | Status |
|---|---|---|
| Rogue machine account creation | Windows Events — 4741 (computer account created) | ready |
| New Domain Admin / privileged group membership change | Windows Events — 4720 (user created) + 4728/4732/4756 (member added to a security-enabled group) | ready |
| RBCD configuration write | Windows Events — 5136 (directory service object modified, `msDS-AllowedToActOnBehalfOfOtherIdentity`) | ready |
| ACL / delegation abuse (DACL rights granted) | Windows Events — 5136 (directory service object modified, `nTSecurityDescriptor`), monitored on **every** occurrence — legitimate ACL edits in this range should be effectively zero after initial provisioning (no ongoing AD administration), so filtering to specific rights/GUIDs isn't necessary the way it would be in a live production domain | ready |
| Logon script or ScriptPath tampering | Windows Events — 4663 (SACL, write to a NETLOGON script) + 5136 (`scriptPath` attribute modified) | ready |

## Defense evasion

| Detection | Log source | Status |
|---|---|---|
| Event log clearing | Windows Events — 1102 (audit log cleared) + System log 104 | ready |
| Security software tampering (stop service, modify registry, uninstall) | Windows Events — 7040 (service start-type changed) + 4657 (SACL on the `WinDefend`/`WdNisSvc`/`Sense` registry keys) + Defender's own tamper-protection events (5001-5013) — scoped to Defender only, since that's the only security product in this range | ready |

## Host persistence

| Detection | Log source | Status |
|---|---|---|
| Local scheduled task persistence | Windows Events — 4698 (scheduled task created) | ready |
| Malicious local service creation | Windows Events — 7045 (service installed) + 4697 | ready |
| WMI event subscription persistence | Sysmon — Events 19/20/21 (WmiEvent: filter/consumer/binding created) — requires the WMI event tracing subscriptions to be turned on in the Sysmon config | ready |

## Linux (service-abuse host)

| Detection | Log source | Status |
|---|---|---|
| `/etc/shadow` read | auditd — file watch + PAM `USER_LOGIN`, tied by `auid`/`ses` | ready — **note:** ingestion not wired up yet; auditd's plain-text format mostly auto-extracts in Splunk without an add-on, see `defense-tooling`'s open items for what a dedicated add-on would still improve |
