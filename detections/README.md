# Implemented detections

A reference for every detection currently implemented in this repo — **54
saved searches** across 17 categories, each one live-fire verified against the
`cyberhawks.lab` range.

- This catalog is a convenience index. The **YAML file is authoritative** for
  the exact SPL, the `verification` block, and the full `known_false_positives`
  history. Each row links to its file.
- [backlog.md](backlog.md) is the design tracker (planned + implemented). The
  root [README.md](../README.md) covers repo layout, the build, and how to
  contribute. [CLAUDE.md](../CLAUDE.md) carries the conventions and the
  per-area investigation notes.

## How to read the "Output fields" and "Exclusions" columns

- **Output fields** are the columns the saved search emits (its final
  `| table`), which become the Discord embed fields. By convention
  (`CLAUDE.md`) the first column is always **`attacker_ip`** — a raw source IP
  resolved to a name in the embed description via the Proxmox attacker
  directory — so it is omitted below; each entry lists only the *additional*
  fields, in embed order. Host- and user-valued fields are normalized to short
  lowercase hostnames (`dc1`) and bare account names (`dsmith`).
- **One alert per attempt.** Every search fires per result row and throttles
  (5m) on a key that identifies one attempt — listed as **Throttle** below.
  Two attackers, or one attacker against two objects, are distinct alerts.
- **Exclusions** are the *deliberate* ones (benign sources/accounts filtered
  out by design). Common infrastructure exclusions — the range gateway
  `10.0.2.1`, loopback/null sources (`-`, `127.0.0.1`, `::1`, `0.0.0.0`) on a
  logon-source trace — are noted only where they matter. "None (every
  occurrence is signal)" means the technique should never happen in this range
  after provisioning, so no filtering is applied by design.

## Summary

| # | Detection | Category | Data source | Additional output fields |
|---|---|---|---|---|
| 1 | [DACL Modification](ad-persistence/dacl_modification.yml) | ad-persistence | Win 5136 (`nTSecurityDescriptor`) | user, target |
| 2 | [Logon Script Tampering](ad-persistence/logon_script_tampering.yml) | ad-persistence | Win 4663 (SYSVOL\scripts write) | host, user, script |
| 3 | [Machine Account Creation](ad-persistence/machine_account_creation.yml) | ad-persistence | Win 4741 | user, account |
| 4 | [Password Change](ad-persistence/password_change.yml) | ad-persistence | Win 4723/4724 | host, user, target |
| 5 | [Privileged Group Membership](ad-persistence/privileged_group_membership.yml) | ad-persistence | Win 4728/4732/4756 + removals | user, group, action, member |
| 6 | [RBCD Configuration](ad-persistence/rbcd_configuration.yml) | ad-persistence | Win 5136 (`msDS-AllowedToActOnBehalfOfOtherIdentity`) | user, target |
| 7 | [ScriptPath Attribute Tampering](ad-persistence/scriptpath_attribute_tampering.yml) | ad-persistence | Win 5136 (`scriptPath`) | user, target, value |
| 8 | [Certificate Request (HTTP)](adcs/certificate_request_http.yml) | adcs | IIS ETW (ca) + Win 4887 | user, template, id |
| 9 | [Certificate Request (RPC)](adcs/certificate_request_rpc.yml) | adcs | Win 4886/4887 + Zeek conn | user, template, id |
| 10 | [Domain Replication (DCSync)](credential-dumping/dcsync.yml) | credential-dumping | Win 4662 (DS-Replication-Get-Changes GUIDs) | user, host |
| 11 | [DPAPI Dump](credential-dumping/dpapi_dump.yml) | credential-dumping | Win 4663 (Protect\ / Credentials\) | host, user, masterkeys, credentials |
| 12 | [NTDS.dit Extraction](credential-dumping/ntds_dit_extraction.yml) | credential-dumping | Win 4656/4663 (`\NTDS\ntds.dit`) + 4624 | host, user |
| 13 | [Pass-the-Ticket](credential-dumping/pass_the_ticket.yml) | credential-dumping | Zeek kerberos.log (TGS from non-AS-REQ IP) | origin, user, service |
| 14 | [Shadow Credential Creation](credential-dumping/shadow_credential_creation.yml) | credential-dumping | Win 5136 (`msDS-KeyCredentialLink`) | host, user, target |
| 15 | [Windows Credential Dump (Local)](credential-dumping/windows_credential_dump_local.yml) | credential-dumping | Win 4656/4663 (SAM/SECURITY hives) + 4624 | host, user, method, hives |
| 16 | [Windows Credential Dump (Remote)](credential-dumping/windows_credential_dump_remote.yml) | credential-dumping | Win 4656/4673 (svchost on hives) + 4624 Type 3 | host, user, method, hives |
| 17 | [NETLOGON Share Read](credential-exposure/netlogon_share_read.yml) | credential-exposure | Win 5145 (`\\*\NETLOGON`) | host, files |
| 18 | [SMB Share Access](credential-exposure/smb_share_access.yml) | credential-exposure | Win 5145 (`\\*\Shared`, sql1) | host, share, files |
| 19 | [SYSVOL Share Read](credential-exposure/sysvol_share_read.yml) | credential-exposure | Win 5145 (`\\*\SYSVOL`) | host, files |
| 20 | [Event Log Clear](defense-evasion/event_log_clear.yml) | defense-evasion | Win 1102 + System 104 + 4624 | host, user, logs |
| 21 | [Delegation: S4U2Proxy](delegation/s4u2proxy.yml) | delegation | Win 4769 (`Transited Services`) + Zeek kerberos | user, service, impersonated |
| 22 | [Delegation: S4U2Self](delegation/s4u2self.yml) | delegation | Win 4769 (self-reference) + Zeek kerberos | user, service, impersonated |
| 23 | [LDAP Query](enumeration/ldap_query.yml) | enumeration | Win 1644 (Field Engineering) + Zeek conn_open | host, protocol, user, query, attributes |
| 24 | [Scheduled Task Creation (Local)](host-persistence/scheduled_task_local.yml) | host-persistence | Win 4698, no correlated Type 3 logon | host, user, task |
| 25 | [Service Creation (Local)](host-persistence/service_creation_local.yml) | host-persistence | Win 7045, no correlated Type 3 logon | host, user, service |
| 26 | [WMI Event Subscription Creation](host-persistence/wmi_event_subscription.yml) | host-persistence | Sysmon 19/20/21 | host, user, filter, consumer, binding |
| 27 | [Lateral Movement: MSSQL](lateral-movement/mssql_logon.yml) | lateral-movement | SQL Audit SUCCESSFUL_LOGIN_GROUP | host, user |
| 28 | [Lateral Movement: RDP](lateral-movement/rdp_logon.yml) | lateral-movement | Win 4624 Type 10 | host, user |
| 29 | [Lateral Movement: Scheduled Task](lateral-movement/scheduled_task.yml) | lateral-movement | Win 4698 + correlated Type 3 logon | host, user, task |
| 30 | [Lateral Movement: Service](lateral-movement/service_creation.yml) | lateral-movement | Win 7045 + correlated Type 3 logon | host, user, service |
| 31 | [Lateral Movement: WinRM](lateral-movement/winrm_logon.yml) | lateral-movement | WinRM/Operational 91 (+ Zeek/4624 on 2016) | host, user |
| 32 | [Lateral Movement: WMI](lateral-movement/wmi_execution.yml) | lateral-movement | Sysmon 1 (`WmiPrvSE.exe` child) + 4624 | host, user |
| 33 | [Shadow Dump](linux/shadow_dump.yml) | linux | auditd `shadow_read` watch + USER_LOGIN | host, user |
| 34 | [DNS Record Creation](ntlm/dns_record_creation.yml) | ntlm | Win 5137 (dnsNode) | user, name |
| 35 | [Forced Authentication](ntlm/forced_authentication.yml) | ntlm | RPC Firewall event 3 + Zeek conn (backstop) | host, type, user |
| 36 | [NTLM Authentication](ntlm/ntlm_authentication.yml) *(disabled)* | ntlm | Win 4624 (NTLM) | host, user |
| 37 | [ARP Scan](reconnaissance/arp_scan.yml) | reconnaissance | Zeek arp_request.log | hosts |
| 38 | [DHCPv6 Spoofing](reconnaissance/dhcpv6_spoofing.yml) | reconnaissance | Zeek conn.log (UDP 547→546) | mac, targets |
| 39 | [Name Resolution Poisoning](reconnaissance/name_resolution_poisoning.yml) | reconnaissance | Zeek conn.log (LLMNR/mDNS/NBNS) | target, protocols |
| 40 | [Ping Sweep](reconnaissance/ping_sweep.yml) | reconnaissance | Zeek conn.log (ICMP) | hosts |
| 41 | [Port Scan](reconnaissance/port_scan.yml) | reconnaissance | Zeek conn.log (TCP/UDP) | hosts, protocol, ports |
| 42 | [EXECUTE AS Impersonation](sql-server/execute_as_impersonation.yml) | sql-server | SQL Audit (action IMP) | host, user, impersonated |
| 43 | [Linked Server Execution](sql-server/linked_server_execution.yml) | sql-server | SQL XE `oledb_provider_information` | host, user, linked |
| 44 | [xp_cmdshell Execution](sql-server/xp_cmdshell_execution.yml) | sql-server | SQL XE sql_text | host, user, command |
| 45 | [xp_dirtree Execution](sql-server/xp_dirtree_execution.yml) | sql-server | SQL XE sql_text | host, user, path |
| 46 | [AS-REP Roast](weak-auth/asreproast.yml) | weak-auth | Win 4768 (Pre-Auth Type 0) | users |
| 47 | [Computer Password Spray](weak-auth/computer_password_spray.yml) | weak-auth | Win 4624 + 4768 (computer4$/computer5$) | host, successes |
| 48 | [Kerberoast](weak-auth/kerberoast.yml) | weak-auth | Win 4769 (RC4-HMAC, or 2+ SPNs/5m) | users, encryption |
| 49 | [NetNTLMv1 Authentication](weak-auth/netntlmv1_authentication.yml) | weak-auth | Win 4624 (NTLM V1) | host, user |
| 50 | [Password Spray](weak-auth/password_spray.yml) | weak-auth | Win 4625/4771 (+ 4624/4768 successes) | host, successes |
| 51 | [SMB Anonymous Object Enumeration](weak-auth/smb_anonymous_object_enumeration.yml) | weak-auth | Zeek dce_rpc.log (samr enum) | host, method, objects |
| 52 | [Zone Transfer](weak-auth/zone_transfer.yml) | weak-auth | Zeek dns.log (AXFR) | host |
| 53 | [Database Credential Read (admin)](web-application/portal_database_read.yml) | web-application | SQL XE (`Users` table read) | user |
| 54 | [Web Credential Read (Web.config.bak)](web-application/web_config_bak_leak.yml) | web-application | IIS ETW (web) | file |

All 54 are `status: production`. **NTLM Authentication (#36) is disabled**
(`disabled: true`) — kept for reference but not scheduled.

---

## AD persistence

### DACL Modification
An AD object's `nTSecurityDescriptor` (its DACL) replaced — ACL/delegation
abuse granting a principal new rights (GenericAll, WriteDacl, etc.).
- **Fields:** user, target · **Throttle:** attacker_ip, user, target
- **Exclusions:** None (every occurrence is signal; no filtering to specific rights/GUIDs).

### Logon Script Tampering
A write to a file inside a DC's NETLOGON scripts folder
(`SYSVOL\domain\scripts`) — the classic logon-script backdoor.
- **Fields:** host, user, script · **Throttle:** attacker_ip, host, user
- **Exclusions:** None specific.

### Machine Account Creation
Any computer account created anywhere in the domain (the default
`ms-DS-MachineAccountQuota` of 10 lets any user self-join).
- **Fields:** user, account · **Throttle:** attacker_ip, account
- **Exclusions:** None (every occurrence is signal).

### Password Change
One account changes (4723) or resets (4724) another account's password, or its
own. Reset without the old password = ForceChangePassword abuse.
- **Fields:** host, user, target · **Throttle:** attacker_ip, user, target
- **Exclusions:** local-system sources (`-`/loopback/`0.0.0.0`), the gateway `10.0.2.1`, the SYSTEM session (`0x3e7`), and cloudbase-init's self-change.

### Privileged Group Membership
A member added to or removed from a Tier-0 group (Domain/Enterprise/Schema
Admins, built-in Administrators, Account/Backup/Server Operators).
- **Fields:** user, group, action, member · **Throttle:** attacker_ip, user, action, group, member
- **Exclusions:** None (both directions fire; guards require the attacker IP and target SID to resolve).

### RBCD Configuration
A computer object's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute
written — Resource-Based Constrained Delegation setup.
- **Fields:** user, target · **Throttle:** attacker_ip, user, target
- **Exclusions:** None (any write is signal).

### ScriptPath Attribute Tampering
A user object's `scriptPath` attribute modified — points the user at a
different (attacker-controlled) logon script. Distinct from Logon Script
Tampering (which edits a script's contents).
- **Fields:** user, target, value · **Throttle:** attacker_ip, user, target
- **Exclusions:** None.

## AD CS

### Certificate Request (HTTP)
A cert enrollment over AD CS HTTP Web Enrollment (`/certsrv`) — the ESC8 relay
transport. Each CA 4887 whose transport is DCOM, joined to an authenticated
`POST /certsrv/certfnsh.asp` in the CA's IIS log for the client IP.
- **Fields:** user, template, id · **Throttle:** attacker_ip, id
- **Exclusions:** loopback request sources. Complements Certificate Request (RPC).

### Certificate Request (RPC)
A cert issued over RPC/ICPR to a non-machine requester — the RPC exploitation
path for the vulnerable templates (ESC1/2/3/4/6/7/9/10/13/15/16/17).
- **Fields:** user, template, id · **Throttle:** attacker_ip, id
- **Exclusions:** machine accounts (`Requester` ending `$`) to skip normal computer-cert auto-enrollment; loopback sources.

## Credential dumping

### Domain Replication (DCSync)
A non-machine account exercising DS-Replication-Get-Changes[-All] at the domain
root (secretsdump `-just-dc` / mimikatz `dcsync`).
- **Fields:** user, host · **Throttle:** attacker_ip, user, host
- **Exclusions:** machine accounts (`user` ending `$`) — legitimate DC-to-DC replication.

### DPAPI Dump
A process other than `lsass.exe` reading a user's DPAPI masterkey or credential
blob (`%APPDATA%\...\Protect\` / `%LOCALAPPDATA%\...\Credentials\`).
- **Fields:** host, user, masterkeys, credentials · **Throttle:** attacker_ip, host, user
- **Exclusions:** `lsass.exe`. (SACL is on the files only, so folder enumeration produces nothing.)

### NTDS.dit Extraction
A process other than `lsass.exe` opening/reading a DC's `ntds.dit` (live or a
shadow-copy device path) — offline domain credential dump.
- **Fields:** host, user · **Throttle:** attacker_ip, host
- **Exclusions:** `lsass.exe`. Attacker IP via the acting session's 4624, defaulting to the DC's own IP when run locally.

### Pass-the-Ticket
A TGS-REQ from an IP that did not perform the AS-REQ for that client principal,
*when* that AS-REQ was seen from a different host — a reused/stolen ticket.
- **Fields:** origin, user, service · **Throttle:** attacker_ip, user, service
- **Exclusions:** `krbtgt/*` service; principals whose AS-REQ was never observed (treated as un-captured/pre-lookback, not reuse).

### Shadow Credential Creation
A computer/user object's `msDS-KeyCredentialLink` written — Shadow Credentials
(PKINIT auth via an attacker cert).
- **Fields:** host, user, target · **Throttle:** attacker_ip, user, target
- **Exclusions:** None (any write is signal).

### Windows Credential Dump (Local)
A process other than `lsass.exe` accessing the local SAM/SECURITY hives.
`method` = `query` / `export` / `shadow copy` / `file read`.
- **Fields:** host, user, method, hives · **Throttle:** attacker_ip, host, user
- **Exclusions:** `lsass.exe` and `svchost.exe` (a remote-registry dump is the Remote detection). Attacker IP via 4624, defaulting to the host's own IP when local.

### Windows Credential Dump (Remote)
A remote hive dump via Remote Registry (MS-RRP) — svchost exercising backup
privilege for a network-logon principal (secretsdump / `netexec --sam/--lsa`).
`method` = `secdump` / `regdump`.
- **Fields:** host, user, method, hives · **Throttle:** attacker_ip, host, method
- **Exclusions:** service accounts `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `-`. The 4624 Type-3 join is also the primary noise filter.

## Credential exposure

### NETLOGON Share Read
A named account reading a file off a DC's NETLOGON share (here: skumar's
`MapDrives.ps1`, which has cleartext credentials).
- **Fields:** host, files · **Throttle:** attacker_ip
- **Exclusions:** machine accounts (`Account_Name` ending `$`). Fires only on a read *inside* the share, not on share-root access; the SYSVOL path to the same script fires SYSVOL Share Read instead.

### SMB Share Access
A read inside sql1's `Shared` file share (one real leaked credential buried in
filler content).
- **Fields:** host, share, files · **Throttle:** attacker_ip
- **Exclusions:** share-root access (enumeration/listing). `files` keeps only the deepest paths read (a parent folder is dropped once something under it is read).

### SYSVOL Share Read
A named account reading files inside a DC's SYSVOL (GPP `Groups.xml` cpassword +
skumar's logon script).
- **Fields:** host, files · **Throttle:** attacker_ip
- **Exclusions:** machine accounts (GP clients read SYSVOL as the machine account). Share-root access excluded; deepest-paths-only `files`; a NETLOGON read fires NETLOGON Share Read instead.

## Defense evasion

### Event Log Clear
An explicit log-clear action (`wevtutil cl`, Event Viewer, `Clear-EventLog`) —
Security 1102 + System 104, merged per host/minute.
- **Fields:** host, user, logs · **Throttle:** attacker_ip, host
- **Exclusions:** loopback sources on the logon join. (Routine size-based rotation never generates these events, so no exclusion is needed for it.)

## Delegation

### Delegation: S4U2Proxy
The S4U2Proxy exchange — a service with `msDS-AllowedToDelegateTo` requesting a
ticket to a downstream SPN on behalf of another user. In this range `sql2$`
delegates to `cifs/dc1`.
- **Fields:** user, service, impersonated · **Throttle:** attacker_ip, user, service
- **Exclusions:** requires `Transited Services` populated (blank on every ordinary TGS). `impersonated`/full SPN come from Zeek kerberos.log.

### Delegation: S4U2Self
The S4U2Self exchange — a service requesting a ticket *to itself* on behalf of
an arbitrary user (protocol transition).
- **Fields:** user, service, impersonated · **Throttle:** attacker_ip, user, service
- **Exclusions:** a self-reference must come from a *foreign* IP (own-IP/loopback excluded — machine accounts self-request locally all the time). Suppressed when a matching S4U2Proxy exists for the same (attacker, user, impersonated).

## Enumeration

### LDAP Query
An LDAP/LDAPS/ADWS directory search against a DC from an IP not in the range's
static-IP inventory. Anchors on the DC's 1644 event (bind account + filter);
ADWS client IP comes from Zeek conn_open.
- **Fields:** host, protocol, user, query, attributes · **Throttle:** attacker_ip, host, protocol
- **Exclusions:** the range's own domain-joined hosts (known static IPs); for ADWS, machine accounts and the `UNAVAILABLE` internal user.

## Host persistence

### Scheduled Task Creation (Local)
A scheduled task created (4698) with **no** correlated fresh Type-3 logon — local
persistence by an attacker already on the box.
- **Fields:** host, user, task · **Throttle:** attacker_ip, host, task
- **Exclusions:** the *presence* of a correlated remote logon routes it to Lateral Movement: Scheduled Task instead. Gateway/loopback excluded on the logon-source trace.

### Service Creation (Local)
A service installed (7045) with **no** correlated fresh Type-3 logon — local
persistence. Same split logic as Scheduled Task Creation (Local).
- **Fields:** host, user, service · **Throttle:** attacker_ip, host, service
- **Exclusions:** correlated-remote-logon case routes to Lateral Movement: Service; driver-type services excluded; gateway/loopback on the logon trace.

### WMI Event Subscription Creation
A permanent WMI subscription (`__EventFilter` + consumer + binding) — fileless
persistence. One alert per creation.
- **Fields:** host, user, filter, consumer, binding · **Throttle:** attacker_ip, host, user
- **Exclusions:** None.

## Lateral movement

### Lateral Movement: MSSQL
A successful login to sql1/sql2 from another machine (Windows Auth or a SQL
login such as `sa`).
- **Fields:** host, user · **Throttle:** attacker_ip, host, user
- **Exclusions:** local-machine logins, the gateway `10.0.2.1`, `svc-sqlmonitor` from the indexer (`10.0.10.2`), `svc-web` from `web` (`10.0.2.5`), and the connection a linked server makes on the attacker's behalf (the linked-server hop).

### Lateral Movement: RDP
A remote-interactive logon (4624 Type 10) on a range host from a source other
than this project's control host. Fires on connect.
- **Fields:** host, user · **Throttle:** attacker_ip, host, user
- **Exclusions:** the gateway `10.0.2.1` and blank/`-` sources.

### Lateral Movement: Scheduled Task
A scheduled task created (4698) that **also** saw a fresh Type-3 logon — remote
task execution (atexec, `schtasks /s`).
- **Fields:** host, user, task · **Throttle:** attacker_ip, host, task
- **Exclusions:** the no-correlated-logon case is Scheduled Task Creation (Local). Gateway/loopback on the logon trace.

### Lateral Movement: Service
A service installed (7045) that **also** saw a fresh Type-3 logon — remote
service execution (PsExec).
- **Fields:** host, user, service · **Throttle:** attacker_ip, host, service
- **Exclusions:** the no-correlated-logon case is Service Creation (Local). Gateway/loopback on the logon trace.

### Lateral Movement: WinRM
A remote PowerShell/WinRM shell (WinRM/Operational event 91) from a source
other than the control host. On Server 2016 (dc1, sql1) the client comes from
Zeek conn_open and the account from the session's 4624.
- **Fields:** host, user · **Throttle:** attacker_ip, host, user
- **Exclusions:** the gateway `10.0.2.1`.

### Lateral Movement: WMI
A process spawned as a child of `WmiPrvSE.exe` (wmiexec / `Invoke-WmiMethod`),
correlated to the preceding remote logon for the source IP.
- **Fields:** host, user · **Throttle:** attacker_ip, host
- **Exclusions:** the gateway `10.0.2.1`.

## Linux

### Shadow Dump
`/etc/shadow` read by a real interactive login session on the `demo` host —
aftermath of local privesc. Tied to the SSH login via auditd session ID.
- **Fields:** host, user · **Throttle:** attacker_ip, host, user
- **Exclusions:** routine system processes (`unix_chkpwd`, `sshd-session`, `systemd`, `accounts-daemon`, `login`, `sudo`) and non-login sessions (`auid` unset).

## NTLM / coercion

### DNS Record Creation
A new DNS record (dnsNode) created under the `cyberhawks.lab` AD-integrated zone
(attacker-added record for a fake service / coercion target).
- **Fields:** user, name · **Throttle:** attacker_ip, name
- **Exclusions:** `SYSTEM` and machine accounts (all real records were provisioned at build time).

### Forced Authentication
A coercion RPC call (PetitPotam/DFSCoerce/PrinterBug/ShadowCoerce) captured by
RPC Firewall, with the caller's source IP, interface, and subject.
- **Fields:** host, type, user · **Throttle:** attacker_ip, host
- **Exclusions:** the secondary Zeek backstop (a DC making an outbound SMB connection) excludes DC-to-DC traffic.

### NTLM Authentication *(disabled)*
Any NTLM authentication whose source is neither a known range host nor the
control-host admin path.
- **Fields:** host, user · **Throttle:** attacker_ip, host, user
- **Exclusions:** the gateway `10.0.2.1` and all known range hosts. **Disabled** (`disabled: true`) — see its `disabled_reason`.

## Reconnaissance

### ARP Scan
One host broadcasting ARP requests for 5+ distinct addresses within 10s — local
subnet discovery (nmap `-sn`/`-PR`, arp-scan, netdiscover).
- **Fields:** hosts · **Throttle:** attacker_ip
- **Exclusions:** the gateways `10.0.2.1` and `192.168.1.1`.

### DHCPv6 Spoofing
A rogue DHCPv6 server reply (UDP src 547 → client 546) — mitm6/Inveigh. Nothing
in this range answers DHCPv6.
- **Fields:** mac, targets · **Throttle:** attacker_ip, mac
- **Exclusions:** None (any server reply is signal; the poisoner's MAC is reported since it otherwise appears only as a link-local address).

### Name Resolution Poisoning
A unicast reply to another host's LLMNR/mDNS/NBNS broadcast query — Responder /
Inveigh / pretender. Nothing legitimately answers these.
- **Fields:** target, protocols · **Throttle:** attacker_ip, target
- **Exclusions:** None by allowlist — the attacker is whoever answered; IPv6 link-local names are de-preferred when a usable name exists.

### Ping Sweep
One source pinging 5+ distinct hosts within 10s.
- **Fields:** hosts · **Throttle:** attacker_ip
- **Exclusions:** None.

### Port Scan
One source touching 15+ distinct ports on a host, or 6+ hosts on the same
port(s), within a 30s sliding window. Scoped to the range subnet (`10.0.2.*`).
- **Fields:** hosts, protocol, ports · **Throttle:** attacker_ip
- **Exclusions:** NTP (port 123), the gateway `10.0.2.1` as source, server-reply flows (history starting `H`), and reversed bad-checksum flows on ephemeral ports (≥49152). See `known_false_positives` for the full reversed-direction history.

## SQL Server

### EXECUTE AS Impersonation
A T-SQL `EXECUTE AS LOGIN` succeeding — on sql1 any login can impersonate `sa`
outright (any-domain-user → sysadmin).
- **Fields:** host, user, impersonated · **Throttle:** attacker_ip, host, user
- **Exclusions:** `NT SERVICE*` principals.

### Linked Server Execution
A SQL instance opening a connection to a linked server for a session (the moment
a query runs through a link). sql1's link to sql2 maps logins to a fixed `sa`.
- **Fields:** host, user, linked · **Throttle:** attacker_ip, host, user, linked
- **Exclusions:** None specific (correlation window only).

### xp_cmdshell Execution
`xp_cmdshell` invoked on a SQL instance — OS command execution from SQL Server.
- **Fields:** host, user, command · **Throttle:** attacker_ip, host, command
- **Exclusions:** `svc-sqlmonitor` and `NT SERVICE*`.

### xp_dirtree Execution
`xp_dirtree` invoked — filesystem enumeration / outbound UNC coercion from SQL
Server.
- **Fields:** host, user, path · **Throttle:** attacker_ip, host, path
- **Exclusions:** `svc-sqlmonitor` and `NT SERVICE*`.

## Weak authentication

### AS-REP Roast
A TGT request (4768) for an account with Kerberos pre-auth disabled (Pre-Auth
Type 0) — GetNPUsers / Rubeus asreproast.
- **Fields:** users · **Throttle:** attacker_ip
- **Exclusions:** None (type-0 pre-auth is itself the signal).

### Computer Password Spray
Any successful auth as `computer4$` (pre-Win2000 default password) or
`computer5$` (blank password) — placeholder objects with no real host.
- **Fields:** host, successes · **Throttle:** attacker_ip
- **Exclusions:** None (any success is signal; real machine accounts are not matched because only these two placeholders are targeted).

### Kerberoast
A service ticket (4769) for a user-account SPN — RC4-HMAC encryption, or 2+
distinct user-SPNs requested by one source in 5 minutes.
- **Fields:** users, encryption · **Throttle:** attacker_ip
- **Exclusions:** `krbtgt` and machine-account SPNs (`*$`) — normal background Kerberos.

### NetNTLMv1 Authentication
A named-account NTLM logon negotiated down to NTLMv1 (both DCs have
`LmCompatibilityLevel=1`).
- **Fields:** host, user · **Throttle:** attacker_ip, host, user
- **Exclusions:** `-`, `ANONYMOUS LOGON`, and machine accounts (`*$`) — constant baseline NTLMv1 traffic, not a distinct signal.

### Password Spray
One source failing auth against 5+ distinct non-machine accounts in 5 minutes
(4625 SMB + 4771 Kerberos), with any successes correlated in.
- **Fields:** host, successes · **Throttle:** attacker_ip
- **Exclusions:** machine accounts, `-`, `ANONYMOUS LOGON` as targets; an account with >2 successful logons from the source in the window is treated as an established session, not a spray hit.

### SMB Anonymous Object Enumeration
An unauthenticated (null-session) SAMR enumerate call (Users/Groups/Aliases)
against a DC — ANONYMOUS LOGON is in Pre-Win2000 Compatible Access here.
- **Fields:** host, method, objects · **Throttle:** attacker_ip, host
- **Exclusions:** None.

### Zone Transfer
An unauthenticated DNS AXFR against a DC (`SecureSecondaries=TransferAnyServer`).
- **Fields:** host · **Throttle:** attacker_ip, host
- **Exclusions:** None (no legitimate client issues AXFR; AD-integrated zones replicate via AD).

## Web application

### Database Credential Read (admin)
The `CyberHawksPortal` `Users` table read by anyone other than the app's own
`svc-web`-from-`web` context (leaked login reuse, or Windows-Auth readability).
- **Fields:** user · **Throttle:** attacker_ip, user
- **Exclusions:** `NT SERVICE*` and the app's own expected `svc-web` from the `WEB` host.

### Web Credential Read (Web.config.bak)
A successful HTTP GET of a config-backup file (e.g. `Web.config.bak`) on the
`web` host — IIS serves the `.bak` as plaintext, leaking the `svc-web`
connection string.
- **Fields:** file · **Throttle:** attacker_ip
- **Exclusions:** None (any 200 on a `.bak`/config-backup path is the leak being exploited).
