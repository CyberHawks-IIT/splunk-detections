# Splunk Detections

Detection content for the CyberHawks cyber range's Splunk instance. This
file is the running source of truth for context and conventions, mirroring
[cyber-range](https://github.com/CyberHawks-IIT/cyber-range)'s own CLAUDE.md.

## What this repo is for

A durable, version-controlled record of detection design work — separate
from `cyber-range` (the range itself) and `defense-tooling` (the
infrastructure that runs Splunk/Zeek), because detection content has its
own lifecycle: it changes independently of and much more often than either
of those, and the people iterating on SPL don't need to touch Ansible to do
it.

## Origin

`detections/backlog.md` was built by reviewing the attacker actions
documented in `cyber-range`'s `ansible/VULNERABLE_RANGE_PLAN.md` (the
vulnerable-range design) against a library of ~70 attacker-action test
templates, identifying gaps, then iterating on log-source/event-ID design
for each one across several review rounds. Every entry reflects that
back-and-forth, not a first guess — the notes on tricky ones (LDAP query
volume, NTLM relay detection specificity, SAM/LSA remote-dump coverage)
capture real reasoning that would otherwise be lost.

## Detection design pass — alert embeds (2026-09-27)

Once these detections go live, alerts push to Discord via a webhook (each
embed: title, an Attacker field resolved from source IP, plus whatever
extra fields that detection needs). In preparation, every backlog.md
detection was run through a dedicated planning tool — the **Alert Embed
Planner**, a standalone Claude Artifact, not tracked in this repo — to
decide each one's embed title and fields. That pass surfaced real design
gaps and questions, not just naming, so `backlog.md` changed too:

- **Split, because they were really separate techniques:** Ping Sweep vs.
  Port Scan (ICMP vs. TCP/UDP); the old single SQL Server row into four
  (`xp_cmdshell`, `xp_dirtree`, `EXECUTE AS`, linked server); Logon script
  tampering vs. ScriptPath attribute tampering; and "Portal DB readable /
  weak admin password" into Web.config.bak credential leak vs. Portal
  database read (see below — these turned out to be two independent bugs).
- **Merged, because they're really one alert:** LDAP/LDAPS/ADWS query
  content collapsed into a single LDAP Query detection with a `protocol`
  field, since all three ultimately land in the same DC-side 1644 log.
- **Logic tweaks from the review:** Kerberoast now keys on RC4-HMAC or a
  burst of SPN requests; Anonymous logon retargeted to the specific
  `dce_rpc.log` RPC calls (`LsarLookupSids`, `SamrEnumerateUsersInDomain`)
  instead of the bare 4624; DCSync and ADCS RPC/ICPR issuance both gained
  exclusions for legitimate DC-to-DC and machine-self-enrollment traffic;
  the two remote-vs-local scheduled-task/service pairs gained the
  correlation (presence of a preceding remote logon) that actually
  distinguishes them, since neither had one before.
- **Portal DB readable, root-caused:** dug into `cyber-range`'s actual
  `web_portal` role rather than guessing. IIS was given a MIME-type mapping
  for `.bak`, so a stray `Web.config.bak` next to the live config is
  servable over HTTP and leaks the real `svc-web` SQL connection string —
  one detection. Independently, `CyberHawksPortal` is *also* readable via
  Windows Auth by any domain user, misconfig unrelated to the leak —
  a second detection that fires on either path. "Weak admin password"
  isn't its own row: the admin's hash (`SHA1('abc123')`, username `admin`)
  is a static fact you get from either DB-read path, not a separate live
  event.
- **Rubeus ticket enumeration, researched and deliberately left
  undesigned:** confirmed the LSASS memory-access row is mimikatz-only —
  Rubeus's own-session `triage`/`dump`/`klist` go through the legitimate
  `LsaCallAuthenticationPackage` LSA API (same as native `klist.exe`), not
  a memory read on `lsass.exe`, so they were never covered. There's no
  native Windows telemetry for that LSA API call, and every fallback
  surface considered (Sysmon Event 1 command-line matching, PowerShell
  Script Block Logging for a reflectively-loaded copy) is narrow and
  evadable — so rather than fabricate a `ready` row around a weak signal,
  this is flagged as an open item in the LSASS row's note and left
  undesigned on purpose. Revisit if a stronger signal turns up.
- Confirmed against `defense-tooling`'s actual deployed config (not just
  assumed) that every log source these tweaks need — `dce_rpc.log`, every
  Windows event ID touched, `Directory Service`/1644 on the DCs — was
  already forwarded. No `defense-tooling` changes came out of this pass.

The two new Conventions below (Splunk alert name = embed title; SPL output
scoped to source IP + the planner's fields) came out of this same pass.

## Conventions

- **Never write SPL into this repo that hasn't been run and verified.** A
  `ready` status in `backlog.md` means the *design* is settled (source,
  event ID, filtering logic) — it is explicitly not a claim that working
  SPL exists. Don't "helpfully" fill that gap with a plausible-looking but
  untested search; that's worse than leaving it blank, since it reads as
  more trustworthy than it is.
- **Every detection targets something real and current in `cyber-range`.**
  If a detection's target (an account, a misconfiguration, a host) gets
  redesigned or removed from the range, update or remove the corresponding
  backlog entry rather than leaving it stale.
- **Log sources here assume `defense-tooling`'s stack.** Sourcetype names
  (`zeek:conn`, `WinEventLog:...`) match what that repo's Splunk add-ons
  produce. If you change the monitoring stack (different Zeek add-on,
  different Windows TA), audit `backlog.md` for sourcetype references that
  no longer match.
- **Don't guess at Splunkbase app names or fabricate download URLs.** If a
  detection needs a new add-on that isn't already in
  `defense-tooling/docs/add-ons.md`, flag it there (with a note on why)
  rather than assuming a specific package exists.
- **A detection's Splunk alert name is its Discord embed title, not this
  file's `Detection`-column wording.** The Alert Embed Planner (a
  standalone tool, not tracked in this repo) is the source of truth for
  each detection's human-facing name — that title is what the saved search
  should be named and what actually shows up in Discord. This file's
  `Detection` column stays a technical/descriptive label (matching the
  attacker-action language from `cyber-range`'s `VULNERABLE_RANGE_PLAN.md`)
  and is under no obligation to match the embed title word-for-word — they
  serve different readers.
- **A detection's SPL output is scoped to what the embed actually needs.**
  Once real SPL is written (not yet — see Status below), the search's
  final `table`/`fields` should be exactly: the source IP (for the
  Attacker lookup) plus whatever "additional fields" are configured for
  that detection in the Alert Embed Planner — not every field the raw
  event happens to carry. Keep the search's field list and the planner's
  field list in sync, the same way `defense-tooling`'s
  `splunk_uf_monitor_files` and this file's Zeek-logs table stay in sync.
  **The output-column names are standardized (2026-09-29):** the attacker
  source IP (the Attacker-lookup key) is always the first column and named
  **`attacker_ip`**; the targeted host is always **`host`**. Every `| table`
  is exactly `attacker_ip` + the planner's additional fields, in the same
  order as `embed.additional_fields`. (Pass-the-Ticket was formerly an
  exception here -- it reported `origin`/`destination` with an
  `embed.attacker_field: destination` -- but as of 2026-09-30 it conforms to
  the standard: `attacker_ip` is the reusing TGS-REQ source, plus `origin`
  (the AS-REQ host), `user`, and `service`.) The Discord
  embed description is "Full Name (attacker_ip)", resolved on the indexer
  from defense-tooling's Proxmox-derived attacker directory (see its
  `docs/discord-alerting.md`), so `attacker_ip` must be a raw source IP.
  **Host and user values are normalized (2026-09-30):** every host-valued
  output (`host`, `hosts`, Name Resolution Poisoning's `target`,
  Pass-the-Ticket's `origin`) is the short, lowercase hostname (`dc1`, not
  `DC1.cyberhawks.lab` or `WEB`), with range IPs mapped to names via
  `known_range_hosts` (non-range IPs stay IPs). Every user-valued output
  (`user`, `users`, `impersonated`, `successes`) is the bare account name
  (`dsmith`, not `CYBERHAWKS\dsmith` or `dsmith@cyberhawks.lab`; machine
  accounts keep their `$`). Each search does this in a standard `eval ...
  mvmap(...)` pair just before its final `| table`; copy it from any
  existing detection. `attacker_ip` always stays a raw IP (it's the Discord
  lookup key), and AD object DNs (`target` on DACL/RBCD/Shadow Credential)
  are left as DNs.
- **Zeek fields in SPL use underscores, not the dotted Zeek/CIM
  convention.** `id.orig_h`, `id.resp_h`, `id.resp_p`, etc. as written in
  this file's prose (and in Zeek's own docs) are `id_orig_h`, `id_resp_h`,
  `id_resp_p` in actual search syntax — Splunk silently normalizes dots to
  underscores for the search-time delimiter extraction this project's Zeek
  fields use (not `Splunk_TA_zeek`'s own `INDEXED_EXTRACTIONS`, which
  doesn't work against this range's real data — see `defense-tooling`
  CLAUDE.md's "Zeek sourcetype/field-extraction incident" for why). Verify
  a field's real extracted name with `| fieldsummary` before assuming the
  dotted form works.
- **One YAML file per detection, not one giant savedsearches.conf.**
  Modeled on (a much smaller-scoped version of) how
  [splunk/security_content](https://github.com/splunk/security_content)
  structures its own detections — a `detections/<category>/<slug>.yml` per
  detection (schema: `name`, `id`, `search`, `description`,
  `known_false_positives`, a `verification` block, etc. — see any existing
  file for the exact fields), compiled by `build/build_app.py` into
  `app/default/savedsearches.conf`. That generated file is never
  hand-edited. This was a deliberate choice (2026-09-27, mid-implementation)
  over the single-file approach the first two detections (Ping Sweep, Port
  Scan) originally shipped with — one file per detection scales far better
  once dozens exist, and keeps each detection's SPL, tuning history, and
  verification evidence together in one reviewable place instead of
  scattered across a shared file's stanzas.

## SAM/LSA dump detection: two techniques, only one splits by hive (2026-09-27)

While live-testing the SAM/LSA hive-dumping detections on `workstation`
(Defender real-time monitoring disabled first, per the user's ask), found
that the classic `reg save HKLM\SAM ...` technique produces **no usable
telemetry at all** under this project's original design (4656/4663 SACLs on
the registry key + file), and required real infrastructure fixes before it
produced anything:

1. `RegSaveKeyEx`'s backup-privilege codepath never trips the ordinary
   Registry/File System SACLs — confirmed zero 4656/4663 for `reg.exe`
   even with correct SACLs and audit subcategories. Windows' real signal
   for this is Privilege Use (4673/4674), not Object Access.
2. Enabling "Sensitive Privilege Use" auditing alone wasn't enough either —
   Windows separately gates *all* backup/restore-privilege auditing behind
   an LSA registry value, `FullPrivilegeAuditing`
   (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`), which needs a **reboot**
   to take effect (LSA reads it once at startup). cyber-range's
   `detection_logging` role now sets this value for future provisioning
   (`configure_audit_policy.ps1`); this session applied it live via a
   reboot on every reachable range host except ca/sql2 (LAPS-managed local
   admin, not directly accessible that session). **Update 2026-09-30: ca and
   sql2 now confirmed enabled AND live** — reached via the qemu-guest-agent
   (`qm guest exec 322/325`), both show `FullPrivilegeAuditing=01` +
   `Sensitive Privilege Use=Success and Failure`, and a `reg save HKLM\SAM` as
   SYSTEM produces SeBackupPrivilege 4674s (which are suppressed unless the
   value is live at boot), so no further reboot is needed. They were
   reprovisioned with the role's value since the original session.
3. Even with both of those, `defense-tooling`'s Windows forwarder ships an
   explicit per-channel Event ID whitelist for the Security log that
   simply didn't include 4673/4674 — added them
   (`group_vars/splunk_forwarders_windows/monitor.yml`).
4. Once all three were fixed, 4674 turned out extremely noisy from a
   *different* direction: ordinary software (Splunk's own forwarder
   binaries, Edge WebView, Teams, the Widgets dashboard app) routinely
   exercises backup/restore privilege — 17,000+ events from `splunkd.exe`
   alone in one hour. Scoped to `Process_Name=reg.exe` to cut through it.
5. **Real, durable limitation, not a config gap:** the 4674 event this
   produces never names the *source* registry key (only an object-less
   privilege check, or the destination file `reg.exe` is writing to, which
   is attacker-controlled). So this technique cannot be split into
   separate SAM/LSA detections without command-line matching — which the
   user explicitly ruled out ("never make command line based detections -
   all detections should be action based"). It ships as one merged
   detection, **SAM/LSA Dump: Registry Export**.
6. The *other* local dumping technique — direct `RegQueryValueEx`/
   `RegEnumKeyEx` enumeration (what SYSTEM-context tooling and remote
   SAMR/LSARPC-style access actually do under the hood) — does **not**
   use backup privilege at all, goes through the ordinary Registry SACL
   path, and correctly names the real key
   (`\REGISTRY\MACHINE\SAM\...` vs `\REGISTRY\MACHINE\SECURITY\...`). This
   one splits cleanly: **SAM Dump: Registry Query** and
   **LSA Dump: Registry Query**.

Net result: 3 saved searches instead of 2 for this backlog area (plus
DPAPI Dump, which needed no fix and worked as originally designed), named
to make the technique split explicit rather than folding it into one
ambiguous "SAM Dump (Local)"/"LSA Dump (Local)" pair. The NTDS.dit
extraction row in `backlog.md` is flagged as needing the same verification
before assuming its SACL-only design actually fires — `ntdsutil`'s IFM path
plausibly hits the same backup-privilege gap.

## LDAP query logging: 1644 thresholds are 1, not 0 (2026-09-29)

Asked to get full LDAP query content for LDAPS and ADWS too. Findings, all
confirmed live on dc1 (Server 2016):

- **The 1644 layer was silently partial.** cyber-range set the NTDS
  search thresholds to 0 intending "log everything," but 0 means "use the
  default" (30 s / 10,000 visited / 1,000 inefficient) — only slow or
  unindexed searches logged, over *any* protocol. Indexed recon
  (`(sAMAccountName=x)`, `(servicePrincipalName=*)`) never appeared. Fixed
  to 1 for all three (read live, no NTDS restart).
- **LDAPS and ADWS both log to 1644** — the earlier "verified gaps" were
  artifacts of the thresholds. LDAPS logs the real client IP:port. ADWS
  runs searches over loopback, so it logs client `[::1]` with the real
  remote user; the DC's 4624 for ADWS has no source IP, so attribution is
  a time join to Zeek's 9389 session (same approach Huntress published).
- **Alternatives considered and rejected:** there's no server-side "LDAP
  Operational" channel on these DCs; `Microsoft-Windows-LDAP-Client/Debug`
  (Sigma's `win_ldap_recon`) is client-side only — it would never see
  john-kali. Elastic/Splunk-content LDAP rules use 4662 attribute reads or
  process/command-line telemetry, neither of which gives query text (and
  the latter violates the action-based rule).
- **Volume (free tier, 500 MB/day):** full 1644 logging is ~52 MB/day, almost
  all the DCs' own searches — dropped at the forwarder (DC machine accounts +
  `UNAVAILABLE` internal ops only). While measuring, found a far bigger
  problem: the forwarder's own 4673/4674 feedback loop (reading the
  Security log with SeBackupPrivilege under `FullPrivilegeAuditing`) was
  ~29 GB/day; blacklisted at the forwarder for the UF's own binaries.
- **Zeek `_time` is not the connection time.** It's near index time,
  minute-rounded; the real start is the `ts` field. Any SPL that needs
  sub-minute Zeek timing must use `ts`.

## S4U delegation: the impersonated user is only in Zeek, not 4769 (2026-09-29)

Added `Delegation: S4U2Self` and `Delegation: S4U2Proxy` (the range configures
`sql2$` with protocol transition / T2A4D → `cifs/dc1`). Findings, all
confirmed live from john-kali:

- **Windows 4769 does NOT carry the impersonated principal.** In both the
  S4U2Self and S4U2Proxy 4769 events, `Account Name` is the delegating
  *service* (`sql2$`), never the impersonated user; the 4768 TGT is also for
  `sql2$`. The impersonated user ("who the ticket is for") rides in
  PA-FOR-USER and Server 2016 simply doesn't log it. This matches every
  public rule (Sigma/SpecterOps/Elastic are all 4769-only and note they
  can't recover it). **Zeek `kerberos.log` DOES surface it** as the TGS
  request's `client` field (plus the full SPN in `service`, e.g.
  `cifs/dc1.cyberhawks.lab` vs Windows' bare `DC1$`). So both detections use
  Windows 4769 as the reliable trigger and join Zeek on attacker IP + event
  second for `impersonated`/full-SPN. **`impersonated` is now recovered on
  every attacker path** (2026-09-30): the earlier "router-crossing only,
  best-effort" caveat was a symptom of the mirror sensor discarding
  checksum-offloaded packets before L4 reassembly — same-vnet Kerberos (and
  DCE-RPC/LDAP) produced no `kerberos.log` at all, only pfSense-re-checksummed
  router-crossing traffic decoded. Fixed by `redef ignore_checksums = T` on
  the Zeek sensor (see the "Mirrored capture: ignore_checksums" note below);
  verified with same-vnet (10.0.2.10) and router-crossing (john-kali) TGS
  both decoding the `client` field. The detection still falls back to the
  4769 signal alone if Zeek ever misses a single flow.
- **S4U2Proxy signal:** 4769 with `Transited Services` populated (blank on
  every ordinary TGS; zero in 24h baseline). `Transited Services` is not
  auto-extracted — `rex` it from `_raw` (the value is on the line *after* the
  label, so `\s*` must cross the newline).
- **S4U2Self signal:** 4769 self-reference (requesting account == target
  service). This alone is noisy — machine accounts self-request constantly as
  legit local Kerberos (baseline `ca$` 42×/day, DCs over `::1`) — but always
  from the host's **own IP or loopback**, so the real signal is a
  self-reference from a *foreign* IP (own IP resolved via `known_range_hosts`,
  loopback excluded).
- **Pairing/dedup keys on identity, not time.** When a Self and Proxy come
  from the same operation they share the same impersonated principal and
  requesting account (and a Windows Logon GUID). S4U2Self is suppressed only
  when an S4U2Proxy exists for the same `(attacker_ip, requesting user,
  impersonated principal)` — so a *different* S4U2Self in the same window
  (different impersonated user, or `getST -self` with no proxy) still fires.
  When `impersonated` can't be recovered (Zeek miss), the Self is not
  suppressed rather than dropped on an unverifiable match.

## Per-attempt alerting, index-time windows, shared macros (2026-09-30)

A pass over all 49 detections for two questions the user asked: can each be
simplified without losing accuracy, and does each fire *separately per
attacker* when several run the same technique in a short window. Three
mechanisms came out of it; they are now the standard shape for every
detection and for anything added later.

- **Every detection runs over the events *indexed* in a recent window, not
  the last minute of *event* time.** The base search carries the
  `` `detection_window` `` macro. This fixes a real, silent miss — the old
  searches used a `-1m..now` *event-time* window, but Zeek `conn` is written
  ~1 min after a flow ends and Security events land up to ~50 s late, so a
  scan or logon whose events were indexed after its run's window closed was
  never evaluated by any run. **NOTE (superseded 2026-09-30 by "Sub-minute
  dispatch" below):** the window was originally `-1m@m..@m`, a minute-snapped
  slice that, dispatched once a minute, tiled index time exactly (every event
  evaluated exactly once). It is now a rolling `-90s` window dispatched every
  15 s, so runs overlap and an event is evaluated several times; fire-once is
  now guaranteed by the throttle, not the window. The dispatch window
  (`dispatch.earliest_time=-4h`, `latest=+5m`, both from `build_app.py`'s
  `DEFAULT_SCHEDULE`) is only an outer bound on how late an event may arrive
  and still be seen. `build_app.py` supplies the schedule, so a YAML normally
  has **no `schedule:` block**.
- **One alert per attempt, keyed on identity, via per-result throttling.**
  Each saved search sets `alert.digest_mode = 0` (Splunk fires the action
  once per result row) and `alert.suppress = 1` on the YAML's **`throttle`**
  field list for `alert.suppress.period` (default 5m). The throttle key is
  the columns that identify one attempt — the attacker plus the target/object
  (`attacker_ip` + e.g. `task`, `service`, `id`, `target`, `command`, or just
  `attacker_ip` for a burst technique like a scan or spray). So two attackers,
  or one attacker against two objects, are distinct rows and distinct alerts;
  the throttle only stops the *same* attempt re-alerting as its later events
  trickle in or its burst is re-evaluated. `throttle` is a required YAML
  field (`build_app.py` enforces it). The Discord action honours this: with
  `action.discord_alert.param.per_result = 1` it posts only the row the
  invocation is for (see defense-tooling `discord_alert.py`), so each fired
  attempt is its own embed and the per-search throttle governs repeats.
  **Firing separately per attacker is structural** — every `| stats` groups
  `by attacker_ip` (+ object) and every `| table` leads with it — not a
  timing accident; verified live with two concurrent attackers and a
  3-row probe (3 IPs → 3 independently-throttled embeds).
- **Threshold/pair detections search a wider event-time span and gate on a
  freshly-indexed event.** A detection that must see an attempt's
  *neighbouring* events to judge it — a burst threshold (scan, spray,
  Kerberoast), a query/reply pair (Name Resolution Poisoning), or a
  two-log pair indexed apart (Service Creation's 4697 in Security + 7045 in
  System) — can't use the short `` `detection_window` `` alone. These use
  `earliest=-30m latest=+5m` (or `-30m` on the pieces) and the
  `` `in_detection_window(t)` `` macro to fire only when a matching group
  includes a freshly-indexed event, so each burst is judged whole when a new
  event of it arrives — and boundary-straddling bursts that fixed `bucket`s
  used to split (and drop under threshold) no longer are. Recon burst counts
  moved from `bucket` to `streamstats time_window=...` (a true sliding window)
  for the same reason. (Under the sub-minute dispatch below, a fresh burst
  passes this gate on several consecutive runs; the throttle collapses them.)
- **Shared macros replace the copy-pasted blocks** (`app/default/macros.conf`,
  hand-maintained like `build_app.py`, not generated): `` `detection_window` ``,
  `` `in_detection_window(t)` ``, `` `subject_session` `` (host_key +
  session_id off a Windows Security event), `` `logon_source` `` (the
  4624 `Logon_ID`→`Source_Network_Address` trace + host-IP fallback that ~20
  Windows detections shared verbatim), and `` `normalize_host(field)` `` /
  `` `normalize_user(field)` `` (the standard output-normalization `eval
  mvmap` pairs). Use them instead of re-pasting; they are the accuracy-neutral
  half of the "simplify" answer. The macros are in the app's `default/`, so
  they resolve for the app's own searches with no metadata export.

## Sub-minute dispatch: 15s latency without losing fire-once (2026-09-30)

The user asked to get alerts into Discord faster without sacrificing accuracy
(still one alert per attempt). Latency was measured end to end and cut at every
stage. The repo/live state is authoritative; this is the "why".

- **The dominant delay was the once-a-minute scheduler.** Splunk cron can't go
  below 1 minute, so an event waited 0–60 s (avg ~30 s) for the next run. A
  small dispatcher now fires every detection every 15 s. It lives with the app
  (`app/bin/dispatch_detections.py`) and runs as a systemd service on the
  indexer (`cyberhawks-dispatch`, deployed by defense-tooling's `splunk_indexer`
  role with a 0600 `local/dispatcher.conf` of REST creds). It POSTs each
  enabled+scheduled saved search to `saved/searches/<name>/dispatch` with
  `trigger_actions=1` — the same alert path the scheduler uses, so throttling
  and the Discord action work identically (verified live). It fires at
  :15/:30/:45; Splunk's own 1/min cron covers :00 **and stays on as a
  fallback** — if the dispatcher stops, every detection is still evaluated once
  a minute.
- **Fire-once now comes from the throttle, not the window.** The old
  `-1m@m..@m` window tiled index time exactly-once *because* it ran once a
  minute. Dispatched every 15 s that no longer holds, so `` `detection_window` ``
  became a **rolling `_index_earliest=-90s`** (90 > the 60 s fallback gap, so
  two consecutive 1/min fallback runs overlap and leave no hole). Overlapping
  runs evaluate each event ~6×; `alert.suppress` on the `throttle` fields
  collapses those to one alert per attempt. The throttle period (5m) ≫ the 90 s
  an event stays in the window, so an attempt is never re-alerted after the
  window rolls past it. Verified live: a port scan and a `Web.config.bak` read
  each produced exactly one Discord fire (`fired=1` once, then `suppressed=1` on
  every later run), ~11–13 s after the action. `` `in_detection_window(t)` ``
  likewise became `t >= now-90s`.
- **Concurrency.** ~49 searches dispatched at once would overrun the default
  historical-search cap and an over-cap dispatch *fails* (a detection silently
  skips that cycle). `app/default/limits.conf` raises `[search]
  base_max_searches` so the cap is ~90 on the 16-core indexer, and
  `[scheduler] max_searches_perc = 100` stays. The indexer was resized to **16
  cores / 16 GB** (Proxmox CT 510; vm-templates `debian-containers.md`), and
  internal indexes (`_audit`/`_internal`/`_introspection`) got size caps in
  defense-tooling's `dt_detection_content_indexes.conf` because ~200 runs/min
  write a lot of audit/scheduler data.
- **Ingestion delays cut at the source.** (1) **Zeek** UDP/ICMP flows were held
  for the 1-min `udp/icmp_inactivity_timeout` before conn.log wrote them (~62 s
  for Ping Sweep, Name Resolution Poisoning, UDP scans); dropped to 5 s, then
  (same day, second pass) **all** of Zeek's flow-end holds — UDP/ICMP
  inactivity plus TCP's unanswered-SYN, RST and FIN-close delays, 5 s each by
  default — went to **1 s**, and `Log::flush_interval` 1 s → 250 ms
  (`zeek_sensor` role's `cyberhawks.zeek`). Measured with the same john-kali
  scan before/after: index lag TCP S0 5.8 → 2.3 s, ICMP 7.0 → 3.1 s; Port Scan
  posted 10.9 → 5.0 s after the scan, Ping Sweep 10.7 → 4.7 s. Record volume
  was unchanged (~60 TCP flows/min background). Splitting a flow with a >1 s
  gap into two records is harmless — those detections count distinct
  hosts/ports or pair by timestamp. An open-time log (like `conn_open`) was
  considered for scans and rejected: `connection_established` never fires for
  the closed/filtered ports that make up most of a scan, and Port Scan's
  `history` filters need the finished flow. (2) **SQL** DB Connect polled
  every 60 s; now **5 s** (`splunk_dbconnect_mssql_poll_interval`; each poll is
  ~60–90 ms). (3) **IIS** was the worst: HTTP.SYS buffers the W3C log *files*
  up to ~60 s and **neither `DisableLogBuffering` nor IIS 10's
  `flushByEntryCountW3CLog` changes that** (both tested live — the earlier note
  that DisableLogBuffering gave ~5 s was wrong). Fixed by logging IIS requests
  to **ETW** as well (`logTargetW3C = File,ETW` + enabling the
  `Microsoft-IIS-Logging/Logs` channel, cyber-range `detection_logging`), which
  indexes each request in ~1 s; the forwarder now ships that channel instead of
  the files (defense-tooling web/ca `host_vars`, and the forwarder's service
  account was granted read on the channel). `DisableLogBuffering` is still set
  (harmless, keeps the on-host files current). Web Credential Read and
  Certificate Request (HTTP) consume the ETW events (same `cs_uri_stem`/`c_ip`/
  … field names); Cert Request (HTTP) dropped its extra-minute window since IIS
  now beats the 4887.
- **Latency budget after all this** (event → Discord): Windows/Sysmon/Linux
  ~15–25 s, IIS ~11 s, Zeek conn (TCP/UDP/ICMP) ~5–20 s (was ~100 s for
  UDP/ICMP), SQL ~15–25 s. The floor is now dispatch cadence (≤15 s) + run
  start/exec + the source's own index lag, not the minute scheduler.
- **Discord embeds escape markdown.** Field values and the attacker line are
  backslash-escaped by defense-tooling's `discord_alert.py`, so event data like
  an LDAP filter `(cn=*svc_*)` shows literally instead of turning into italics
  (2026-09-30). Titles and field names are ours and stay unescaped — don't put
  markdown characters in a saved-search name or output-column name.
- **Non-SPL changes, so the snapshot cycle is owed** for 510 (cores/limits/
  dispatcher/db poll), 511 (Zeek timeouts), web and ca (IIS ETW). See the
  infra-fix snapshot workflow.

## Mirrored capture: ignore_checksums (2026-09-30)

Investigating why the S4U `impersonated` field was "best-effort" turned up a
much larger, silent hole: **the Zeek sensor was emitting no `kerberos.log` at
all, and only sporadic `dce_rpc.log`/`ldap.log`**, while `conn.log` logged
every flow normally. Root cause: sensor 511 analyzes packets mirrored from
every guest tap, and the range's virtio NICs offload checksum computation, so
mirrored copies carry incomplete/blank checksums. Zeek discards packets with
invalid checksums *before* L4 reassembly by default — so `conn.log`
(header-only) is unaffected, but every application-layer analyzer that needs
reassembled payload (Kerberos, DCE-RPC, LDAP-over-TCP) sees nothing. Only
router-crossing traffic decoded, because pfSense recomputes checksums as it
routes — which is exactly why the S4U note read "Zeek only decodes cleanly for
router-crossing traffic." It was never an S4U-specific limit; it degraded
every same-vnet application-layer signal.

- **Fix:** `redef ignore_checksums = T;` in the `zeek_sensor` role's
  `cyberhawks.zeek` (applied live via `zeekctl deploy` and committed to
  defense-tooling). On a mirror/IDS sensor the checksums are not ours to
  validate — this is the standard SPAN-capture setting.
- **Verified:** after the fix, `kerberos.log` decodes on both a same-vnet
  path (test, 10.0.2.10 → dc1) and the router-crossing path (john-kali), with
  the `client` principal populated; Splunk `zeek:kerberos` immediately began
  showing real same-vnet domain Kerberos (web→dc2 for bsmith/rsmith, both DCs)
  where it had been empty for a week.
- **Implication for the validation pass:** any detection whose signal is a
  Zeek application-layer log (S4U `impersonated`, LDAP Query's Zeek 9389/ADWS
  join, Anonymous Logon's `dce_rpc` `LsarLookupSids`/`SamrEnumerateUsersInDomain`
  calls, NTLM relay specifics) was decode-starved for same-vnet launches before
  this and should be re-verified now that it isn't. The "same-vnet
  double-capture gap" framing in earlier notes was a misdiagnosis — conn.log
  shows exactly one record per uid (no double-capture); the cause was checksums.
- **Snapshot owed** for 511 (this joins the Zeek-timeouts change already owed
  there).

## Status

Implementation phase started 2026-09-27 (step 5 of the monitoring rollout
plan — see below). `detections/backlog.md` entries move here as their SPL is
written and verified against the live range, per the README's "Contributing
a detection" process. See `defense-tooling` CLAUDE.md's "Zeek sourcetype/
field-extraction incident" for a real infrastructure bug found and fixed
while starting this phase (every Zeek log was landing with no field
extraction at all) before any detection SPL could be tested.

## Monitoring rollout plan (2026-09-27)

This repo is **step 5** of a 5-step plan documented in full in
`cyber-range`'s CLAUDE.md under "Monitoring rollout plan" — that's the hub;
this note is just the pointer. Steps 1-4 (installing forwarders, turning on
the log sources this backlog depends on, minimal forwarding, and organizing
the data in Splunk) happen in `cyber-range` and `defense-tooling` first —
starting real implementation here before that data is actually flowing
means writing SPL against nothing, which is exactly the kind of
unverifiable "trust me" content the Conventions section above says not to
add.
