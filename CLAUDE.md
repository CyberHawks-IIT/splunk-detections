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
  order as `embed.additional_fields`. (The one exception is Pass-the-Ticket,
  whose ticket-reuse semantics report `origin`/`destination` rather than a
  single attacker IP; its `embed.attacker_field: destination` tells the
  Discord action which column to resolve to an attacker name.) The Discord
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
   admin, not directly accessible this session).
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
  second for `impersonated`/full-SPN. Zeek only decodes cleanly for
  router-crossing traffic (the default john-kali path), so `impersonated` is
  best-effort — the detection still fires on the 4769 signal when Zeek misses.
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

- **Every detection runs every minute over the events *indexed* in the
  previous minute, not the last minute of event time.** The base search
  carries the `` `detection_window` `` macro (`_index_earliest=-2m@m
  _index_latest=-1m@m`). A scheduled run's `now()` is its scheduled minute,
  so consecutive runs tile index time with no gap or overlap: every event is
  evaluated exactly once, however late it lands. This fixes a real,
  silent miss — the old searches used a `-1m..now` *event-time* window, but
  Zeek `conn` is written ~1 min after a flow ends (p90 ~1 min index lag) and
  Security events land up to ~50 s late, so a scan or logon whose events
  were indexed after its run's window closed was never evaluated by any run.
  The dispatch window (`dispatch.earliest_time=-4h`, `latest=+5m`, both from
  `build_app.py`'s `DEFAULT_SCHEDULE`) is only an outer bound on how late an
  event may arrive and still be seen; `+5m` also tolerates a host clock
  running a little fast. `build_app.py` supplies the schedule, so a YAML
  normally has **no `schedule:` block** — add one only to override (e.g.
  Certificate Request (HTTP) uses a window one minute further back for IIS
  delivery lag).
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
  System) — can't use the 1-minute `` `detection_window` `` alone. These use
  `earliest=-30m latest=+5m` (or `-30m` on the pieces) and the
  `` `in_detection_window(t)` `` macro to fire only when a matching group
  includes an event indexed in *this* run's minute, so each burst is judged
  whole, once, when a new event of it arrives — and boundary-straddling
  bursts that fixed `bucket`s used to split (and drop under threshold) no
  longer are. Recon burst counts moved from `bucket` to `streamstats
  time_window=...` (a true sliding window) for the same reason.
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
