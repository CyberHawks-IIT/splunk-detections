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
