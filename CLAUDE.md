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

## Status

Design/backlog phase only — see `detections/backlog.md`. No real
implementation (SPL, saved searches, a deployable app) exists yet. See that
repo's README for the planned structure once implementation starts.

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
