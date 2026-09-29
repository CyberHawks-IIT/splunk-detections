# Splunk Detections

Detection content — planned and (eventually) implemented — for the
[CyberHawks-IIT/cyber-range](https://github.com/CyberHawks-IIT/cyber-range)
Splunk instance.

## Status: implementation in progress

[detections/backlog.md](detections/backlog.md) lists every planned
detection: the attacker behavior it targets, the log source/event ID(s) it
needs, and any open questions from design. A `ready` status means *the
design is settled* — not that working SPL exists yet for that entry. Entries
that do have real, verified SPL move to backlog.md's "Implemented" section
and get their own YAML file under `detections/<category>/`, compiled into
[app/default/savedsearches.conf](app/default/savedsearches.conf).
See [CLAUDE.md](CLAUDE.md) before adding any.

> **Setting up the whole range + monitoring?** Follow cyber-range's end-to-end
> guide:
> **[range-with-monitoring.md](https://github.com/CyberHawks-IIT/cyber-range/blob/main/docs/setup/range-with-monitoring.md)**.
> It covers deploying this content automatically — defense-tooling's
> `splunk_indexer` role drops this repo's `app/` into Splunk when you point
> `splunk_detections_app_src` at it, so you don't copy files by hand.

## How the pieces fit together

| Repo | Role |
|---|---|
| [cyber-range](https://github.com/CyberHawks-IIT/cyber-range) | The range these detections target — hosts, accounts, vulnerabilities |
| [defense-tooling](https://github.com/CyberHawks-IIT/defense-tooling) | Installs/configures the Splunk + Zeek stack these detections run on |
| **splunk-detections** *(this repo)* | The detection logic itself |

## Status legend

| Status | Meaning |
|---|---|
| `ready` | Log source + event ID(s) + filtering logic are settled. Not yet implemented. |
| `needs work` | Open question — see the entry's notes. |

## Structure

```
splunk-detections/
  README.md
  CLAUDE.md
  detections/
    backlog.md               # every NOT-yet-implemented detection, by category
    reconnaissance/*.yml      # one YAML file per implemented detection, by category
    .../*.yml                 # (more category folders as detections graduate)
  build/build_app.py          # compiles detections/**/*.yml -> app/default/savedsearches.conf
  app/default/app.conf            # deployable Splunk app, hand-maintained
  app/default/savedsearches.conf  # GENERATED -- do not hand-edit, see build/build_app.py
```

Modeled on (a much smaller-scoped version of) how
[splunk/security_content](https://github.com/splunk/security_content)
structures its own detections — one YAML file per detection rather than a
single giant config file, with a build step that compiles them into the
deployable artifact. See any file under `detections/reconnaissance/` for the
schema (name, id, search, description, known_false_positives, a
`verification` block recording exactly how it was live-fire tested, etc.).

`app/` is a deployable Splunk app that `defense-tooling`'s `splunk_indexer`
role can drop straight into `$SPLUNK_HOME/etc/apps/` — same pattern it
already uses for its own `dt_detection_content` app. Every saved search is
scheduled (visible firing under Activity > Triggered Alerts in Splunk web)
but has no alert *action* configured: Discord webhook alerting isn't wired
up yet (see CLAUDE.md), so nothing here reaches Discord or anywhere
external until that's built.

## Contributing a detection

1. Check `backlog.md` for the entry (or add one, matching the existing format).
2. Implement it and **actually run it** against the range — confirm it fires on the real technique, and ideally that it doesn't fire on benign activity.
3. Only then does it graduate out of the backlog: remove its `backlog.md`
   row, add a one-line pointer to `backlog.md`'s "Implemented" section, and
   add its own YAML file under `detections/<category>/` (see Structure
   above for the schema). Run `python3 build/build_app.py` to regenerate
   `app/default/savedsearches.conf`, and deploy the updated `app/` to the
   live Splunk indexer (`defense-tooling`'s `splunk_indexer` role, or
   directly for a quick iteration).
