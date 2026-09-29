# Splunk Detections

Detection content for the [cyber-range](https://github.com/CyberHawks-IIT/cyber-range)
Splunk instance. One saved search per attacker behavior, each one written and
**live-fire verified** against the real `cyberhawks.lab` range.

> **Setting up the whole range and monitoring?** Start with cyber-range's
> end-to-end guide,
> **[range-with-monitoring.md](https://github.com/CyberHawks-IIT/cyber-range/blob/main/docs/setup/range-with-monitoring.md)**.
> You don't copy anything by hand. defense-tooling's `splunk_indexer` role
> deploys this repo's `app/` into Splunk when you point `splunk_detections_app_src`
> at it.

## How the pieces fit

| Repo | Role |
|---|---|
| [cyber-range](https://github.com/CyberHawks-IIT/cyber-range) | The range these detections target: hosts, accounts, vulnerabilities |
| [defense-tooling](https://github.com/CyberHawks-IIT/defense-tooling) | Installs and configures the Splunk and Zeek stack, and deploys this content |
| **splunk-detections** *(this repo)* | The detection logic itself |

## How it's organized

- **[detections/backlog.md](detections/backlog.md)** is the design tracker. It
  lists every detection, the attacker behavior it targets, and the log source
  and event IDs it needs. A row is either `ready` (design settled: source, event
  ID, filtering) or `needs work` (an open question, see its notes). Implemented
  rows move to the "Implemented" section.
- **`detections/<category>/*.yml`** is one file per implemented detection. It
  holds the SPL plus a `verification` block recording exactly how it was
  live-fire tested. See any existing file for the schema (`name`, `id`,
  `search`, `description`, `known_false_positives`, `embed`, and so on).
- **`build/build_app.py`** compiles those YAMLs into
  `app/default/savedsearches.conf`. That file is generated, never hand-edited.
- **`app/`** is the deployable Splunk app that defense-tooling drops into
  `$SPLUNK_HOME/etc/apps/`.

```
splunk-detections/
  detections/
    backlog.md            # design tracker (planned + implemented index)
    <category>/*.yml      # one implemented detection each
  build/build_app.py      # detections/**/*.yml -> app/default/savedsearches.conf
  app/default/
    app.conf              # hand-maintained
    savedsearches.conf    # GENERATED, do not hand-edit
  CLAUDE.md               # running source of truth
```

The one-file-per-detection layout mirrors, at much smaller scope, how
[splunk/security_content](https://github.com/splunk/security_content) structures
its own content.

## Alerting

Every saved search is scheduled, so it shows under **Activity > Triggered Alerts**
in Splunk when it fires. **Discord alerting is optional and off by default.** The
committed `app/` carries no alert action. Turn it on from defense-tooling by
setting `discord_webhook_url`, which builds the app with `build_app.py --discord`
and installs the `discord_alert` action. See
[defense-tooling/docs/discord-alerting.md](https://github.com/CyberHawks-IIT/defense-tooling/blob/main/docs/discord-alerting.md).

## Contributing a detection

1. Find (or add) the entry in `backlog.md`.
2. Implement it and **actually run it** against the range. Confirm it fires on
   the real technique, and ideally that benign activity doesn't trip it.
3. Graduate it. Move its `backlog.md` row to "Implemented", add the YAML under
   `detections/<category>/`, run `python3 build/build_app.py`, and redeploy
   `app/` (via defense-tooling's `splunk_indexer` role, or directly for a quick
   iteration).

Read [CLAUDE.md](CLAUDE.md) before adding any. It carries the conventions, such
as never committing unverified SPL and the output field naming.
