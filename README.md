# Splunk Detections

Detection content — planned and (eventually) implemented — for the
[CyberHawks-IIT/cyber-range](https://github.com/CyberHawks-IIT/cyber-range)
Splunk instance.

## Status: design backlog, not implementation

[detections/backlog.md](detections/backlog.md) lists every planned
detection: the attacker behavior it targets, the log source/event ID(s) it
needs, and any open questions from design. **None of these are real, tested
Splunk searches yet.** A `ready` status means *the design is settled* —
not that working SPL exists. See [CLAUDE.md](CLAUDE.md) before adding any.

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
  detections/backlog.md   # every planned detection, by category
```

Once SPL is written and verified, the plan is a deployable Splunk app
(`app/default/savedsearches.conf`, macros, lookups) that `defense-tooling`'s
`splunk_indexer` role can drop straight into `$SPLUNK_HOME/etc/apps/` — same
pattern it already uses for the Zeek sourcetype mapping.

## Contributing a detection

1. Check `backlog.md` for the entry (or add one, matching the existing format).
2. Implement it and **actually run it** against the range — confirm it fires on the real technique, and ideally that it doesn't fire on benign activity.
3. Only then does it graduate out of the backlog — open an issue/PR to discuss where the real SPL should live.
