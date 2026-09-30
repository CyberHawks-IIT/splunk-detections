#!/usr/bin/env python3
"""Compile detections/**/*.yml into app/default/savedsearches.conf.

Mirrors (a much smaller-scoped version of) how splunk/security_content's
contentctl builds individual detection YAML files into a deployable app --
see splunk-detections CLAUDE.md. Run this after adding/editing any
detection YAML; do not hand-edit savedsearches.conf, it's generated.
"""
import argparse
import glob
import os
import sys

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DETECTIONS_GLOB = os.path.join(REPO_ROOT, "detections", "**", "*.yml")
OUTPUT_PATH = os.path.join(REPO_ROOT, "app", "default", "savedsearches.conf")

REQUIRED_FIELDS = ["name", "id", "search", "description", "verification", "throttle"]

# Every detection runs every minute and evaluates the events indexed in the
# `detection_window` macro's one-minute index-time window (see
# app/default/macros.conf), so the event-time range below is only an outer
# bound on how late an event can arrive and still be evaluated. latest is in
# the future so a host whose clock runs a little fast isn't silently ignored.
# A detection can override any of these with its own `schedule:` block.
DEFAULT_SCHEDULE = {"cron": "* * * * *", "earliest": "-4h", "latest": "+5m"}
# How long a fired attempt stays throttled (see render_stanza).
DEFAULT_THROTTLE_PERIOD = "5m"

HEADER = """\
# GENERATED FILE -- do not hand-edit. Run build/build_app.py after changing
# any file under detections/**/*.yml, which is the actual source of truth.
#
# Each stanza name is a technical/descriptive label (matching backlog.md's
# `Detection` column) -- NOT the Discord embed title. The Alert Embed
# Planner (see CLAUDE.md) is the source of truth for each detection's
# human-facing name; the corresponding YAML's embed.title notes this is
# still TBD for most entries.
#
# Scheduled (disabled = false in the YAML -> disabled = 0 here) so each one
# is visible under Activity > Triggered Alerts in Splunk web when it fires.
# Each result row is its own alert, throttled on the YAML's `throttle` fields.
#
# Discord alerting: build with --discord to also wire each search to the
# `discord_alert` custom alert action (defense-tooling installs that action
# and the webhook URL when a Discord webhook is configured). Without --discord
# (the default, and the committed app/) no alert action is configured, so this
# app is inert as far as Discord goes -- nothing reaches Discord until you both
# build with --discord AND deploy defense-tooling's discord_alert action.
"""


def load_detections():
    detections = []
    for path in sorted(glob.glob(DETECTIONS_GLOB, recursive=True)):
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        if doc is None:
            continue
        missing = [field for field in REQUIRED_FIELDS if field not in doc]
        if missing:
            sys.exit(f"{path}: missing required field(s): {', '.join(missing)}")
        if doc.get("status") != "production":
            continue  # only verified/graduated detections become saved searches
        doc["_source_path"] = os.path.relpath(path, REPO_ROOT)
        detections.append(doc)
    return detections


def render_search(search_text):
    lines = search_text.rstrip("\n").split("\n")
    return "\\\n".join(lines)


def render_stanza(d, discord=False):
    search = render_search(d["search"])
    description = " ".join(d["description"].split())
    schedule = {**DEFAULT_SCHEDULE, **(d.get("schedule") or {})}
    throttle_fields = d["throttle"]
    if isinstance(throttle_fields, str):
        throttle_fields = [throttle_fields]
    disabled = "1" if d.get("disabled", True) else "0"
    # A disabled detection keeps its whole stanza (disabled = 1), so it can be
    # switched back on by flipping the YAML's `disabled` without rewriting it.
    # Neither Splunk's scheduler nor the 15s dispatcher runs a disabled search.
    note = ""
    if disabled == "1" and d.get("disabled_reason"):
        note = f"# Disabled: {' '.join(d['disabled_reason'].split())}\n"
    stanza = (
        f"{note}"
        f"[{d['name']}]\n"
        f"search = {search}\n"
        f"description = {description}\n"
        f"cron_schedule = {schedule['cron']}\n"
        f"dispatch.earliest_time = {schedule['earliest']}\n"
        f"dispatch.latest_time = {schedule['latest']}\n"
        f"enableSched = 1\n"
        f"disabled = {disabled}\n"
        f"alert.severity = 4\n"
        # Trigger only when the search returns results. These are the
        # savedsearches.conf keys; the alert_type/alert_comparator/
        # alert_threshold names this build used before are the web UI's REST
        # parameters, which the conf file silently ignores, so every run of
        # every search counted as triggered (found 2026-09-30 once the Discord
        # action ran on each of those phantom triggers).
        f"counttype = number of events\n"
        f"relation = greater than\n"
        f"quantity = 0\n"
        # Always list fired alerts under Activity > Triggered Alerts. The
        # default (auto) defers to the actions' track_alert, and discord_alert
        # ships track_alert = 0, so wiring Discord would otherwise hide them.
        f"alert.track = 1\n"
        # Continuous scheduling: when a run is delayed (the scheduler's
        # concurrency cap is reached), run it later over its own window
        # instead of skipping it. With the default (1) Splunk silently skipped
        # ~8.5% of runs on a 1-core indexer (2026-09-30), and a skipped
        # window is an attack that never alerts or reaches Discord.
        f"realtime_schedule = 0\n"
        # One alert per result row (alert.digest_mode = 0), each throttled on
        # the detection's `throttle` fields -- the columns that identify one
        # attempt (attacker + target/object). Two attackers, or one attacker
        # against two targets, are separate rows and separate alerts. The
        # throttle only stops the SAME attempt re-alerting: its later events
        # indexed in the next window, or a burst re-evaluated as it grows.
        f"alert.digest_mode = 0\n"
        f"alert.suppress = 1\n"
        f"alert.suppress.fields = {','.join(throttle_fields)}\n"
        f"alert.suppress.period = {d.get('throttle_period', DEFAULT_THROTTLE_PERIOD)}\n"
    )
    if discord:
        # The stanza name is the embed title (this repo's convention: the
        # Splunk alert name IS the Discord embed title). The action resolves
        # the attacker IP column to "Name (IP)" for the embed description and
        # renders the planner's additional_fields as embed fields; each
        # search's `| table` is already exactly attacker_ip + those fields, so
        # we pass that field list to fix ordering and skip any stray columns.
        # A search with no attacker_ip column names its own via
        # embed.attacker_field (the action defaults to attacker_ip).
        embed = d.get("embed", {})
        fields = embed.get("additional_fields", []) or []
        stanza += "action.discord_alert = 1\n"
        # Per-result alerting: post just the row this invocation is for.
        stanza += "action.discord_alert.param.per_result = 1\n"
        if fields:
            stanza += f"action.discord_alert.param.fields = {','.join(fields)}\n"
        if embed.get("attacker_field"):
            stanza += f"action.discord_alert.param.attacker_field = {embed['attacker_field']}\n"
    return stanza


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--discord",
        action="store_true",
        help="wire each search to the discord_alert custom alert action "
        "(defense-tooling installs that action + the webhook)",
    )
    args = parser.parse_args()

    detections = load_detections()
    if not detections:
        sys.exit("No production detections found under detections/**/*.yml")
    stanzas = [render_stanza(d, discord=args.discord) for d in detections]
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(HEADER)
        f.write("\n")
        f.write("\n".join(stanzas))
    print(f"Wrote {len(detections)} saved search(es) to {os.path.relpath(OUTPUT_PATH, REPO_ROOT)}:")
    for d in detections:
        state = "  [DISABLED]" if d.get("disabled", True) else ""
        print(f"  - {d['name']}  ({d['_source_path']}){state}")


if __name__ == "__main__":
    main()
