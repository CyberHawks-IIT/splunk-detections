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

REQUIRED_FIELDS = ["name", "id", "search", "description", "verification", "schedule"]

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
    schedule = d["schedule"]
    disabled = "1" if d.get("disabled", True) else "0"
    stanza = (
        f"[{d['name']}]\n"
        f"search = {search}\n"
        f"description = {description}\n"
        f"cron_schedule = {schedule['cron']}\n"
        f"dispatch.earliest_time = {schedule['earliest']}\n"
        f"dispatch.latest_time = {schedule['latest']}\n"
        f"enableSched = 1\n"
        f"disabled = {disabled}\n"
        f"alert.severity = 4\n"
        f"alert_type = number of events\n"
        f"alert_comparator = greater than\n"
        f"alert_threshold = 0\n"
    )
    if discord:
        # The stanza name is the embed title (this repo's convention: the
        # Splunk alert name IS the Discord embed title). The action renders the
        # result row's columns as embed fields; each search's `| table` is
        # already exactly attacker_ip + the planner's additional_fields, so we
        # pass that field list to fix ordering and skip any stray columns.
        embed = d.get("embed", {})
        fields = embed.get("additional_fields", []) or []
        stanza += "action.discord_alert = 1\n"
        if fields:
            stanza += f"action.discord_alert.param.fields = {','.join(fields)}\n"
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
        print(f"  - {d['name']}  ({d['_source_path']})")


if __name__ == "__main__":
    main()
