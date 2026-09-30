#!/usr/bin/env python3
"""Fire every detection saved search every 15 seconds for sub-minute alerting.

Splunk's own scheduler runs a saved search at most once a minute (cron has no
sub-minute granularity), so an event waited up to ~60s (avg ~30s) for the next
run before its Discord alert could fire. This service dispatches every enabled,
scheduled detection in the cyberhawks_detections app every 15s via the REST
dispatch endpoint with trigger_actions=1, which runs the search and fires its
alert actions immediately -- the same path the scheduler uses, so per-result
throttling (alert.suppress) still applies and each attempt still alerts once.

Splunk's 1/min scheduler is left enabled as a fallback: if this service stops,
every detection is still evaluated once a minute over the `detection_window`
(90s, wider than the 60s gap, so no coverage is lost).

The dispatcher fires at :15, :30 and :45 past each minute; the scheduler's own
run covers :00. dispatch.now is not pinned: the detection_window is a rolling
"last 90s" relative to each run's own time, so overlapping runs are expected
and the throttle collapses them to one alert per attempt.

Config (INI) is read from $SPLUNK_HOME/etc/apps/cyberhawks_detections/local/
dispatcher.conf, deployed 0600 by the splunk_indexer role:

    [dispatcher]
    base_url = https://127.0.0.1:8089
    username = admin
    password = ...
    app = cyberhawks_detections
    interval = 15
"""
import configparser
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request
import json

SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
CONF = os.path.join(
    SPLUNK_HOME, "etc", "apps", "cyberhawks_detections", "local", "dispatcher.conf"
)
# The saved searches are refreshed from Splunk periodically so a newly deployed
# detection is picked up without restarting this service.
REFRESH_EVERY = 20  # cycles (~5 min at 15s)


def log(msg):
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}", flush=True)


def load_config():
    cp = configparser.ConfigParser()
    if not cp.read(CONF):
        sys.exit(f"dispatcher.conf not found or unreadable at {CONF}")
    d = cp["dispatcher"]
    return {
        "base_url": d.get("base_url", "https://127.0.0.1:8089").rstrip("/"),
        "username": d.get("username", "admin"),
        "password": d["password"],
        "app": d.get("app", "cyberhawks_detections"),
        "interval": d.getint("interval", 15),
    }


def make_opener(cfg):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, cfg["base_url"], cfg["username"], cfg["password"])
    auth = urllib.request.HTTPBasicAuthHandler(mgr)
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx), auth
    )


def list_searches(opener, cfg):
    """Enabled, scheduled saved searches in the detections app."""
    url = (
        f"{cfg['base_url']}/servicesNS/nobody/{cfg['app']}/saved/searches"
        "?output_mode=json&count=0&f=disabled&f=is_scheduled"
    )
    with opener.open(url, timeout=30) as r:
        data = json.loads(r.read())
    names = []
    for e in data.get("entry", []):
        c = e.get("content", {})
        if not c.get("disabled", False) and c.get("is_scheduled", False):
            names.append(e["name"])
    return names


def dispatch(opener, cfg, name):
    url = (
        f"{cfg['base_url']}/servicesNS/nobody/{cfg['app']}/saved/searches/"
        f"{urllib.parse.quote(name)}/dispatch"
    )
    # trigger_actions runs the alert actions (incl. Discord); a short TTL keeps
    # the dispatch directory from filling with finished jobs (one per search
    # every 15s). The alert action runs synchronously as the job triggers, so
    # the job does not need to outlive it.
    body = urllib.parse.urlencode(
        {"trigger_actions": "1", "dispatch.ttl": "120", "output_mode": "json"}
    ).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    opener.open(req, timeout=30).read()


def main():
    cfg = load_config()
    opener = make_opener(cfg)
    interval = cfg["interval"]
    searches = []
    cycle = 0
    log(f"dispatcher starting: app={cfg['app']} interval={interval}s")
    while True:
        # Align to the next interval boundary; skip second 0 (the scheduler's
        # own 1/min run covers it), so the cadence is :15/:30/:45.
        now = time.time()
        wait = interval - (now % interval)
        time.sleep(wait)
        if int(time.time()) % 60 == 0:
            continue
        if cycle % REFRESH_EVERY == 0 or not searches:
            try:
                searches = list_searches(opener, cfg)
                log(f"tracking {len(searches)} detection searches")
            except Exception as exc:  # noqa: BLE001
                log(f"ERROR listing searches: {exc}")
        cycle += 1
        ok = 0
        errs = 0
        for name in searches:
            try:
                dispatch(opener, cfg, name)
                ok += 1
            except Exception as exc:  # noqa: BLE001
                errs += 1
                log(f"ERROR dispatching {name!r}: {exc}")
        if errs:
            log(f"dispatched {ok} ok, {errs} errors")


if __name__ == "__main__":
    main()
