#!/usr/bin/env python3
"""Synthetic PAMSignal event producer for the try-it stack.

Generates pamsignal-shaped events across a synthetic fleet and pushes them
either directly to Loki (instant labels), to a file tailed by Alloy
(proves the Alloy pipeline), or both.

The JSON body matches what Alloy emits when it scrapes journald with
format_as_json=true: uppercase keys mirroring the structured fields that
PAMSignal writes via sd_journal_send().

Env vars:
  LOKI_URL         Loki HTTP push endpoint
  ALLOY_LOG_PATH   File path the Alloy file-source watches (file/both mode)
  HOST_COUNT       Size of synthetic fleet (default 12)
  EVENT_RATE       Events per second across the fleet (default 2.0)
  MODE             loki | file | both (default both)
"""
from __future__ import annotations

import json
import os
import random
import signal
import sys
import time
from datetime import datetime, timezone
from urllib import error as urlerror
from urllib import request as urlrequest

LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100/loki/api/v1/push")
ALLOY_LOG_PATH = os.environ.get("ALLOY_LOG_PATH")
HOST_COUNT = int(os.environ.get("HOST_COUNT", "12"))
EVENT_RATE = float(os.environ.get("EVENT_RATE", "2.0"))
MODE = os.environ.get("MODE", "both").lower()

if MODE not in ("loki", "file", "both"):
    print(f"[synthetic] invalid MODE={MODE}", file=sys.stderr)
    sys.exit(2)

HOSTNAMES = [f"vps-{i:02d}.example.org" for i in range(1, HOST_COUNT + 1)]

SERVICES = ["sshd", "sudo", "su", "login"]
SERVICE_WEIGHTS = [0.65, 0.22, 0.08, 0.05]

USERS_LEGIT = ["alice", "bob", "carol", "dave", "deploy", "ops", "ubuntu"]
USERS_ATTACK = ["root", "admin", "test", "postgres", "git", "oracle", "ubuntu"]

LEGIT_IPS = [f"10.0.0.{i}" for i in range(2, 30)]
ATTACK_IPS = [
    "185.220.101.42",
    "194.169.175.66",
    "45.95.147.236",
    "103.130.218.10",
    "92.118.39.41",
    "5.42.65.99",
    "162.247.74.27",
]


class Burst:
    """A single in-flight brute-force attack."""

    def __init__(self) -> None:
        self.active = False
        self.attacker_ip: str | None = None
        self.target_host: str | None = None
        self.target_user: str | None = None
        self.attempts = 0
        self.threshold = 0

    def trigger(self) -> None:
        self.active = True
        self.attacker_ip = random.choice(ATTACK_IPS)
        self.target_host = random.choice(HOSTNAMES)
        self.target_user = random.choice(USERS_ATTACK)
        self.attempts = 0
        self.threshold = random.randint(6, 12)

    def finish(self) -> None:
        self.active = False


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def event_body(
    *,
    action: str,
    host: str,
    service: str,
    user: str,
    source_ip: str | None = None,
    source_port: int | None = None,
    target_user: str | None = None,
) -> dict[str, str]:
    """Build the JSON body matching PAMSignal's journald structured fields."""
    outcome = (
        "success"
        if action in ("login_success", "session_opened", "session_closed")
        else "failure"
        if action == "login_failure"
        else "unknown"
    )

    if action in ("session_opened", "session_closed"):
        category = "authentication,session"
        severity = 3
        kind = "event"
    elif action == "brute_force_detected":
        category = "authentication,intrusion_detection"
        severity = 8
        kind = "alert"
    elif action == "login_failure":
        category = "authentication"
        severity = 5
        kind = "event"
    else:
        category = "authentication"
        severity = 4
        kind = "event"

    pid = random.randint(1000, 99999)

    if action in ("session_opened", "session_closed"):
        message = (
            f"pamsignal: {action} user={user} service={service} at {utc_now_iso()}"
        )
    elif action == "brute_force_detected":
        message = (
            f"pamsignal: BRUTE_FORCE_DETECTED ip={source_ip} attempts=7 "
            f"window=60s user={user}"
        )
    else:
        sip = source_ip or "-"
        sport = source_port or 0
        message = (
            f"pamsignal: {action} user={user} from={sip} port={sport} "
            f"service={service} auth=password at {utc_now_iso()}"
        )

    body: dict[str, str] = {
        "MESSAGE": message,
        "SYSLOG_IDENTIFIER": "pamsignal",
        "EVENT_ACTION": action,
        "EVENT_CATEGORY": category,
        "EVENT_KIND": kind,
        "EVENT_OUTCOME": outcome,
        "EVENT_SEVERITY": str(severity),
        "EVENT_MODULE": "pamsignal",
        "SERVICE_NAME": service,
        "USER_NAME": user,
        "HOST_HOSTNAME": host,
        "PROCESS_PID": str(pid),
        "_HOSTNAME": host,
        "PRIORITY": "4" if outcome == "failure" else "5",
    }

    if source_ip is not None:
        body["SOURCE_IP"] = source_ip
    if source_port is not None:
        body["SOURCE_PORT"] = str(source_port)
    if target_user is not None:
        body["USER_TARGET_NAME"] = target_user

    return body


def push_loki(streams_map: dict[tuple, list[list[str]]]) -> None:
    if not streams_map:
        return
    streams = [
        {"stream": dict(labels), "values": entries}
        for labels, entries in streams_map.items()
    ]
    payload = json.dumps({"streams": streams}).encode("utf-8")
    req = urlrequest.Request(
        LOKI_URL,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlrequest.urlopen(req, timeout=5) as resp:
            if resp.status >= 300:
                print(
                    f"[synthetic] loki push status={resp.status}",
                    file=sys.stderr,
                    flush=True,
                )
    except urlerror.URLError as exc:
        print(f"[synthetic] loki push error: {exc}", file=sys.stderr, flush=True)


def write_file(bodies: list[dict[str, str]]) -> None:
    if not ALLOY_LOG_PATH or not bodies:
        return
    os.makedirs(os.path.dirname(ALLOY_LOG_PATH), exist_ok=True)
    with open(ALLOY_LOG_PATH, "a", encoding="utf-8") as fh:
        for body in bodies:
            fh.write(json.dumps(body) + "\n")


def gen_normal_event() -> tuple[dict[str, str], str, str, str]:
    host = random.choice(HOSTNAMES)
    service = random.choices(SERVICES, weights=SERVICE_WEIGHTS, k=1)[0]

    if service == "sshd":
        roll = random.random()
        if roll < 0.50:
            action = "login_success"
        elif roll < 0.72:
            action = "session_opened"
        elif roll < 0.90:
            action = "session_closed"
        else:
            action = "login_failure"
    elif service in ("sudo", "su"):
        roll = random.random()
        if roll < 0.65:
            action = "session_opened"
        elif roll < 0.94:
            action = "session_closed"
        else:
            action = "login_failure"
    else:
        action = "login_success" if random.random() < 0.7 else "login_failure"

    user = "root" if random.random() < 0.06 else random.choice(USERS_LEGIT)

    source_ip = random.choice(LEGIT_IPS) if service == "sshd" else None
    source_port = random.randint(20000, 65000) if source_ip else None

    target_user = None
    if service in ("sudo", "su") and action != "login_failure":
        target_user = (
            "root" if random.random() < 0.7 else random.choice(USERS_LEGIT)
        )

    body = event_body(
        action=action,
        host=host,
        service=service,
        user=user,
        source_ip=source_ip,
        source_port=source_port,
        target_user=target_user,
    )
    return body, action, host, service


def gen_burst_event(burst: Burst) -> tuple[dict[str, str], str, str, str]:
    """Emit either a failed-login attempt or the closing brute-force alert."""
    assert burst.target_host and burst.target_user and burst.attacker_ip
    burst.attempts += 1
    host = burst.target_host
    service = "sshd"

    if burst.attempts >= burst.threshold:
        body = event_body(
            action="brute_force_detected",
            host=host,
            service=service,
            user=burst.target_user,
            source_ip=burst.attacker_ip,
        )
        burst.finish()
        return body, "brute_force_detected", host, service

    body = event_body(
        action="login_failure",
        host=host,
        service=service,
        user=burst.target_user,
        source_ip=burst.attacker_ip,
        source_port=random.randint(20000, 65000),
    )
    return body, "login_failure", host, service


def main() -> None:
    print(
        f"[synthetic] hosts={HOST_COUNT} rate={EVENT_RATE}/s mode={MODE} "
        f"loki={LOKI_URL} file={ALLOY_LOG_PATH}",
        flush=True,
    )

    running = True

    def stop(_signum, _frame):  # noqa: ANN001
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    time.sleep(2)  # let Loki/Alloy finish booting

    interval = 1.0 / max(EVENT_RATE, 0.1)
    burst = Burst()

    stream_batch: dict[tuple, list[list[str]]] = {}
    file_batch: list[dict[str, str]] = []
    last_flush = time.time()

    while running:
        if not burst.active and random.random() < 0.02:
            burst.trigger()
            print(
                f"[synthetic] burst start: {burst.attacker_ip} -> "
                f"{burst.target_host} user={burst.target_user} "
                f"threshold={burst.threshold}",
                flush=True,
            )

        if burst.active:
            body, action, host, service = gen_burst_event(burst)
        else:
            body, action, host, service = gen_normal_event()

        labels = (
            ("app", "pamsignal"),
            ("host", host),
            ("service", service),
            ("event_action", action),
        )
        ts_ns = str(time.time_ns())
        line = json.dumps(body)

        stream_batch.setdefault(labels, []).append([ts_ns, line])
        file_batch.append(body)

        now = time.time()
        total = sum(len(v) for v in stream_batch.values())
        if total >= 200 or (now - last_flush) >= 1.0:
            if MODE in ("loki", "both"):
                push_loki(stream_batch)
            if MODE in ("file", "both"):
                write_file(file_batch)
            stream_batch.clear()
            file_batch.clear()
            last_flush = now

        time.sleep(interval)

    if MODE in ("loki", "both"):
        push_loki(stream_batch)
    if MODE in ("file", "both"):
        write_file(file_batch)
    print("[synthetic] stopped", flush=True)


if __name__ == "__main__":
    main()
