# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Small, observation-only endpoint producer for the local OTLP stack.

This is deliberately not the ShadowClaw product. It reports process identity,
coverage, exporter health, and its own resource usage. Detection, ledger,
correlation, and enforcement remain outside this Phase 1 component.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defenseclaw.doctor_gateway import GatewayEvidence
from defenseclaw.process_liveness import pid_alive

try:
    import resource as _resource_usage
except ImportError:  # pragma: no cover - resource is not available on Windows
    _resource_usage = None

SERVICE_NAME = "shadowclaw"
SERVICE_NAMESPACE = "shadowclaw"
COMPONENT_NAME = "endpoint-observer"
COMPONENT_VERSION = "phase1"
EVENT_SNAPSHOT = "shadowclaw.endpoint.snapshot"
EVENT_STATUS = "shadowclaw.observer.status"
DEFAULT_ENDPOINT = "http://127.0.0.1:4318"
DEFAULT_INTERVAL = 5.0
DEFAULT_REPORT_LIMIT = 25
MAX_ERROR_LENGTH = 240


@dataclass(frozen=True)
class ProcessObservation:
    pid: int
    ppid: int
    user: str
    rss_kb: int
    cpu_percent: float
    start_time: str
    executable: str

    def body(self, observed_at: float) -> dict[str, Any]:
        return {
            "event_name": EVENT_SNAPSHOT,
            "observed_at": observed_at,
            "process": {
                "pid": self.pid,
                "parent_pid": self.ppid,
                "user": self.user,
                "rss_kb": self.rss_kb,
                "cpu_percent": self.cpu_percent,
                "start_time": self.start_time,
                "executable_identity": self.executable,
            },
            "observation_only": True,
        }


def _now_nanos() -> str:
    return str(int(time.time() * 1_000_000_000))


def _any_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": str(value)}


def _attributes(values: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"key": key, "value": _any_value(value)}
        for key, value in values.items()
        if value is not None
    ]


def _resource_attributes() -> dict[str, Any]:
    return {
        "service.name": SERVICE_NAME,
        "service.namespace": SERVICE_NAMESPACE,
        "service.version": COMPONENT_VERSION,
        "shadowclaw.product": "ShadowClaw",
        "shadowclaw.component": COMPONENT_NAME,
        "shadowclaw.mode": "observation-only",
        "host.name": socket.gethostname(),
        "os.type": platform.system().lower(),
    }


def _resource() -> dict[str, Any]:
    return {"attributes": _attributes(_resource_attributes())}


class OtlpExporter:
    def __init__(self, endpoint: str, timeout: float = 5.0) -> None:
        self.endpoint = _validate_endpoint(endpoint).rstrip("/")
        self.timeout = timeout
        self.successes = 0
        self.failures = 0
        self.last_error = ""

    def _post(self, path: str, payload: dict[str, Any]) -> bool:
        request = urllib.request.Request(
            self.endpoint + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if 200 <= response.status < 300:
                    self.successes += 1
                    return True
                self._failed(f"HTTP {response.status}")
        except (OSError, ValueError, urllib.error.URLError) as exc:
            self._failed(str(exc))
        return False

    def _failed(self, message: str) -> None:
        self.failures += 1
        self.last_error = message[:MAX_ERROR_LENGTH]

    def logs(self, records: list[dict[str, Any]]) -> bool:
        if not records:
            return True
        return self._post(
            "/v1/logs",
            {
                "resourceLogs": [{
                    "resource": _resource(),
                    "scopeLogs": [{
                        "scope": {"name": SERVICE_NAME, "version": COMPONENT_VERSION},
                        "logRecords": records,
                    }],
                }],
            },
        )

    def metrics(self, metrics: list[dict[str, Any]]) -> bool:
        if not metrics:
            return True
        return self._post(
            "/v1/metrics",
            {
                "resourceMetrics": [{
                    "resource": _resource(),
                    "scopeMetrics": [{
                        "scope": {"name": SERVICE_NAME, "version": COMPONENT_VERSION},
                        "metrics": metrics,
                    }],
                }],
            },
        )


def _validate_endpoint(endpoint: str) -> str:
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("endpoint must be an http(s) URL")
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme == "http" and hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("plaintext endpoint must be loopback")
    if parsed.path not in {"", "/"}:
        raise ValueError("endpoint must be the OTLP base URL")
    return endpoint


def _executable_identity(pid: int, fallback: str) -> str:
    if sys.platform.startswith("linux"):
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except OSError:
            pass
    return fallback


def _parse_ps_line(line: str) -> ProcessObservation | None:
    head = line.split(None, 4)
    if len(head) != 5:
        return None
    pid_text, ppid_text, user, rss_text, remainder = head
    start_and_executable = remainder.split(None, 6)
    if len(start_and_executable) != 7:
        return None
    start_time = " ".join(start_and_executable[1:6])
    executable = start_and_executable[6]
    try:
        pid = int(pid_text)
        ppid = int(ppid_text)
        rss_kb = int(rss_text)
        cpu_percent = float(start_and_executable[0])
    except ValueError:
        return None
    return ProcessObservation(
        pid=pid,
        ppid=ppid,
        user=user[:128],
        rss_kb=max(0, rss_kb),
        cpu_percent=max(0.0, cpu_percent),
        start_time=start_time[:128],
        executable=_executable_identity(pid, executable[:512]),
    )


def sample_processes() -> tuple[list[ProcessObservation], str]:
    if os.name == "nt":
        return [], "native process table observer is not implemented on Windows"
    try:
        completed = subprocess.run(
            ["ps", "-Ao", "pid=,ppid=,user=,rss=,%cpu=,lstart=,comm="],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], str(exc)[:MAX_ERROR_LENGTH]
    if completed.returncode != 0 and not completed.stdout:
        return [], (completed.stderr or "ps failed")[:MAX_ERROR_LENGTH]
    processes = [
        parsed
        for line in completed.stdout.splitlines()
        if (parsed := _parse_ps_line(line)) is not None
    ]
    return processes, "" if processes else "process table returned no usable rows"


def _log_record(body: dict[str, Any], attrs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "timeUnixNano": _now_nanos(),
        "observedTimeUnixNano": _now_nanos(),
        "severityNumber": 9,
        "severityText": "INFO",
        "body": {"stringValue": json.dumps(body, separators=(",", ":"))},
        "attributes": _attributes(attrs or {}),
    }


def _gauge(name: str, value: float, unit: str = "1", attrs: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "unit": unit,
        "gauge": {
            "dataPoints": [{
                "timeUnixNano": _now_nanos(),
                "asDouble": float(value),
                "attributes": _attributes(attrs or {}),
            }],
        },
    }


def _resource_metrics() -> tuple[float, float]:
    if _resource_usage is None:
        return 0.0, 0.0
    usage = _resource_usage.getrusage(_resource_usage.RUSAGE_SELF)
    max_rss = float(usage.ru_maxrss)
    if sys.platform != "darwin":
        max_rss *= 1024
    return usage.ru_utime + usage.ru_stime, max_rss


def observe_once(exporter: OtlpExporter, report_limit: int = DEFAULT_REPORT_LIMIT) -> dict[str, Any]:
    processes, reason = sample_processes()
    selected = sorted(processes, key=lambda item: (item.cpu_percent, item.rss_kb), reverse=True)[:report_limit]
    coverage = len(selected) / len(processes) if processes else 0.0
    observed_at = time.time()
    cpu_seconds, max_rss = _resource_metrics()
    status = {
        "event_name": EVENT_STATUS,
        "component": COMPONENT_NAME,
        "observation_only": True,
        "processes_observed": len(processes),
        "processes_reported": len(selected),
        "coverage": round(coverage, 4),
        "coverage_status": "complete" if len(selected) == len(processes) else "partial" if processes else "unavailable",
        "process_table_reason": reason,
        "exporter_successes": exporter.successes,
        "exporter_failures": exporter.failures,
        "exporter_last_error": exporter.last_error,
        "resource_cpu_seconds": round(cpu_seconds, 4),
        "resource_max_rss": max_rss,
    }
    records = [_log_record(status, {"shadowclaw.event_name": EVENT_STATUS})]
    records.extend(
        _log_record(item.body(observed_at), {"shadowclaw.event_name": EVENT_SNAPSHOT})
        for item in selected
    )
    metrics = [
        _gauge("shadowclaw.observer.up", 1.0, attrs={"shadowclaw.mode": "observation-only"}),
        _gauge(
            "shadowclaw.observer.coverage",
            coverage,
            attrs={"shadowclaw.coverage_status": status["coverage_status"]},
        ),
        _gauge("shadowclaw.observer.processes.observed", len(processes), unit="{process}"),
        _gauge("shadowclaw.observer.processes.reported", len(selected), unit="{process}"),
        _gauge("shadowclaw.observer.exporter.successes", exporter.successes, unit="{request}"),
        _gauge("shadowclaw.observer.exporter.failures", exporter.failures, unit="{request}"),
        _gauge("shadowclaw.observer.resource.cpu_seconds", cpu_seconds, unit="s"),
        _gauge("shadowclaw.observer.resource.max_rss", max_rss, unit="By"),
    ]
    exporter.logs(records)
    exporter.metrics(metrics)
    return status


def _pid_file(data_dir: str) -> Path:
    return Path(data_dir) / "endpoint-observer" / "observer.pid"


def _read_pid_record(data_dir: str) -> dict[str, Any] | None:
    path = _pid_file(data_dir)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def observer_status(data_dir: str) -> dict[str, Any]:
    record = _read_pid_record(data_dir)
    if not record or not isinstance(record.get("pid"), int):
        return {"state": "stopped", "pid": None}
    pid = record["pid"]
    if not pid_alive(pid):
        return {"state": "stale", "pid": pid}
    evidence = GatewayEvidence().process(pid)
    if evidence.status != "ok" or evidence.start_identity != record.get("start_identity"):
        return {"state": "unknown", "pid": pid}
    return {"state": "running", "pid": pid, "endpoint": record.get("endpoint", "")}


def start_observer(data_dir: str, endpoint: str, interval: float = DEFAULT_INTERVAL) -> dict[str, Any]:
    current = observer_status(data_dir)
    if current["state"] in {"running", "unknown"}:
        return current
    destination = _pid_file(data_dir)
    destination.parent.mkdir(parents=True, exist_ok=True)
    log_path = destination.with_name("observer.log")
    log_handle = log_path.open("a", encoding="utf-8")
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "defenseclaw.endpoint_observer",
                "--run",
                "--endpoint",
                endpoint,
                "--interval",
                str(interval),
                "--pid-file",
                str(destination),
            ],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=os.name != "nt",
            close_fds=True,
        )
    except OSError:
        log_handle.close()
        raise
    log_handle.close()
    for _ in range(20):
        record = _read_pid_record(data_dir)
        if record and record.get("pid") == process.pid:
            return observer_status(data_dir)
        time.sleep(0.05)
    return {"state": "starting", "pid": process.pid}


def stop_observer(data_dir: str) -> dict[str, Any]:
    status = observer_status(data_dir)
    if status["state"] != "running" or not status.get("pid"):
        return {"state": "stopped", "pid": status.get("pid")}
    pid = int(status["pid"])
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return {"state": "stopped", "pid": pid}
    for _ in range(40):
        if not pid_alive(pid):
            return {"state": "stopped", "pid": pid}
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    return {"state": "stopped", "pid": pid}


def _write_pid_file(path: Path) -> None:
    evidence = GatewayEvidence().process(os.getpid())
    payload = {
        "pid": os.getpid(),
        "start_identity": evidence.start_identity,
        "endpoint": _RUN_ENDPOINT,
        "component": COMPONENT_NAME,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


_RUN_ENDPOINT = DEFAULT_ENDPOINT


def _run(endpoint: str, interval: float, pid_file: str) -> int:
    global _RUN_ENDPOINT
    _RUN_ENDPOINT = endpoint
    exporter = OtlpExporter(endpoint)
    path = Path(pid_file)
    _write_pid_file(path)
    stopping = False

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        while not stopping:
            observe_once(exporter)
            deadline = time.monotonic() + interval
            while not stopping and time.monotonic() < deadline:
                time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DefenseClaw Phase 1 endpoint observer")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL)
    parser.add_argument("--pid-file", default="")
    args = parser.parse_args(argv)
    if not args.run:
        parser.error("--run is required")
    if not 1.0 <= args.interval <= 60.0:
        parser.error("--interval must be between 1 and 60 seconds")
    if not args.pid_file:
        parser.error("--pid-file is required")
    return _run(args.endpoint, args.interval, args.pid_file)


if __name__ == "__main__":
    raise SystemExit(main())
