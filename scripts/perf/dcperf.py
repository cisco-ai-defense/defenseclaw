#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""DefenseClaw performance harness (stdlib only, no secrets).

Measures one per-user install on the host it runs on and writes a JSON
result plus a one-line summary:

* hook latency of the installed Claude Code and Codex hooks (the command
  the connector registered in ~/.claude/settings.json and ~/.codex/hooks.json),
  benign PreToolUse calls: idle (sequential) and burst (32-way);
* processes spawned per hook call: Linux with strace on PATH; macOS from an
  `eslogger exec fork` log that root writes during the run (--eslogger-log),
  which also counts what the gateway itself starts while the hooks run;
* gateway restart time until /health answers from the new process;
* wall time of `defenseclaw status`, `doctor` and `setup claude-code`;
* skill scan time on scripts/perf/fixtures/benign-skill (no LLM);
* gateway RSS after an idle period, split into the anonymous and the
  file-backed part (Linux /proc, macOS vmmap).

It needs Python 3.11+. Started by an older python3 (macOS ships 3.9), it
runs itself again under the DefenseClaw venv Python of the install it
measures (HOME/.defenseclaw/.venv/bin/python, 3.12).

Subcommands:
  provision --assets DIR --home DIR   install the release assets into a
                                      throwaway HOME, set up claude-code and
                                      codex, start the gateway on free ports
  run [--home DIR] [--rss-idle S] [--out FILE] [--budgets FILE --column C]
      [--eslogger-log FILE]
  compare RESULT --budgets FILE --column C

`run` and `compare` exit 1 when a gated metric is over its budget by more
than the tolerance in budgets.json, or when a gated metric could not be
measured. Nothing here reads or prints credentials: the hook token stays in
the files the installed hooks read themselves.
"""

from __future__ import annotations

import argparse
import calendar
import concurrent.futures
import json
import os
import platform
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE_SKILL = HERE / "fixtures" / "benign-skill"
SCHEMA = 1

# idle hook calls, burst calls, burst width, restarts, status/doctor/setup/scan
# repetitions, traced hook calls. The RSS sample waits rss_idle seconds (300 by
# default): the gateway's first retention pass runs about 60 s after a start
# (TST-0218), so an earlier sample lands before or after it by chance.
PLAN = dict(idle=100, burst=128, width=32, restarts=3, status=5, doctor=3, setup=3, scan=3, exec_calls=10)
DEFAULT_RSS_IDLE_S = 300

# eslogger tracing (macOS): the traced calls are a second apart, so the
# events of one call never fall in the window of the next, and an event
# counts for a call up to ESLOGGER_SLACK_S after the hook returned.
ESLOGGER_CALL_GAP_S = 1.0
ESLOGGER_SLACK_S = 0.3


# ---------------------------------------------------------------- statistics


def percentile(values: list[float], pct: float) -> float:
    """Linear-interpolated percentile (pct in 0..100) of a non-empty list."""
    if not values:
        raise ValueError("percentile of an empty list")
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct / 100.0
    lo = int(k)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def summarize(values: list[float]) -> dict:
    return {
        "n": len(values),
        "p50_ms": round(percentile(values, 50), 1),
        "p95_ms": round(percentile(values, 95), 1),
        "max_ms": round(max(values), 1),
        "min_ms": round(min(values), 1),
    }


# ---------------------------------------------------------------- budgets


def flatten(result: dict) -> dict[str, float]:
    """Return {"hook.claudecode.idle.p50_ms": 61.2, ...} for every number in
    result["metrics"]."""
    out: dict[str, float] = {}

    def walk(prefix: str, node) -> None:
        if isinstance(node, bool):
            return
        if isinstance(node, (int, float)):
            out[prefix] = float(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                walk(f"{prefix}.{key}" if prefix else key, value)

    walk("", result.get("metrics", {}))
    return out


def compare(result: dict, budgets: dict, column: str) -> dict:
    """Compare a result with one budgets.json column.

    A budget entry is {"budget": <number>, "source": "..."} (gated),
    {"budget": <number>, "gate": false, ...} (reported, not gated) or
    {"budget": "TODO", ...} (no baseline yet). A gated metric fails when its
    value is over budget * (1 + tolerance), or when the result does not have
    it (a measurement that did not run must not pass the gate).
    """
    tolerance = float(budgets.get("tolerance", 0.20))
    col = budgets.get("columns", {}).get(column)
    if col is None:
        raise KeyError(f"budgets.json has no column {column!r}")
    values = flatten(result)
    rows = []
    for metric, entry in sorted(col.items()):
        budget = entry.get("budget") if isinstance(entry, dict) else entry
        value = values.get(metric)
        if not isinstance(budget, (int, float)) or isinstance(budget, bool):
            rows.append({"metric": metric, "value": value, "budget": budget, "status": "todo"})
            continue
        if isinstance(entry, dict) and entry.get("gate") is False:
            rows.append({"metric": metric, "value": value, "budget": budget, "status": "info"})
            continue
        limit = float(budget) * (1.0 + tolerance)
        if value is None:
            status = "missing"
        elif value > limit:
            status = "regression"
        else:
            status = "ok"
        rows.append({"metric": metric, "value": value, "budget": budget, "limit": round(limit, 1), "status": status})
    failed = [r for r in rows if r["status"] in ("regression", "missing")]
    return {"column": column, "tolerance": tolerance, "rows": rows, "failed": len(failed), "ok": not failed}


def merge_results(results: list[dict]) -> dict:
    """One result from several passes of `run`, the metrics merged (a later
    pass wins a metric both measured). On macOS the exec count needs an
    eslogger running, and Endpoint Security makes every exec of the Mac
    slower while it runs, so the hook latency is measured in a pass without
    it (README)."""

    def merge(into: dict, other: dict) -> None:
        for key, value in other.items():
            if isinstance(value, dict) and isinstance(into.get(key), dict):
                merge(into[key], value)
            else:
                into[key] = value

    merged = json.loads(json.dumps(results[0]))
    for other in results[1:]:
        merge(merged.setdefault("metrics", {}), other.get("metrics", {}))
        merged.setdefault("errors", {}).update(other.get("errors", {}))
        merged["groups"] = sorted(set(merged.get("groups", [])) | set(other.get("groups", [])))
    return merged


def compare_text(report: dict) -> str:
    lines = []
    for row in report["rows"]:
        if row["status"] in ("todo", "info"):
            continue
        value = "-" if row["value"] is None else f"{row['value']:.1f}"
        lines.append(
            f"  {row['status']:<10} {row['metric']:<44} {value:>10} budget {row['budget']} (limit {row['limit']})"
        )
    head = (
        f"budget check [{report['column']}] tolerance {report['tolerance']:.0%}: "
        f"{'PASS' if report['ok'] else 'FAIL'} ({report['failed']} failed)"
    )
    return "\n".join([head] + lines)


# ---------------------------------------------------------------- install


class Install:
    """Paths of one per-user install under HOME."""

    def __init__(self, home: Path) -> None:
        self.home = home
        self.dc = home / ".defenseclaw"
        self.bin = home / ".local" / "bin"
        self.cli = self.bin / "defenseclaw"
        self.gateway = self.bin / "defenseclaw-gateway"
        self._work: Path | None = None

    @property
    def work(self) -> Path:
        """Scratch directory the hooks run in (the agent's cwd)."""
        if self._work is None:
            self._work = Path(tempfile.mkdtemp(prefix="dcperf-work-"))
            (self._work / "hello.txt").write_text("hello\n", encoding="utf-8")
        return self._work

    def env(self) -> dict[str, str]:
        env = dict(os.environ)
        env["HOME"] = str(self.home)
        env["PATH"] = f"{self.bin}{os.pathsep}{env.get('PATH', '')}"
        env["DEFENSECLAW_NO_UPDATE_CHECK"] = "1"
        env.setdefault("DEFENSECLAW_APP_PATH", "none")
        for key in ("DEFENSECLAW_HOME", "DEFENSECLAW_CONFIG"):
            env.pop(key, None)
        return env

    def api_port(self) -> int:
        """gateway.api_port from config.yaml (18970 when unset)."""
        text = (self.dc / "config.yaml").read_text(encoding="utf-8")
        section = re.search(r"^gateway:\s*\n((?:[ \t]+.*\n|\s*\n)*)", text, re.M)
        if section:
            port = re.search(r"^[ \t]+api_port:\s*(\d+)", section.group(1), re.M)
            if port and int(port.group(1)) > 0:
                return int(port.group(1))
        return 18970

    def gateway_pid(self) -> int | None:
        try:
            data = json.loads((self.dc / "gateway.pid").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        pid = data.get("pid") if isinstance(data, dict) else data
        return int(pid) if isinstance(pid, int) and pid > 0 else None


def run_cmd(
    argv: list[str], env: dict, timeout: float = 600, cwd: str | None = None, data: bytes | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        env=env,
        cwd=cwd,
        input=data,
        capture_output=True,
        timeout=timeout,
        stdin=None if data is not None else subprocess.DEVNULL,
    )


def free_port_block(width: int = 3) -> int:
    """A port p with p..p+width-1 free on 127.0.0.1 (api, ingress, egress)."""
    for _ in range(200):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            base = probe.getsockname()[1]
        if base + width > 65535:
            continue
        sockets = []
        try:
            for offset in range(width):
                s = socket.socket()
                s.bind(("127.0.0.1", base + offset))
                sockets.append(s)
            return base
        except OSError:
            continue
        finally:
            for s in sockets:
                s.close()
    raise RuntimeError("no free block of ports")


def health_ok(port: int, timeout: float = 1.0) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=timeout) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def wait_for(predicate, deadline_s: float, step_s: float = 0.05) -> float | None:
    """Poll predicate until true; return seconds taken, None at the deadline."""
    start = time.perf_counter()
    while True:
        if predicate():
            return time.perf_counter() - start
        if time.perf_counter() - start > deadline_s:
            return None
        time.sleep(step_s)


def provision(assets: Path, home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    inst = Install(home)
    env = inst.env()

    def step(argv, what, timeout=900):
        proc = run_cmd(argv, env, timeout=timeout, cwd=str(inst.work))
        if proc.returncode != 0:
            tail = (proc.stdout + proc.stderr).decode(errors="replace")[-2000:]
            raise SystemExit(f"provision: {what} failed rc={proc.returncode}\n{tail}")
        return proc

    step(["bash", str(assets / "install.sh"), "--local", str(assets), "--yes"], "install.sh")
    step(
        [
            str(inst.cli),
            "init",
            "--non-interactive",
            "--no-start-gateway",
            "--no-verify",
            "--skip-install",
            "--connector",
            "none",
        ],
        "init",
    )
    port = free_port_block()
    py = inst.dc / ".venv" / "bin" / "python"
    step(
        [
            str(py),
            "-I",
            "-c",
            "import sys, yaml\n"
            "p, port = sys.argv[1], int(sys.argv[2])\n"
            "c = yaml.safe_load(open(p, encoding='utf-8'))\n"
            "c.setdefault('gateway', {})['api_port'] = port\n"
            "yaml.safe_dump(c, open(p, 'w', encoding='utf-8'), sort_keys=False)\n",
            str(inst.dc / "config.yaml"),
            str(port),
        ],
        "set api_port",
    )
    for connector in ("claude-code", "codex"):
        step([str(inst.cli), "setup", connector, "--yes", "--no-restart"], f"setup {connector}")
    step([str(inst.gateway), "start"], "gateway start", timeout=120)
    if wait_for(lambda: health_ok(port), 90) is None:
        raise SystemExit(f"provision: gateway did not answer /health on port {port} in 90 s")
    print(f"provisioned HOME={home} api_port={port}")


# ---------------------------------------------------------------- hooks


def registered_hook(inst: Install, connector: str) -> str:
    """The PreToolUse command the connector registered for DefenseClaw."""
    if connector == "claudecode":
        path = inst.home / ".claude" / "settings.json"
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        # Codex reads [[hooks.PreToolUse]] from config.toml (or hooks.json).
        path = inst.home / ".codex" / "config.toml"
        if path.exists():
            import tomllib  # Python 3.11+

            data = tomllib.loads(path.read_text(encoding="utf-8"))
        else:
            path = inst.home / ".codex" / "hooks.json"
            data = json.loads(path.read_text(encoding="utf-8"))
    for group in data.get("hooks", {}).get("PreToolUse", []):
        for hook in group.get("hooks", []):
            command = hook.get("command", "")
            if "defenseclaw" in command or str(inst.dc) in command:
                return command
    raise RuntimeError(f"no DefenseClaw PreToolUse hook registered in {path}")


def hook_payload(connector: str, work: Path, session: str) -> bytes:
    tool_use_id = "toolu_" + uuid.uuid4().hex[:20]
    if connector == "claudecode":
        body = {
            "session_id": session,
            "hook_event_name": "PreToolUse",
            "cwd": str(work),
            "transcript_path": "",
            "permission_mode": "default",
            "tool_name": "Read",
            "tool_input": {"file_path": str(work / "hello.txt")},
            "tool_use_id": tool_use_id,
        }
    else:
        body = {
            "session_id": session,
            "turn_id": "t-" + tool_use_id[-8:],
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": f"cat {work / 'hello.txt'}"},
            "tool_use_id": tool_use_id,
            "cwd": str(work),
            "model": "perf-harness",
            "transcript_path": None,
            "permission_mode": "default",
        }
    return json.dumps(body).encode()


DENY_RE = re.compile(rb'"(permissionDecision|decision)"\s*:\s*"(deny|block)"')


def call_hook(inst: Install, env: dict, command: str, connector: str, session: str):
    data = hook_payload(connector, inst.work, session)
    start = time.perf_counter()
    proc = subprocess.run(
        ["/bin/sh", "-c", command], input=data, env=env, cwd=str(inst.work), capture_output=True, timeout=60
    )
    elapsed = (time.perf_counter() - start) * 1000.0
    denied = proc.returncode == 2 or bool(DENY_RE.search(proc.stdout))
    return elapsed, proc.returncode, denied


def measure_hook(inst: Install, connector: str, prof: dict) -> dict:
    env = inst.env()
    command = registered_hook(inst, connector)
    session = f"dcperf-{connector}-{uuid.uuid4().hex[:8]}"
    for _ in range(3):  # warm the gateway session state
        call_hook(inst, env, command, connector, session)
    idle, idle_bad = [], 0
    for _ in range(prof["idle"]):
        ms, rc, denied = call_hook(inst, env, command, connector, session)
        idle.append(ms)
        idle_bad += int(rc != 0 or denied)
    burst, burst_bad = [], 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=prof["width"]) as pool:
        futures = [
            pool.submit(call_hook, inst, env, command, connector, f"{session}-b{i % prof['width']}")
            for i in range(prof["burst"])
        ]
        for fut in futures:
            ms, rc, denied = fut.result()
            burst.append(ms)
            burst_bad += int(rc != 0 or denied)
    return {
        "idle": dict(summarize(idle), not_allowed=idle_bad),
        "burst": dict(summarize(burst), width=prof["width"], not_allowed=burst_bad),
    }


def parse_strace(text: str) -> dict:
    """Processes and programs in one `strace -f -e trace=execve,clone,clone3,fork,vfork` log.

    strace -f prefixes each line with the pid and splits a call that another
    process interrupts into "<unfinished ...>" and "<... resumed>" lines, so
    the call name and its result are joined per pid. A clone with CLONE_THREAD
    is a thread, not a process. Returns the successful execs (program and the
    program of the process that started it) and, per new process, the program
    that forked it.
    """
    pending: dict[str, str] = {}
    program: dict[str, str] = {}
    parent: dict[str, str] = {}
    execs: list[tuple[str, str]] = []
    forks: list[str] = []
    for line in text.splitlines():
        m = re.match(r"(\d+)\s+(.*)$", line)
        if not m:
            continue
        pid, rest = m.groups()
        r = re.match(r"<\.\.\. (\w+) resumed>(.*)$", rest)
        if r:
            call, tail = r.group(1), pending.pop(pid + r.group(1), "") + r.group(2)
        else:
            c = re.match(r"(\w+)\((.*)$", rest)
            if not c:
                continue
            call, tail = c.group(1), c.group(2)
            if tail.endswith("<unfinished ...>"):
                pending[pid + call] = tail[: -len("<unfinished ...>")]
                continue
        result = re.search(r"\)\s*=\s*(-?\d+)", tail)
        if not result:
            continue
        rc = int(result.group(1))
        if call == "execve" and rc == 0:
            path = re.match(r'\s*"([^"]+)"', tail)
            name = os.path.basename(path.group(1)) if path else "?"
            execs.append((name, program.get(parent.get(pid, ""), "")))
            program[pid] = name
        elif call in ("clone", "clone3", "fork", "vfork") and rc > 0:
            if "CLONE_THREAD" in tail:
                continue
            forks.append(program.get(pid, "") or "agent")
            parent[str(rc)] = pid
            program[str(rc)] = program.get(pid, "")
    return {"execs": execs, "forks": forks}


def count_execs(inst: Install, connector: str, calls: int, eslogger_log: Path | None = None) -> dict | None:
    """Processes started per hook invocation, traced with strace -f (Linux)
    or read from an eslogger log (macOS, count_execs_eslogger).

    Counts every successful execve and every new process (fork or non-thread
    clone) in the hook's tree, including the /bin/sh the agent starts the
    hook command with; by_program says which program each exec ran and
    spawned_by which program started it.
    """
    if platform.system() == "Darwin":
        return count_execs_eslogger(inst, connector, calls, eslogger_log) if eslogger_log else None
    strace = shutil.which("strace")
    if not strace or platform.system() != "Linux":
        return None
    env = inst.env()
    command = registered_hook(inst, connector)
    session = f"dcperf-exec-{uuid.uuid4().hex[:8]}"
    names: dict[str, int] = {}
    spawned: dict[str, int] = {}
    forked: dict[str, int] = {}
    per_call, forks = [], []
    for _ in range(calls):
        with tempfile.NamedTemporaryFile(prefix="dcperf-strace-", delete=False) as tmp:
            trace = tmp.name
        try:
            subprocess.run(
                [
                    strace,
                    "-f",
                    "-qq",
                    "-e",
                    "trace=execve,clone,clone3,fork,vfork",
                    "-o",
                    trace,
                    "/bin/sh",
                    "-c",
                    command,
                ],
                input=hook_payload(connector, inst.work, session),
                env=env,
                cwd=str(inst.work),
                capture_output=True,
                timeout=60,
            )
            parsed = parse_strace(Path(trace).read_text(errors="replace"))
        finally:
            os.unlink(trace)
        per_call.append(len(parsed["execs"]))
        forks.append(len(parsed["forks"]))
        for by in parsed["forks"]:
            forked[by] = forked.get(by, 0) + 1
        for name, by in parsed["execs"]:
            names[name] = names.get(name, 0) + 1
            key = f"{by or 'agent'}>{name}"
            spawned[key] = spawned.get(key, 0) + 1

    def ranked(counts):
        return {k: round(v / calls, 2) for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))}

    return {
        "tracer": "strace",
        "per_call_p50": statistics.median(per_call),
        "per_call_max": max(per_call),
        "processes_per_call_p50": statistics.median(forks),
        "calls": calls,
        "by_program": ranked(names),
        "spawned_by": ranked(spawned),
        "forks_by": ranked(forked),
    }


def eslogger_time(text: str) -> float:
    """Seconds since the epoch of an eslogger "time" (UTC, "...T08:31:00.123456789Z")."""
    whole, _, fraction = text.rstrip("Z").partition(".")
    return calendar.timegm(time.strptime(whole, "%Y-%m-%dT%H:%M:%S")) + float("0." + (fraction or "0"))


def parse_eslogger(
    lines: list[str], windows: list[tuple[float, float]], runner_pid: int, gateway_pid: int | None
) -> dict:
    """Execs and processes per hook call in an `eslogger exec fork` JSON log (macOS).

    windows holds the wall-clock start and end of each traced call, which
    runner_pid ran with /bin/sh. A call's tree is the /bin/sh that runner_pid
    started in its window and every process forked below it there; on macOS
    /bin/sh runs bash, so a call's own shell is two execs. Endpoint Security
    drops events under load, so a call whose window has a gap in the seq_num
    of an event type is dropped rather than counted short. gateway_execs
    counts the execs of the gateway's descendants from the first call to the
    last: a per-user macOS gateway ran four dscl, each with a process-group
    watchdog shell, every 2 s while hooks came in (rel-1-0-6 GAP-0326).
    """
    events = []
    for line in lines:
        try:
            event = json.loads(line)
            at, seq = eslogger_time(event["time"]), (event["event_type"], event["seq_num"])
            body = event["event"]
            if "exec" in body:
                target = body["exec"]["target"]
                pid, ppid = target["audit_token"]["pid"], target["ppid"]
                events.append((at, "exec", seq, pid, ppid, os.path.basename(target["executable"]["path"])))
            elif "fork" in body:
                child = body["fork"]["child"]
                events.append((at, "fork", seq, child["audit_token"]["pid"], child["ppid"], ""))
        except (ValueError, KeyError, TypeError, AttributeError):
            continue  # a line eslogger was still writing, or another event
    events.sort(key=lambda event: event[0])
    parent: dict[int, int] = {}
    for _, _, _, pid, ppid, _ in events:
        parent.setdefault(pid, ppid)
    per_call, procs, names, dropped = [], [], {}, 0
    for start, end in windows:
        window = [e for e in events if start - 0.05 <= e[0] <= end + ESLOGGER_SLACK_S]
        gap = False
        for kind in ("exec", "fork"):
            seqs = sorted(e[2][1] for e in window if e[1] == kind)
            gap = gap or bool(seqs and seqs[-1] - seqs[0] + 1 != len(seqs))
        roots = [e for e in window if e[1] == "exec" and e[4] == runner_pid and e[5] == "sh"]
        if gap or not roots:
            dropped += 1
            continue
        tree, links, grown = {roots[0][3]}, {e[3]: e[4] for e in window}, True
        while grown:
            grown = False
            for pid, ppid in links.items():
                if ppid in tree and pid not in tree:
                    tree.add(pid)
                    grown = True
        execs = [e for e in window if e[1] == "exec" and e[3] in tree]
        per_call.append(len(execs))
        procs.append(len(tree))
        for e in execs:
            names[e[5]] = names.get(e[5], 0) + 1
    out: dict = {"calls": len(per_call), "calls_dropped": dropped}
    if per_call:
        out.update(
            per_call_p50=statistics.median(per_call),
            per_call_max=max(per_call),
            processes_per_call_p50=statistics.median(procs),
            by_program={
                k: round(v / len(per_call), 2) for k, v in sorted(names.items(), key=lambda kv: (-kv[1], kv[0]))
            },
        )
    if gateway_pid and windows:

        def below_gateway(pid: int) -> bool:
            for _ in range(64):
                if pid == gateway_pid:
                    return True
                pid = parent.get(pid, 0)
                if pid <= 1:
                    return False
            return False

        first, last = windows[0][0], windows[-1][1] + ESLOGGER_SLACK_S
        gateway = [e for e in events if e[1] == "exec" and first <= e[0] <= last and below_gateway(e[3])]
        programs: dict[str, int] = {}
        for e in gateway:
            programs[e[5]] = programs.get(e[5], 0) + 1
        out["gateway_execs_per_call"] = round(len(gateway) / len(windows), 2)
        out["gateway_by_program"] = dict(sorted(programs.items(), key=lambda kv: (-kv[1], kv[0])))
    return out


def _read_log_from(path: Path, offset: int) -> list[str]:
    with path.open("rb") as handle:
        handle.seek(offset)
        return handle.read().decode(errors="replace").splitlines()


def count_execs_eslogger(inst: Install, connector: str, calls: int, log: Path) -> dict:
    """Processes started per hook invocation on macOS, from an eslogger log.

    macOS has no strace, and only root may run `eslogger exec fork`, so the
    operator starts it for the run (README) and passes its log; the harness
    marks the time of each call, a second apart, and reads the events that
    eslogger wrote after the first call. eslogger writes through a buffer:
    the log is read once it holds an event from after the last call.
    """
    env = inst.env()
    command = registered_hook(inst, connector)
    session = f"dcperf-exec-{uuid.uuid4().hex[:8]}"
    offset = log.stat().st_size
    windows = []
    for _ in range(calls):
        start = time.time()
        subprocess.run(
            ["/bin/sh", "-c", command],
            input=hook_payload(connector, inst.work, session),
            env=env,
            cwd=str(inst.work),
            capture_output=True,
            timeout=60,
        )
        windows.append((start, time.time()))
        time.sleep(ESLOGGER_CALL_GAP_S)
    after = windows[-1][1] + ESLOGGER_SLACK_S + 0.5
    deadline = time.time() + 60
    while True:
        lines = _read_log_from(log, offset)
        newest = 0.0
        for line in reversed(lines[-50:]):
            try:
                newest = max(newest, eslogger_time(json.loads(line)["time"]))
            except (ValueError, KeyError, TypeError):
                continue
        if newest > after or time.time() > deadline:
            break
        time.sleep(1.0)
    parsed = parse_eslogger(lines, windows, os.getpid(), inst.gateway_pid())
    if not parsed["calls"]:
        raise RuntimeError(
            f"no traced call in {log} ({parsed['calls_dropped']} dropped): is `eslogger exec fork` writing it?"
        )
    return dict(parsed, tracer="eslogger")


# ---------------------------------------------------------------- gateway, CLI


def rss_kb(pid: int) -> int | None:
    status = Path(f"/proc/{pid}/status")
    if status.exists():
        for line in status.read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
        return None
    proc = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
    return int(proc.stdout.strip()) if proc.stdout.strip().isdigit() else None


def rss_split_kb(pid: int) -> dict:
    """The anonymous and the file-backed part of a process's memory.

    Linux: RssAnon and RssFile. macOS: the physical footprint (the dirty
    memory vmmap charges to the process, anon_kb) and the resident pages of
    its mapped files (file_kb, vmmap -summary). {} elsewhere or when vmmap
    cannot read the process. Until rel-1-0-6 GAP-0327 the file-backed part
    also held the audit.db pages the gateway read through SQLite's mmap, so it
    grew with the store; audit.db is no longer mapped.
    """
    status = Path(f"/proc/{pid}/status")
    out = {}
    if status.exists():
        for line in status.read_text().splitlines():
            key = line.split(":", 1)[0]
            if key in ("RssAnon", "RssFile"):
                out[key[3:].lower() + "_kb"] = int(line.split()[1])
        return out
    if platform.system() == "Darwin":
        try:
            proc = subprocess.run(["vmmap", "-summary", str(pid)], capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            return out
        out = parse_vmmap_summary(proc.stdout)
    return out


_VMMAP_UNITS = {"": 1 / 1024, "B": 1 / 1024, "K": 1, "M": 1024, "G": 1024**2, "T": 1024**3}


def _vmmap_kb(text: str) -> int | None:
    match = re.fullmatch(r"([\d.]+)([BKMGT]?)", text.strip())
    return int(float(match.group(1)) * _VMMAP_UNITS[match.group(2)]) if match else None


def parse_vmmap_summary(text: str) -> dict:
    """anon_kb (Physical footprint) and file_kb (resident size of the
    "mapped file" region type) from `vmmap -summary` output."""
    out = {}
    footprint = re.search(r"^Physical footprint:\s+(\S+)", text, re.M)
    mapped = re.search(r"^mapped file\s+(\S+)\s+(\S+)", text, re.M)
    if footprint and _vmmap_kb(footprint.group(1)) is not None:
        out["anon_kb"] = _vmmap_kb(footprint.group(1))
    if mapped and _vmmap_kb(mapped.group(2)) is not None:
        out["file_kb"] = _vmmap_kb(mapped.group(2))
    return out


def measure_restart(inst: Install, count: int) -> dict:
    env = inst.env()
    port = inst.api_port()
    totals, commands = [], []
    for _ in range(count):
        old = inst.gateway_pid()
        start = time.perf_counter()
        proc = run_cmd([str(inst.gateway), "restart"], env, timeout=180, cwd=str(inst.work))
        commands.append((time.perf_counter() - start) * 1000.0)
        if proc.returncode != 0:
            raise RuntimeError(f"gateway restart rc={proc.returncode}")

        def ready() -> bool:
            pid = inst.gateway_pid()
            return pid is not None and pid != old and health_ok(port, 0.5)

        if wait_for(ready, 120, 0.02) is None:
            raise RuntimeError("gateway did not answer /health from a new process in 120 s")
        totals.append((time.perf_counter() - start) * 1000.0)
    return {"to_api_ready": summarize(totals), "command": summarize(commands)}


def time_cli(inst: Install, argv: list[str], count: int, ok_codes=(0,)) -> dict:
    env = inst.env()
    walls, codes = [], set()
    for _ in range(count):
        start = time.perf_counter()
        proc = run_cmd([str(inst.cli)] + argv, env, timeout=600, cwd=str(inst.work))
        walls.append((time.perf_counter() - start) * 1000.0)
        codes.add(proc.returncode)
    out = summarize(walls)
    out["exit_codes"] = sorted(codes)
    if not codes <= set(ok_codes):
        out["error"] = f"exit codes {sorted(codes)}"
    return out


# ---------------------------------------------------------------- run


GROUPS = ("hook", "execs", "cli", "restart", "rss")


def measure(
    inst: Install,
    rss_idle: int = DEFAULT_RSS_IDLE_S,
    only: tuple[str, ...] = GROUPS,
    eslogger_log: Path | None = None,
) -> dict:
    prof = dict(PLAN, rss_idle=rss_idle)
    metrics: dict = {}
    errors: dict = {}

    def attempt(name, fn):
        try:
            return fn()
        except Exception as exc:  # recorded, and a gated metric then reads "missing"
            errors[name] = f"{type(exc).__name__}: {exc}"[:400]
            return None

    port = inst.api_port()
    if not health_ok(port):
        raise SystemExit(f"gateway is not answering /health on port {port}; start it first")
    hooks = {}
    for connector in ("claudecode", "codex") if "hook" in only else ():
        value = attempt(f"hook.{connector}", lambda c=connector: measure_hook(inst, c, prof))
        if value:
            hooks[connector] = value
    if hooks:
        metrics["hook"] = hooks
    execs = None
    if "execs" in only:
        execs = attempt("hook_execs", lambda: count_execs(inst, "claudecode", prof["exec_calls"], eslogger_log))
    if execs:
        metrics["hook_execs"] = {"claudecode": execs}
    cli = {}
    for name, argv, count, ok in (
        ("status", ["status"], prof["status"], (0,)),
        # doctor exits 1 when a check warns or fails (no LLM key here); the wall time still counts
        ("doctor", ["doctor"], prof["doctor"], (0, 1)),
        ("setup_claudecode", ["setup", "claude-code", "--yes", "--no-restart"], prof["setup"], (0,)),
        ("skill_scan", ["skill", "scan", "--path", str(FIXTURE_SKILL), "--no-use-llm", "--json"], prof["scan"], (0,)),
    ):
        if "cli" not in only:
            break
        value = attempt(f"cli.{name}", lambda a=argv, n=count, o=ok: time_cli(inst, a, n, o))
        if value and "error" in value:
            errors[f"cli.{name}"] = value.pop("error")
            value = None
        if value:
            cli[name] = value
    if cli:
        metrics["cli"] = cli
    restart = attempt("restart", lambda: measure_restart(inst, prof["restarts"])) if "restart" in only else None
    if restart:
        metrics["gateway_restart"] = restart
    if "rss" not in only:
        return _result(inst, metrics, errors, only)
    # RSS: the gateway started by the last restart, after rss_idle seconds of no traffic
    time.sleep(prof["rss_idle"])
    pid = inst.gateway_pid()
    rss = rss_kb(pid) if pid else None
    if rss:
        db = inst.dc / "audit.db"
        metrics["gateway_rss_kb"] = dict(
            after_idle=rss,
            idle_s=prof["rss_idle"],
            audit_db_kb=db.stat().st_size // 1024 if db.exists() else 0,
            **rss_split_kb(pid),
        )
    else:
        errors["gateway_rss"] = "no gateway pid or RSS"
    return _result(inst, metrics, errors, only)


def cpu_score_ms(rounds: int = 5) -> float:
    """Best of `rounds` timings of a fixed single-thread Python workload.

    CI runners of one label differ in CPU: the skill scan took 4.95, 7.51
    and 8.45 s on three ubuntu-latest runs of the same commit (each within
    1% across its own 3 scans). The score lets a result be compared across
    hosts; it is recorded with every result.
    """
    payload = {"items": [{"id": i, "name": f"item-{i}", "tags": ["a", "b", str(i)]} for i in range(2000)]}
    best = float("inf")
    for _ in range(rounds):
        start = time.perf_counter()
        total = 0
        for i in range(1_500_000):
            total += i * i % 7
        for _ in range(25):
            json.loads(json.dumps(payload))
        best = min(best, (time.perf_counter() - start) * 1000.0)
    return round(best, 1)


def _cpu_model() -> str:
    """CPU model name (Linux /proc/cpuinfo; platform.processor() elsewhere).

    Runner CPUs differ between CI runs, so a result names the one it ran on.
    """
    try:
        for line in Path("/proc/cpuinfo").read_text(errors="replace").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def _result(inst: Install, metrics: dict, errors: dict, only: tuple[str, ...]) -> dict:
    cpus = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count()
    return {
        "schema": SCHEMA,
        "groups": list(only),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "cpus": cpus,
            "cpu_model": _cpu_model(),
            "cpu_score_ms": cpu_score_ms(),
            "load1": os.getloadavg()[0] if hasattr(os, "getloadavg") else None,
        },
        "version": version_of(inst),
        "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "metrics": metrics,
        "errors": errors,
    }


def version_of(inst: Install) -> str:
    try:
        proc = run_cmd([str(inst.gateway), "--version"], inst.env(), timeout=30)
        return proc.stdout.decode(errors="replace").strip().splitlines()[0][:120]
    except (OSError, IndexError, subprocess.SubprocessError):
        return "unknown"


def one_line(result: dict) -> str:
    m = result["metrics"]
    parts = []
    for connector, value in m.get("hook", {}).items():
        i, b = value["idle"], value["burst"]
        parts.append(
            f"{connector} idle p50/p95/max {i['p50_ms']:.0f}/{i['p95_ms']:.0f}/{i['max_ms']:.0f} ms"
            f" burst{b['width']} p95 {b['p95_ms']:.0f} ms"
        )
    ex = m.get("hook_execs", {}).get("claudecode")
    if ex and "per_call_p50" in ex:
        parts.append(f"execs/hook {ex['per_call_p50']:g}")
    if ex and "gateway_execs_per_call" in ex:
        parts.append(f"gateway execs/hook {ex['gateway_execs_per_call']:g}")
    r = m.get("gateway_restart")
    if r:
        parts.append(f"restart {r['to_api_ready']['p50_ms']:.0f} ms")
    for name, value in m.get("cli", {}).items():
        parts.append(f"{name} {value['p50_ms']:.0f} ms")
    rss = m.get("gateway_rss_kb")
    if rss:
        split = ""
        if "anon_kb" in rss and "file_kb" in rss:
            split = f" (anon {rss['anon_kb'] / 1024:.0f}, file {rss['file_kb'] / 1024:.0f})"
        parts.append(f"rss after {rss['idle_s']} s idle {rss['after_idle'] / 1024:.0f} MiB{split}")
    if result.get("errors"):
        parts.append(f"errors {sorted(result['errors'])}")
    return "dcperf: " + "; ".join(parts)


def _groups(text: str) -> tuple[str, ...]:
    groups = tuple(g.strip() for g in text.split(",") if g.strip())
    unknown = sorted(set(groups) - set(GROUPS))
    if unknown or not groups:
        raise SystemExit(f"--only: unknown or empty groups {unknown}; choose from {','.join(GROUPS)}")
    return groups


def reexec_under_install_python(argv: list[str]) -> None:
    """Run again under the DefenseClaw venv Python when this one is older
    than 3.11 (tomllib, and the syntax above): macOS ships python3 3.9.

    The venv is the one of the install --home names (HOME by default). It
    runs isolated (-I), as the harness needs only the standard library.
    """
    if sys.version_info >= (3, 11):
        return
    home = Path.home()
    for i, arg in enumerate(argv):
        if arg == "--home" and i + 1 < len(argv):
            home = Path(argv[i + 1])
        elif arg.startswith("--home="):
            home = Path(arg.split("=", 1)[1])
    python = home / ".defenseclaw" / ".venv" / "bin" / "python"
    if os.environ.get("DCPERF_REEXEC") != "1" and os.access(python, os.X_OK):
        os.environ["DCPERF_REEXEC"] = "1"
        os.execv(str(python), [str(python), "-I", str(Path(__file__).resolve())] + argv)
    raise SystemExit(f"dcperf needs Python 3.11+, this is {platform.python_version()}; no DefenseClaw venv at {python}")


def main(argv: list[str] | None = None) -> int:
    reexec_under_install_python(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("provision")
    p.add_argument("--assets", type=Path, required=True)
    p.add_argument("--home", type=Path, required=True)
    r = sub.add_parser("run")
    r.add_argument("--home", type=Path, default=Path.home())
    r.add_argument(
        "--rss-idle", type=int, default=DEFAULT_RSS_IDLE_S, help="seconds of no traffic before the RSS sample"
    )
    r.add_argument("--only", default=",".join(GROUPS), help=f"comma-separated measurement groups ({','.join(GROUPS)})")
    r.add_argument("--out", type=Path)
    r.add_argument("--budgets", type=Path)
    r.add_argument("--column", default="linux-per-user")
    r.add_argument(
        "--eslogger-log",
        type=Path,
        help="macOS: the JSON log a root `eslogger exec fork` writes during the run (counts execs per hook)",
    )
    c = sub.add_parser("compare")
    c.add_argument("result", type=Path, nargs="+", help="one result, or several passes to merge (later wins)")
    c.add_argument("--budgets", type=Path, required=True)
    c.add_argument("--column", default="linux-per-user")
    args = parser.parse_args(argv)

    if args.cmd == "provision":
        provision(args.assets.resolve(), args.home.resolve())
        return 0
    if args.cmd == "compare":
        result = merge_results([json.loads(path.read_text(encoding="utf-8")) for path in args.result])
    else:
        result = measure(Install(args.home.resolve()), args.rss_idle, _groups(args.only), args.eslogger_log)
        text = json.dumps(result, indent=1, sort_keys=True)
        if args.out:
            args.out.write_text(text + "\n", encoding="utf-8")
        else:
            print(text)
        print(one_line(result))
    if getattr(args, "budgets", None):
        report = compare(result, json.loads(args.budgets.read_text(encoding="utf-8")), args.column)
        print(compare_text(report))
        return 0 if report["ok"] else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
