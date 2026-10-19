# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Kill the tracked contributor harness after a fixed contained tree is ready."""

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import time


def owned_processes(prefixes, known_pids):
    quoted = ["'" + (str(path).rstrip("\\/") + "\\").replace("'", "''") + "'" for path in prefixes]
    predicate = " -or ".join(
        f"$_.ExecutablePath.StartsWith({path}, [StringComparison]::OrdinalIgnoreCase)" for path in quoted
    )
    known = ",".join(str(int(pid)) for pid in known_pids)
    command = (
        "$ErrorActionPreference='Stop'; $known=@("
        + known
        + "); $items=@(Get-CimInstance Win32_Process | Where-Object { "
        "($known -contains $_.ProcessId) -or ($_.ExecutablePath -and ("
        + predicate
        + ")) } | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath); "
        "ConvertTo-Json -InputObject $items -Compress"
    )
    shell = pathlib.Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run(
        [str(shell), "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    return json.loads(result.stdout)


def run(args):
    case = args.case_root.resolve()
    if case.exists():
        raise ValueError("use a fresh private parent-death case directory")
    verification = json.loads(args.verification.read_text(encoding="utf-8-sig"))
    command = [
        str(args.harness.resolve()),
        "-verification",
        str(args.verification.resolve()),
        "-probe",
        str(args.probe.resolve()),
        "-probe-sha256",
        args.probe_sha256,
        "-case-root",
        str(case),
        "-mode",
        "parent-death",
    ]
    stdout_path = case.parent / (case.name + "-controller-stdout.txt")
    stderr_path = case.parent / (case.name + "-controller-stderr.txt")
    ready_path = case / "parent-death-ready.json"
    ready = None
    before, remaining, known_pids = [], [], []
    error = None
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        deadline = time.monotonic() + 12
        try:
            while time.monotonic() < deadline and process.poll() is None:
                if ready_path.is_file():
                    try:
                        ready = json.loads(ready_path.read_text())
                        break
                    except json.JSONDecodeError:
                        pass
                time.sleep(0.02)
            if ready is None:
                raise ValueError("contained descendant readiness was not observed")
            tree = re.search(r'"mode":"tree","pid":(\d+)', ready["output"])
            leaf = re.search(r'"detail":(\d+),"ok":true,"probe":"descendant_ready"', ready["output"])
            if not tree or not leaf:
                raise ValueError("fixed tree and leaf identities were not observed")
            known_pids = [int(ready["axis_pid"]), int(tree[1]), int(leaf[1])]
            before = owned_processes([case, pathlib.Path(verification["payload"])], known_pids)
            visible = {int(item["ProcessId"]) for item in before if item.get("ExecutablePath")}
            if not set(known_pids) <= visible:
                raise ValueError("CIM could not inspect all known task-owned processes; cleanup remains unqualified")
            # Popen retains the owned process handle. No inferred child PID
            # is killed; OS Job closure must perform descendant teardown.
            process.kill()
            process.wait(timeout=5)
            remaining = before
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                remaining = owned_processes([case, pathlib.Path(verification["payload"])], known_pids)
                if not remaining:
                    break
                time.sleep(0.1)
        except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
            error = str(exc)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    passed = error is None and ready is not None and len(before) >= 3 and not remaining
    result = {
        "mode": "parent-death",
        "qualified_customer_runtime": False,
        "passed": passed,
        "command": command,
        "tracked_harness_pid": process.pid,
        "harness_exit_code": process.returncode,
        "readiness": ready,
        "error": error,
        "known_task_pids": known_pids,
        "before_processes": before,
        "remaining_processes": remaining,
        "scope": (
            "observed task-owned AXIS/MXC/fixed payload/descendant tree after killing its tracked harness handle; "
            "no inferred descendant was signaled"
        ),
    }
    result_path = (
        case / "parent-death-result.json" if case.exists() else case.parent / (case.name + "-parent-death-result.json")
    )
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return passed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness", type=pathlib.Path, required=True)
    parser.add_argument("--verification", type=pathlib.Path, required=True)
    parser.add_argument("--probe", type=pathlib.Path, required=True)
    parser.add_argument("--probe-sha256", required=True)
    parser.add_argument("--case-root", type=pathlib.Path, required=True)
    sys.exit(0 if run(parser.parse_args()) else 1)
