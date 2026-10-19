# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Run only the reviewed signed Claude 2.1.292 --version, offline in MXC."""

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

from run_headless import sha, yaml_path

CLAUDE_SHA256 = "eb95bb65955f8b1702e800815f9a2c0388a5de0f196c354c7ee1dd5cb9a2ba23"
CLAUDE_SIZE = 254858400
EXPECTED_VERSION = "2.1.292 (Claude Code)"
AXIS = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
MXC = "1736b48398c3fe4d1315b2311c0951cc893eb3ae"


def run(args):
    claude = args.claude.resolve(strict=True)
    if claude.name.lower() != "claude.exe" or claude.stat().st_size != CLAUDE_SIZE or sha(claude) != CLAUDE_SHA256:
        raise ValueError("only the reviewed Claude 2.1.292 binary is accepted")
    system = pathlib.Path(os.environ["SystemRoot"])
    if not system.is_absolute():
        raise ValueError("absolute Windows system directory required")
    shell = system / "System32/WindowsPowerShell/v1.0/powershell.exe"
    # Windows PowerShell must load its own security module, even when this
    # contributor script was launched from PowerShell 7. Do not inherit caller
    # module paths or credential-bearing environment into the verifier either.
    signature_environment = {
        "SYSTEMROOT": str(system),
        "WINDIR": str(system),
        "PSModulePath": str(system / "System32/WindowsPowerShell/v1.0/Modules"),
    }
    literal = "'" + str(claude).replace("'", "''") + "'"
    signature_command = (
        "$ErrorActionPreference='Stop'; $s=Get-AuthenticodeSignature -LiteralPath "
        + literal
        + "; @{status=$s.Status.ToString();subject=$s.SignerCertificate.Subject;"
        "thumbprint=$s.SignerCertificate.Thumbprint} | ConvertTo-Json -Compress"
    )
    signature = json.loads(
        subprocess.check_output(
            [str(shell), "-NoProfile", "-NonInteractive", "-Command", signature_command],
            env=signature_environment,
            text=True,
            timeout=15,
        )
    )
    if signature["status"] != "Valid" or 'O="Anthropic, PBC"' not in signature["subject"]:
        raise ValueError("valid Anthropic Authenticode signature required")
    verification = json.loads(args.verification.read_text(encoding="utf-8-sig"))
    if (
        verification.get("verified") is not True
        or verification.get("variant") != "inherited-console-relay"
        or verification.get("axis_commit") != AXIS
        or verification.get("mxc_commit") != MXC
    ):
        raise ValueError("the explicitly verified paired relay artifact is required")
    payload = pathlib.Path(verification["payload"])
    overlays = verification.get("contributor_relay_overlays") or {}
    if set(overlays) != {"axis", "mxc"}:
        raise ValueError("both reviewed relay overlays are required")
    for entry, expected in [
        (verification.get("contributor_overlay") or {}, "AXIS_INHERITED_CONSOLE.patch"),
        (overlays["axis"], "AXIS_CONSOLE_CTRL_C_RELAY.patch"),
        (overlays["mxc"], "MXC_CONSOLE_CTRL_C_RELAY.patch"),
    ]:
        if entry.get("path") != expected or sha(payload / expected) != entry.get("sha256"):
            raise ValueError("retained reviewed source overlay changed")
    names = set()
    for entry in verification["binaries"]:
        name = pathlib.PurePosixPath(entry["path"])
        if name.parent != pathlib.PurePosixPath("bin") or name.name in {".", ".."} or entry["path"] in names:
            raise ValueError("invalid verified runtime binary inventory")
        names.add(entry["path"])
        path = payload / entry["path"]
        if path.stat().st_size != entry["size_bytes"] or sha(path) != entry["sha256"]:
            raise ValueError("verified runtime changed before execution")
    if not {"bin/axis.exe", "bin/axisd.exe", "bin/wxc-exec.exe"} <= names:
        raise ValueError("required paired runtime binaries absent")
    case = args.case_root.resolve()
    if case.exists():
        raise ValueError("use one fresh private Claude-version case directory")
    workspace, home, temporary = case / "workspace", case / "private-home", case / "private-tmp"
    appdata, localappdata = home / "AppData/Roaming", home / "AppData/Local"
    for directory in [workspace, home, temporary, appdata, localappdata]:
        directory.mkdir(parents=True, exist_ok=True)
    contained = workspace / "claude.exe"
    shutil.copyfile(claude, contained)
    if sha(contained) != CLAUDE_SHA256:
        raise ValueError("private Claude fixture digest mismatch")
    policy = case / "policy.yaml"
    policy.write_text(
        "version: 1\nname: defenseclaw-windows-claude-version\n"
        "runtime: {containment: process, provider: mxc}\n"
        "filesystem:\n  compatibility: hard_requirement\n"
        f"  read_write: ['{{workspace}}', {yaml_path(temporary)}]\n"
        "process:\n  max_processes: 0\n  max_memory_mb: 0\n  cpu_rate_percent: 0\n"
        "  timeout_sec: 10\nnetwork: {mode: block}\n",
    )
    environment = {
        "SYSTEMROOT": str(system),
        "WINDIR": str(system),
        "COMSPEC": str(system / "System32/cmd.exe"),
        "PATH": str(system / "System32") + ";" + str(system),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "APPDATA": str(appdata),
        "LOCALAPPDATA": str(localappdata),
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local/share"),
        "XDG_CACHE_HOME": str(home / ".cache"),
    }
    # Fixed sole workload invocation: no prompt, login, model, hook, or arbitrary
    # argument path is accepted. The policy also requests blocked networking.
    command = [
        str(payload / "bin/axis.exe"),
        "--socket",
        "127.0.0.1:0",
        "run",
        "--policy",
        str(policy),
        "--",
        str(contained),
        "--version",
    ]
    started = time.monotonic()
    timed_out = False
    with (case / "stdout.txt").open("wb") as stdout, (case / "stderr.txt").open("wb") as stderr:
        process = subprocess.Popen(
            command, cwd=workspace, env=environment, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr
        )
        try:
            code = process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()  # The tracked Popen handle; no inferred child PID.
            code = process.wait(timeout=5)
    outputs = {}
    for name in ["stdout", "stderr"]:
        path = case / (name + ".txt")
        if path.stat().st_size > 128 * 1024:
            raise ValueError("fixed version output exceeded its bound")
        outputs[name] = path.read_text(encoding="utf-8", errors="replace")
    passed = not timed_out and code == 0 and EXPECTED_VERSION in outputs["stdout"].splitlines()
    record = {
        "passed": passed,
        "qualified_customer_runtime": False,
        "scope": "signed reviewed binary --version only; no authentication/model/hook qualification",
        "command": command,
        "claude_sha256": CLAUDE_SHA256,
        "authenticode": signature,
        "policy_sha256": sha(policy),
        "artifact_archive_sha256": verification["archive_sha256"],
        "variant": verification["variant"],
        "environment_keys": sorted(environment),
        "exit_code": code,
        "parent_timeout": timed_out,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        **outputs,
        "cleanup_scope": (
            "tracked AXIS leader reaped; owned descendants and profile resources require separate inspection"
        ),
    }
    (case / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    return passed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verification", required=True, type=pathlib.Path)
    parser.add_argument("--claude", required=True, type=pathlib.Path)
    parser.add_argument("--case-root", required=True, type=pathlib.Path)
    sys.exit(0 if run(parser.parse_args()) else 1)
