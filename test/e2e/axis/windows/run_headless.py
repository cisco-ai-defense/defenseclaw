# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Run one fixed offline Windows MXC probe from an already verified bundle."""

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import stat
import subprocess
import sys
import time

import verify_artifact

OVERLAY_ROOT = pathlib.Path(__file__).resolve().parent / "patches"
VARIANTS = {"baseline", "inherited-console", "inherited-console-relay"}
REVIEWED_OVERLAYS = {
    "AXIS_INHERITED_CONSOLE.patch": "axis-inherited-console.patch",
    "AXIS_CONSOLE_CTRL_C_RELAY.patch": "axis-console-ctrl-c-relay.patch",
    "MXC_CONSOLE_CTRL_C_RELAY.patch": "mxc-console-ctrl-c-relay.patch",
}


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def yaml_path(path):
    return "'" + str(path).replace("'", "''") + "'"


def checked_overlay(entry, payload, name, kind):
    if not isinstance(entry, dict) or entry.get("path") != name or entry.get("kind") != kind:
        raise ValueError("reviewed Windows overlay metadata differs")
    digest = entry.get("sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("reviewed Windows overlay digest missing")
    if sha(OVERLAY_ROOT / REVIEWED_OVERLAYS[name]) != digest or sha(payload / name) != digest:
        raise ValueError("reviewed Windows overlay bytes differ")


def checked_bundle(verification_path):
    verification = json.loads(verification_path.read_text(encoding="utf-8-sig"))
    variant = verification.get("variant", "baseline") if isinstance(verification, dict) else None
    if (
        not isinstance(verification, dict)
        or verification.get("verified") is not True
        or not isinstance(variant, str)
        or variant not in VARIANTS
        or verification.get("axis_commit") != verify_artifact.AXIS
        or verification.get("mxc_commit") != verify_artifact.MXC
        or not isinstance(verification.get("workflow_commit"), str)
        or re.fullmatch(r"[0-9a-f]{40}", verification["workflow_commit"]) is None
        or not isinstance(verification.get("archive_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", verification["archive_sha256"]) is None
    ):
        raise ValueError("an exact reviewed AXIS/MXC artifact variant is required")
    raw_payload = verification.get("payload")
    if not isinstance(raw_payload, str) or not pathlib.Path(raw_payload).is_absolute():
        raise ValueError("an absolute verified payload is required")
    payload = pathlib.Path(raw_payload)
    relay = verification.get("contributor_relay_overlays")
    if variant == "baseline":
        if verification.get("contributor_overlay") is not None or relay is not None:
            raise ValueError("baseline cannot contain a Windows contributor overlay")
    else:
        checked_overlay(
            verification.get("contributor_overlay"),
            payload,
            "AXIS_INHERITED_CONSOLE.patch",
            "windows_inherited_console_experiment",
        )
        if variant == "inherited-console":
            if relay is not None:
                raise ValueError("relay overlays require the reviewed paired relay variant")
        else:
            if not isinstance(relay, dict) or set(relay) != {"axis", "mxc"}:
                raise ValueError("both reviewed relay overlays are required")
            for entry, name in [
                (relay["axis"], "AXIS_CONSOLE_CTRL_C_RELAY.patch"),
                (relay["mxc"], "MXC_CONSOLE_CTRL_C_RELAY.patch"),
            ]:
                checked_overlay(entry, payload, name, "windows_console_ctrl_c_relay_experiment")
    entries = verification.get("binaries")
    if not isinstance(entries, list):
        raise ValueError("verified binary inventory is required")
    allowed = {"bin/" + name for name in verify_artifact.BINARIES | verify_artifact.OPTIONAL_BINARIES}
    required = {"bin/" + name for name in verify_artifact.BINARIES}
    names = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid verified binary inventory")
        name, digest, size = entry.get("path"), entry.get("sha256"), entry.get("size_bytes")
        if (
            not isinstance(name, str)
            or name not in allowed
            or name in names
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or type(size) is not int
            or size < 1
        ):
            raise ValueError("invalid verified binary inventory")
        names.add(name)
    if not required <= names:
        raise ValueError("required paired runtime binaries absent")
    bin_dir = payload / "bin"
    if not bin_dir.is_dir() or bin_dir.is_symlink() or getattr(bin_dir.lstat(), "st_file_attributes", 0) & 0x400:
        raise ValueError("verified bin directory changed")
    if {path.name for path in bin_dir.iterdir()} != {pathlib.PurePosixPath(name).name for name in names}:
        raise ValueError("verified bin inventory changed")
    for entry in entries:
        file = payload / entry["path"]
        info = file.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
            or info.st_size != entry["size_bytes"]
            or sha(file) != entry["sha256"]
        ):
            raise ValueError("verified binary changed before execution: " + entry["path"])
    return verification, payload


def run(verification_path, probe, case_root, mode):
    if mode not in {"boundary", "exit23", "timeout"}:
        raise ValueError("unsupported fixed headless case")
    verification, payload = checked_bundle(verification_path)
    if case_root.exists():
        raise ValueError("use a fresh task-owned case directory")
    workspace = case_root / "workspace"
    home = case_root / "private-home"
    temporary = case_root / "private-tmp"
    readonly = case_root / "readonly"
    appdata = home / "AppData/Roaming"
    localappdata = home / "AppData/Local"
    for directory in [workspace, home, temporary, readonly, appdata, localappdata]:
        directory.mkdir(parents=True, exist_ok=True)
    (case_root / "outside-sentinel.txt").write_bytes(b"AXIS_OUTSIDE_SENTINEL")
    (readonly / "reference.txt").write_bytes(b"AXIS_READONLY_SENTINEL")
    contained_probe = workspace / "axis-windows-fixed-probe.exe"
    shutil.copyfile(probe, contained_probe)
    timeout = 1 if mode == "timeout" else 6
    policy = case_root / "policy.yaml"
    policy.write_text(
        "version: 1\nname: defenseclaw-windows-offline-probe\n"
        "runtime: {containment: process, provider: mxc}\n"
        "filesystem:\n  compatibility: hard_requirement\n"
        f"  read_only: [{yaml_path(readonly)}]\n"
        f"  read_write: ['{{workspace}}', {yaml_path(temporary)}]\n"
        f"  deny: [{yaml_path(case_root / 'outside-sentinel.txt')}]\n"
        "process:\n  max_processes: 0\n  max_memory_mb: 0\n  cpu_rate_percent: 0\n"
        f"  timeout_sec: {timeout}\nnetwork: {{mode: block}}\n",
        encoding="utf-8",
    )
    system = pathlib.Path(os.environ["SystemRoot"])
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
        "OPENAI_API_KEY": "AXIS_SYNTHETIC_CANARY_NOT_A_REAL_CREDENTIAL",
    }
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp,
        socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as tcp6,
        socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp6,
    ):
        tcp.bind(("127.0.0.1", 0))
        tcp.listen(1)
        udp.bind(("127.0.0.1", 0))
        tcp6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        udp6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        tcp6.bind(("::1", 0))
        tcp6.listen(1)
        udp6.bind(("::1", 0))
        # Positive controls prove the exact host endpoints accept ordinary
        # host traffic before the contained sender is tested.
        for family, listener, datagram in [(socket.AF_INET, tcp, udp), (socket.AF_INET6, tcp6, udp6)]:
            listener.settimeout(2)
            datagram.settimeout(2)
            with socket.socket(family, socket.SOCK_STREAM) as control:
                control.settimeout(2)
                control.connect(listener.getsockname())
                connection, _ = listener.accept()
                connection.close()
            with socket.socket(family, socket.SOCK_DGRAM) as control:
                control.sendto(b"AXIS_HOST_POSITIVE_CONTROL", datagram.getsockname())
                received, _ = datagram.recvfrom(512)
                if received != b"AXIS_HOST_POSITIVE_CONTROL":
                    raise ValueError("host UDP positive control failed")
        command = [
            str(payload / "bin/axis.exe"),
            "--socket",
            "127.0.0.1:0",
            "run",
            "--policy",
            str(policy),
            "--",
            str(contained_probe),
            "-mode",
            mode,
            "-root",
            str(case_root),
            "-tcp-port",
            str(tcp.getsockname()[1]),
            "-udp-port",
            str(udp.getsockname()[1]),
            "-tcp6-port",
            str(tcp6.getsockname()[1]),
            "-udp6-port",
            str(udp6.getsockname()[1]),
        ]
        stdout_path, stderr_path = case_root / "stdout.txt", case_root / "stderr.txt"
        timed_out = False
        started = time.time()
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                command, cwd=workspace, env=environment, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr
            )
            try:
                code = process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                timed_out = True
                # This is the tracked live AXIS process handle. No raw PID or
                # inferred descendant is signaled after its leader is reaped.
                process.kill()
                code = process.wait(timeout=5)
        outputs = {}
        for name, path in [("stdout", stdout_path), ("stderr", stderr_path)]:
            if path.stat().st_size > 128 * 1024:
                raise ValueError("unexpectedly large fixed-probe output")
            outputs[name] = path.read_text(encoding="utf-8", errors="replace")
        events = []
        for line in outputs["stdout"].splitlines():
            if line.startswith('{"'):
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "probe" in event:
                    events.append(event)
        network_observations = {}
        for name, endpoint in [("tcp4", tcp), ("udp4", udp), ("tcp6", tcp6), ("udp6", udp6)]:
            endpoint.settimeout(0.25)
            arrived = False
            try:
                if name.startswith("udp"):
                    endpoint.recvfrom(512)
                else:
                    connection, _ = endpoint.accept()
                    connection.close()
                arrived = True
            except TimeoutError:
                pass
            network_observations[name] = {"host_positive_control_passed": True, "contained_traffic_observed": arrived}
        expected = {
            "started",
            "appcontainer_token",
            "cwd",
            "private_HOME",
            "private_USERPROFILE",
            "private_APPDATA",
            "private_LOCALAPPDATA",
            "private_TEMP",
            "private_TMP",
            "secret_environment_absent",
            "workspace_write",
            "outside_read_denied",
            "outside_write_denied",
            "readonly_read",
            "readonly_write_denied",
            "loopback_tcp_denied",
            "loopback_udp_send",
            "loopback_tcp6_denied",
            "loopback_udp6_send",
        }
        outside_unchanged = (case_root / "outside-sentinel.txt").read_bytes() == b"AXIS_OUTSIDE_SENTINEL"
        readonly_unchanged = (readonly / "reference.txt").read_bytes() == b"AXIS_READONLY_SENTINEL"
        payload_started = any(e["probe"] == "started" and e["ok"] for e in events)
        boundary_pass = (
            mode == "boundary"
            and code == 0
            and not timed_out
            and outside_unchanged
            and readonly_unchanged
            and not any(item["contained_traffic_observed"] for item in network_observations.values())
            and expected == {e["probe"] for e in events}
            and all(e["ok"] for e in events)
        )
        case_pass = (
            payload_started
            and not timed_out
            and (
                boundary_pass
                or mode == "exit23"
                and code == 23
                or mode == "timeout"
                and code == 1
                and "Windows MXC process timed out after 1 seconds" in outputs["stderr"]
            )
        )
        record = {
            "platform": "native_windows",
            "mode": mode,
            "qualified_customer_runtime": False,
            "axis_source": verification["axis_commit"],
            "mxc_source": verification["mxc_commit"],
            "artifact_archive_sha256": verification["archive_sha256"],
            "probe_sha256": sha(probe),
            "policy_sha256": sha(policy),
            "command": command,
            "cwd": str(workspace),
            "environment_keys": sorted(environment),
            "synthetic_credential_canary": True,
            "parent_pid": process.pid,
            "parent_timeout": timed_out,
            "elapsed_seconds": round(time.time() - started, 3),
            "exit_code": code,
            "payload_started": payload_started,
            "case_passed": case_pass,
            "boundary_checks_passed": boundary_pass,
            "events": events,
            **outputs,
            "network_observations": network_observations,
            "network_observation_scope": (
                "fixed IPv4/IPv6 loopback TCP/UDP canaries only; each receiver checked for 250ms after payload exit"
            ),
            "outside_canary_unchanged": outside_unchanged,
            "readonly_canary_unchanged": readonly_unchanged,
            "cleanup_scope": (
                "loopback listener sockets closed; AXIS leader reaped; descendant inspection remains required"
            ),
            "cli_mode_note": (
                "private unavailable TCP port 0 is a contributor-only standalone-selection probe, "
                "not a production API contract"
            ),
        }
    (case_root / "result.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))
    return case_pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verification", required=True, type=pathlib.Path)
    parser.add_argument("--probe", required=True, type=pathlib.Path)
    parser.add_argument("--case-root", required=True, type=pathlib.Path)
    parser.add_argument("--mode", choices=["boundary", "exit23", "timeout"], default="boundary")
    args = parser.parse_args()
    sys.exit(0 if run(args.verification.resolve(), args.probe.resolve(), args.case_root.resolve(), args.mode) else 1)
