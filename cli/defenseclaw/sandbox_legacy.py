# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Consented, idempotent cleanup of the removed openshell-sandbox standalone mode.

The legacy integration targeted the standalone ``openshell-sandbox`` 0.0.x
binary: root systemd units, launcher scripts under ``/usr/local/lib``, a
network namespace with a 10.200.0.x veth pair, iptables NAT rules, a
``sandbox`` user that owned the operator's OpenClaw home (plus ACLs), and a
config that pointed the gateway at the sandbox. :func:`detect` inspects each
artifact, :func:`plan` turns what it found into ordered steps that carry the
exact commands, and :func:`apply` runs them after consent and records a JSON
receipt so a partial or repeated cleanup only does what is still left.

Privileged commands run through ``sudo`` with every executable resolved only
from root-owned system directories, and nothing ever writes into a tree the
sandbox user controls: nothing after the units step runs while any part of
the legacy sandbox is still running, ownership is restored before
``openclaw.json`` is rewritten, and that rewrite runs as the operator with
symlinks refused.

LEGACY(openshell-0.0.x): delete one release after cleanup.
"""

from __future__ import annotations

import copy
import datetime as _dt
import ipaddress
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

SANDBOX_USER = "sandbox"
LEGACY_HOST_IP = "10.200.0.1"
LEGACY_SANDBOX_IP = "10.200.0.2"
LEGACY_SUBNET = ipaddress.ip_network("10.200.0.0/24")
DEFAULT_OPENCLAW_PORT = 18789
DEFAULT_SANDBOX_HOME = "/home/sandbox"
RECEIPT_NAME = "legacy-sandbox-cleanup.json"
OWNERSHIP_BACKUP_NAME = "openclaw-ownership-backup.json"
ROUTE_LOCALNET_SYSCTL = "net.ipv4.conf.all.route_localnet"

TRUSTED_SYSTEM_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")

# A recursive privileged chown must never land on (or directly under) a system
# root, whatever a tampered backup or config claims.
FORBIDDEN_ROOTS = frozenset(
    {
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/sys",
        "/usr",
        "/var",
    }
)

# The two units and four launcher scripts the legacy setup installed. Each is
# removed only when it is a root-owned regular file that is not group/other
# writable and carries content only the DefenseClaw generator produced; the
# markers are stable across every released generator version.
UNIT_MARKERS: dict[str, tuple[str, ...]] = {
    "openshell-sandbox.service": ("Description=OpenShell Sandbox (DefenseClaw-managed)",),
    "defenseclaw-sandbox.target": ("Description=DefenseClaw Sandbox",),
}
LAUNCHER_MARKERS: dict[str, tuple[str, ...]] = {
    "pre-sandbox.sh": ('OC_LINK="$SANDBOX_HOME/.openclaw"',),
    "start-sandbox.sh": ("exec openshell-sandbox",),
    "post-sandbox.sh": (
        "Injected iptables rules via $NSENTER",
        "# No iptables rules needed (DNS override and guardrail both disabled)",
    ),
    "cleanup-sandbox.sh": ("Cleaned orphan namespace",),
}
SYSTEMD_UNITS = ("defenseclaw-sandbox.target", "openshell-sandbox.service")

# Files the legacy setup wrote under data_dir. They are backed up, then removed.
DATA_DIR_ARTIFACTS = (
    "systemd/openshell-sandbox.service",
    "systemd/defenseclaw-sandbox.target",
    "scripts/pre-sandbox.sh",
    "scripts/start-sandbox.sh",
    "scripts/post-sandbox.sh",
    "scripts/cleanup-sandbox.sh",
    "scripts/run-sandbox.sh",
    "sandbox-resolv.conf",
    "openshell-policy.rego",
    "openshell-policy.yaml",
    "policies/defenseclaw-policy.yaml",
    "saved.route_localnet",
    "sandbox.netns",
    "sandbox.pids",
    "openshell.pid",
    OWNERSHIP_BACKUP_NAME,
)
# Directories that only ever held legacy artifacts; removed once empty.
DATA_DIR_ARTIFACT_DIRS = ("systemd", "scripts")
# The previous release's ordinary connector setup wrote this policy on every
# Linux OpenClaw/ZeptoClaw host, sandboxed or not. It is cleaned up along with
# a legacy install but never counts as proof of one.
NON_EVIDENCE_ARTIFACTS = frozenset({"policies/defenseclaw-policy.yaml"})
# PID files the legacy launchers wrote, with the program each PID must still
# be: run-sandbox.sh wrote "<pid> <program>" lines, and the removed gateway
# `sandbox` subcommand wrote a bare openshell-sandbox PID.
PID_FILES = {"sandbox.pids": "", "openshell.pid": "openshell-sandbox"}
# What the sandboxed agent could have changed in the OpenClaw home, for the
# review the operator does before OpenClaw runs on the host again.
REVIEW_PATHS = ("openclaw.json", "extensions", "skills", "workspace/skills", "hooks")

_NETNS_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_IFNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$")
_PROGRAM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_PID = re.compile(r"^[0-9]{1,7}$")
_PID_MAX = 4194304  # PID_MAX_LIMIT on 64-bit Linux
_ACL_USER_ENTRY = re.compile(r"^(?:default:)?user:([0-9]+):")
_LEGACY_VERSION = re.compile(r"^0\.0\.\d+$")
_MAX_MARKED_FILE_BYTES = 1024 * 1024

STEP_ORDER = (
    "units",
    "stopped",
    "network",
    "ownership",
    "openclaw_json",
    "group",
    "user",
    "binary",
    "config",
    "artifacts",
)


# ---------------------------------------------------------------------------
# Host access (injectable so tests never touch the real system)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def _subprocess_runner(argv: Sequence[str]) -> CommandResult:
    try:
        completed = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except FileNotFoundError as exc:
        return CommandResult(127, "", str(exc))
    except subprocess.TimeoutExpired:
        return CommandResult(124, "", "timed out")
    return CommandResult(completed.returncode, completed.stdout or "", completed.stderr or "")


# The legacy sandbox only ever ran on Linux. pwd/grp/geteuid are resolved
# lazily so the module still imports (and its tests collect) on Windows.


def _euid() -> int:
    geteuid = getattr(os, "geteuid", None)
    return geteuid() if geteuid is not None else -1


def _invoking_user() -> str:
    sudo_user = os.environ.get("SUDO_USER", "").strip()
    if sudo_user and _euid() == 0:
        return sudo_user
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError, AttributeError):
        return os.environ.get("USER", "") or os.environ.get("USERNAME", "")


def _lookup_user(name: str) -> Any | None:
    try:
        import pwd

        return pwd.getpwnam(name)
    except (ImportError, KeyError):
        return None


def _group_members(name: str) -> list[str] | None:
    try:
        import grp

        return list(grp.getgrnam(name).gr_mem)
    except (ImportError, KeyError):
        return None


def _uid_exists(uid: int) -> bool:
    try:
        import pwd

        pwd.getpwuid(uid)
    except (ImportError, KeyError):
        return False
    return True


def _pid_alive(pid: int) -> bool:
    """Whether *pid* names a process, including one owned by another user."""
    if os.name == "nt" or pid <= 1:
        # os.kill on Windows terminates the process; pid 0/-1 signal groups.
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        # EPERM: it exists but belongs to someone else (root, usually).
        return True
    return True


def _pid_cmdline(pid: int) -> str | None:
    """The process's command line, or None when it cannot be read."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read(4096)
    except OSError:
        return None
    return raw.replace(b"\0", b" ").decode("utf-8", "replace").strip()


def _host_os() -> str:
    from defenseclaw.platform_support import host_os

    return host_os()


@dataclass
class System:
    """Everything cleanup reads from or runs on the host.

    Production uses the defaults. Tests point the paths at a temporary tree,
    replace the runner with a recorder, and treat their own uid as root.
    """

    runner: Callable[[Sequence[str]], CommandResult] = _subprocess_runner
    resolve: Callable[[str], str | None] | None = None
    euid: Callable[[], int] = _euid
    trusted_uid: int = 0
    unit_dir: str = "/etc/systemd/system"
    launcher_dir: str = "/usr/local/lib/defenseclaw"
    binary_path: str = "/usr/local/bin/openshell-sandbox"
    netns_dir: str = "/run/netns"
    route_localnet_path: str = "/proc/sys/net/ipv4/conf/all/route_localnet"
    host_os: Callable[[], str] = _host_os
    invoking_user: Callable[[], str] = _invoking_user
    lookup_user: Callable[[str], Any | None] = _lookup_user
    uid_exists: Callable[[int], bool] = _uid_exists
    group_members: Callable[[str], list[str] | None] = _group_members
    pid_alive: Callable[[int], bool] = _pid_alive
    pid_cmdline: Callable[[int], str | None] = _pid_cmdline
    home: Callable[[], str] = lambda: os.path.expanduser("~")
    now: Callable[[], _dt.datetime] = lambda: _dt.datetime.now(_dt.timezone.utc)
    authenticate: Callable[[System], bool] | None = None

    def trusted(self, name: str) -> str | None:
        resolver = self.resolve or trusted_system_command
        return resolver(name)

    def is_root(self) -> bool:
        return self.euid() == 0


# ---------------------------------------------------------------------------
# Trusted executable resolution
# ---------------------------------------------------------------------------


def trusted_system_command(name: str) -> str | None:
    """Resolve a privileged helper only from root-owned system directories.

    ``$PATH`` is never consulted: an executable planted in a user-writable
    directory must not become the program sudo runs as root. The whole link
    chain must be root-owned, but the returned path is the name inside the
    trusted directory, not the chain's target: multi-call binaries such as
    ``xtables-nft-multi`` (behind ``/usr/sbin/iptables``) dispatch on argv[0].
    """
    if not name or os.path.basename(name) != name:
        return None
    for directory in TRUSTED_SYSTEM_DIRS:
        candidate = os.path.join(directory, name)
        resolved = trusted_root_owned_file(candidate, allow_symlinks=True)
        if resolved and os.access(resolved, os.X_OK):
            return candidate
    return None


def trusted_root_owned_file(path: str, *, allow_symlinks: bool = False) -> str | None:
    """Return *path* resolved through root-owned links to a root-owned file.

    Every link and the final file must be owned by root in a directory chain
    that only root can modify, and the file must not be group/other writable.
    """
    if not path:
        return None
    current = os.path.abspath(path)
    for _ in range(40):
        try:
            info = os.lstat(current)
        except OSError:
            return None
        if not stat.S_ISLNK(info.st_mode):
            break
        if not allow_symlinks or info.st_uid != 0 or not _trusted_root_owned_directory_chain(os.path.dirname(current)):
            return None
        try:
            target = os.readlink(current)
        except OSError:
            return None
        current = os.path.abspath(target if os.path.isabs(target) else os.path.join(os.path.dirname(current), target))
    else:
        return None
    if os.path.realpath(current) != current or not _trusted_root_owned_directory_chain(os.path.dirname(current)):
        return None
    try:
        info = os.lstat(current)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        return None
    return current


def _trusted_root_owned_directory_chain(path: str) -> bool:
    current = os.path.abspath(path)
    while True:
        try:
            info = os.lstat(current)
        except OSError:
            return False
        if not stat.S_ISDIR(info.st_mode):
            return False
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            return False
        parent = os.path.dirname(current)
        if parent == current:
            return True
        current = parent


class UntrustedCommandError(RuntimeError):
    """A required helper has no trusted system binary."""


def privileged_argv(system: System, name: str, *args: str) -> tuple[str, ...]:
    """Build a root argv with the helper (and sudo) resolved from trusted dirs."""
    helper = system.trusted(name)
    if not helper:
        raise UntrustedCommandError(f"trusted system {name} binary not found")
    if system.is_root():
        return (helper, *args)
    sudo = system.trusted("sudo")
    if not sudo:
        raise UntrustedCommandError("trusted system sudo binary not found")
    return (sudo, helper, *args)


def validate_sudo(system: System) -> bool:
    """Prompt for the sudo password once, on the terminal, before any step.

    Privileged commands run with captured output, which would hide sudo's
    prompt; ``sudo -v`` up front caches the credential instead. Passwordless
    sudo is detected first so non-interactive runs never block.
    """
    sudo = system.trusted("sudo")
    if not sudo:
        return False
    if subprocess.run([sudo, "-n", "true"], capture_output=True, check=False).returncode == 0:
        return True
    return subprocess.run([sudo, "-v"], check=False).returncode == 0


def unprivileged_argv(system: System, name: str, *args: str) -> tuple[str, ...]:
    helper = system.trusted(name)
    if not helper:
        raise UntrustedCommandError(f"trusted system {name} binary not found")
    return (helper, *args)


def render_argv(argv: Sequence[str]) -> str:
    return shlex.join(list(argv))


# ---------------------------------------------------------------------------
# Detected state
# ---------------------------------------------------------------------------


@dataclass
class MarkedFile:
    """A root-installed legacy file and whether cleanup may remove it."""

    path: str
    removable: bool
    reason: str = ""


@dataclass
class Ownership:
    """A validated ownership backup ready for a privileged restore."""

    home: str
    uid: int
    gid: int
    parent_modes: list[tuple[str, int]] = field(default_factory=list)
    parent_notes: list[str] = field(default_factory=list)


@dataclass
class BinaryState:
    path: str
    version: str = ""
    package_owner: str = ""
    removable: bool = False
    reason: str = ""


@dataclass
class LegacyState:
    data_dir: str
    config_legacy: bool = False
    config_changes: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    sandbox_home: str = DEFAULT_SANDBOX_HOME
    sandbox_uid: int | None = None
    sandbox_uid_note: str = ""
    sandbox_pw_dir: str = ""
    invoking_user: str = ""
    user_in_sandbox_group: bool = False
    units: list[MarkedFile] = field(default_factory=list)
    launchers: list[MarkedFile] = field(default_factory=list)
    recorded_pids: list[tuple[int, str, str]] = field(default_factory=list)  # (pid, program, pid file)
    netns: str = ""
    netns_note: str = ""
    veths: list[str] = field(default_factory=list)
    veth_notes: list[str] = field(default_factory=list)
    iptables_rules: list[tuple[str, ...]] = field(default_factory=list)
    legacy_gateway: dict[str, Any] = field(default_factory=dict)
    route_localnet_saved: str = ""
    route_localnet_current: str = ""
    openclaw_home: str = ""
    # pin | receipt | backup: validated legacy anchors. fallback: the host
    # OpenClaw home of an install whose old `--disable` erased every anchor;
    # only the sandbox ACLs are removed from it.
    openclaw_home_source: str = ""
    openclaw_home_exists: bool = False
    openclaw_home_error: str = ""
    ownership: Ownership | None = None
    ownership_error: str = ""
    acl_ancestors: list[str] = field(default_factory=list)
    openclaw_config: str = ""
    openclaw_config_error: str = ""
    claw_paths_in_sandbox_home: bool = False
    sandbox_link: str = ""
    sandbox_link_state: str = "absent"  # absent | link | not-a-link | unknown
    binary: BinaryState | None = None
    sandbox_user_exists: bool = False
    artifacts: list[str] = field(default_factory=list)
    receipt: dict[str, Any] = field(default_factory=dict)

    @property
    def receipt_path(self) -> str:
        return os.path.join(self.data_dir, RECEIPT_NAME)

    def step_done(self, step_id: str) -> bool:
        steps = self.receipt.get("steps")
        return isinstance(steps, dict) and (steps.get(step_id) or {}).get("status") == "done"

    @property
    def validated_home(self) -> bool:
        return bool(self.openclaw_home) and self.openclaw_home_source in ("pin", "receipt", "backup")

    @property
    def has_system_evidence(self) -> bool:
        """Whether anything proves this host ran the legacy sandbox.

        Checks that need root to observe (NAT rules, ACLs) are only planned
        when there is such evidence, so a clean host never prompts for sudo.
        """
        return bool(
            self.config_legacy
            or self.units
            or self.launchers
            or self.netns
            or self.veths
            or any(rel not in NON_EVIDENCE_ARTIFACTS for rel in self.artifacts)
            or self.openclaw_home_source in ("pin", "backup")
            or (self.openclaw_home_source == "receipt" and not self.receipt.get("completed"))
        )


def _read_receipt(path: str) -> dict[str, Any]:
    try:
        info = os.lstat(path)
    except OSError:
        return {}
    if not stat.S_ISREG(info.st_mode):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _marked_file(path: str, markers: tuple[str, ...], system: System) -> MarkedFile | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return MarkedFile(path, False, f"cannot inspect ({exc.strerror or exc})")
    if not stat.S_ISREG(info.st_mode):
        return MarkedFile(path, False, "not a regular file")
    if info.st_uid != system.trusted_uid:
        return MarkedFile(path, False, f"owned by uid {info.st_uid}, not root")
    if stat.S_IMODE(info.st_mode) & 0o022:
        return MarkedFile(path, False, "group/other writable")
    if info.st_size > _MAX_MARKED_FILE_BYTES:
        return MarkedFile(path, False, "larger than any generated file")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read(_MAX_MARKED_FILE_BYTES)
    except OSError as exc:
        return MarkedFile(path, False, f"cannot read ({exc.strerror or exc})")
    if not any(marker in content for marker in markers):
        return MarkedFile(path, False, "content is not DefenseClaw-generated")
    return MarkedFile(path, True)


def _read_small_text(path: str) -> str:
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            return ""
        with open(path, encoding="utf-8") as fh:
            return fh.read(4096).strip()
    except OSError:
        return ""


def _in_legacy_subnet(host: str) -> bool:
    try:
        return ipaddress.ip_address(str(host).strip()) in LEGACY_SUBNET
    except ValueError:
        return False


def _legacy_gateway(cfg, receipt: dict[str, Any]) -> dict[str, Any]:
    """Return the sandbox IP/port the legacy NAT rules were written for.

    Captured into the receipt on the first apply, because the config reset
    later rewrites gateway.host/port while stale rules may still exist.
    """
    recorded = receipt.get("legacy_gateway")
    if isinstance(recorded, dict):
        host = recorded.get("host")
        port = recorded.get("port")
        if isinstance(host, str) and _in_legacy_subnet(host) and isinstance(port, int) and 0 < port < 65536:
            return {"host": host, "port": port}
    host = str(getattr(cfg.gateway, "host", "") or "")
    try:
        port = int(getattr(cfg.gateway, "port", DEFAULT_OPENCLAW_PORT) or DEFAULT_OPENCLAW_PORT)
    except (TypeError, ValueError):
        port = DEFAULT_OPENCLAW_PORT
    if not _in_legacy_subnet(host):
        host = LEGACY_SANDBOX_IP
    if not 0 < port < 65536:
        port = DEFAULT_OPENCLAW_PORT
    return {"host": host, "port": port}


def iptables_rules(sandbox_ip: str, port: int) -> list[tuple[str, ...]]:
    """The exact host NAT rules the legacy post-sandbox launcher appended.

    Each tuple is ``(chain, *match)``; callers insert ``-C``/``-D``. Rules the
    launcher added inside the sandbox namespace die with that namespace.
    """
    return [
        (
            "OUTPUT", "-d", "127.0.0.1", "-p", "tcp", "--dport", str(port),
            "-j", "DNAT", "--to-destination", f"{sandbox_ip}:{port}",
        ),
        ("POSTROUTING", "-d", sandbox_ip, "-p", "tcp", "--dport", str(port), "-j", "MASQUERADE"),
        ("POSTROUTING", "-s", str(LEGACY_SUBNET), "-p", "udp", "--dport", "53", "-j", "MASQUERADE"),
    ]


def _legacy_veths(system: System, netns: str) -> tuple[list[str], list[str]]:
    """Split the host veths carrying the legacy host address by ownership.

    ``ip -o addr`` prints plain interface names, so the address holders are
    matched against ``ip -o link show type veth``, which prints each veth as
    ``<name>@<peer>`` followed by the peer's ``link-netns``. Only a veth whose
    peer lives in the recorded sandbox namespace is ours to delete, as the
    legacy cleanup script decided; any other veth with the address is
    reported for manual review. Returns ``(ours, notes)``.
    """
    try:
        addr_argv = unprivileged_argv(system, "ip", "-o", "-4", "addr", "show")
        link_argv = unprivileged_argv(system, "ip", "-o", "link", "show", "type", "veth")
    except UntrustedCommandError:
        return [], []
    result = system.runner(addr_argv)
    if result.returncode != 0:
        return [], []
    holders: list[str] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[2] != "inet":
            continue
        if fields[3].split("/", 1)[0] != LEGACY_HOST_IP:
            continue
        name = fields[1].split("@", 1)[0].rstrip(":")
        if _IFNAME.match(name) and name not in holders:
            holders.append(name)
    if not holders:
        return [], []
    links = system.runner(link_argv)
    peer_netns: dict[str, str] = {}
    if links.returncode == 0:
        for line in links.stdout.splitlines():
            fields = line.split()
            if len(fields) < 2 or "@" not in fields[1]:
                continue
            name = fields[1].split("@", 1)[0]
            namespace = ""
            if "link-netns" in fields:
                index = fields.index("link-netns")
                namespace = fields[index + 1] if index + 1 < len(fields) else ""
            peer_netns[name] = namespace
    ours: list[str] = []
    notes: list[str] = []
    for name in holders:
        if name not in peer_netns:
            continue  # not a veth: the legacy sandbox only ever used a veth pair
        if netns and peer_netns[name] == netns:
            ours.append(name)
        else:
            notes.append(
                f"veth {name} carries {LEGACY_HOST_IP} but its peer is not in the recorded sandbox namespace; "
                f"left in place (if it belonged to the legacy sandbox, delete it with: sudo ip link delete {name})"
            )
    return ours, notes


def _recorded_pids(data_dir: str) -> list[tuple[int, str, str]]:
    """The PIDs the legacy launchers recorded, as (pid, program, pid file)."""
    found: list[tuple[int, str, str]] = []
    for rel, default_program in PID_FILES.items():
        for line in _read_small_text(os.path.join(data_dir, rel)).splitlines():
            fields = line.split()
            if not fields or not _PID.match(fields[0]):
                continue
            pid = int(fields[0])
            if not 1 < pid <= _PID_MAX:
                continue
            program = fields[1] if len(fields) > 1 and _PROGRAM.match(fields[1]) else default_program
            if (pid, program, rel) not in found:
                found.append((pid, program, rel))
    return found


def _recorded_netns(data_dir: str, system: System) -> tuple[str, str]:
    recorded = _read_small_text(os.path.join(data_dir, "sandbox.netns")).splitlines()
    name = recorded[0].strip() if recorded else ""
    if not name:
        candidates = []
        try:
            candidates = sorted(entry for entry in os.listdir(system.netns_dir) if "openshell" in entry)
        except OSError:
            pass
        if candidates:
            return "", (
                "no recorded sandbox namespace; review and delete manually if it is the legacy sandbox: "
                + ", ".join(candidates)
            )
        return "", ""
    if not _NETNS_NAME.match(name):
        return "", f"ignoring malformed recorded namespace name {name!r}"
    if not os.path.lexists(os.path.join(system.netns_dir, name)):
        return "", ""
    return name, ""


def _load_ownership_backup(data_dir: str) -> tuple[dict[str, Any] | None, str]:
    path = os.path.join(data_dir, OWNERSHIP_BACKUP_NAME)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None, ""
    except OSError as exc:
        return None, f"cannot inspect ownership backup ({exc.strerror or exc})"
    if not stat.S_ISREG(info.st_mode):
        return None, "ownership backup is not a regular file"
    try:
        with open(path, encoding="utf-8") as fh:
            backup = json.load(fh)
    except (OSError, ValueError) as exc:
        return None, f"cannot read ownership backup ({exc})"
    if not isinstance(backup, dict):
        return None, "ownership backup is not a JSON object"
    return backup, ""


def _strict_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def validate_restore_home(real_home: str) -> str:
    """Return why *real_home* may not receive a recursive chown, or ""."""
    if not real_home or not os.path.isabs(real_home):
        return "OpenClaw home is not an absolute path"
    if real_home in FORBIDDEN_ROOTS:
        return f"refusing recursive chown of system path {real_home}"
    parent = os.path.dirname(real_home)
    if parent != "/" and parent in FORBIDDEN_ROOTS:
        return f"refusing recursive chown directly under system path {parent}"
    return ""


def _pinned_home(cfg) -> str:
    pinned = str(getattr(getattr(cfg, "claw", None), "openclaw_home_original", "") or "").strip()
    if not pinned:
        return ""
    return os.path.realpath(os.path.expanduser(pinned))


def _recorded_home(receipt: dict[str, Any]) -> str:
    raw = receipt.get("openclaw_home")
    if not isinstance(raw, str) or not os.path.isabs(raw.strip()):
        return ""
    return os.path.realpath(raw.strip())


def _resolve_openclaw_home(
    pinned: str,
    recorded: str,
    backup: dict[str, Any] | None,
    backup_error: str,
) -> tuple[str, str, str]:
    """Return ``(home, source, "")`` for the trusted real OpenClaw home, or ``("", "", reason)``.

    Every anchor that exists must agree: the pinned
    ``claw.openclaw_home_original``, the home an earlier cleanup run recorded
    in its receipt (so clearing the pin never turns a refused backup into a
    trusted one), and the ownership backup. The sandbox-owned
    ``$SANDBOX_HOME/.openclaw`` symlink is never trusted: its target is
    attacker-writable (F-0161/F-0162).
    """
    backup_home = ""
    if backup is not None:
        raw = backup.get("openclaw_home")
        if not isinstance(raw, str) or not raw.strip():
            return "", "", "ownership backup has no openclaw_home"
        backup_home = os.path.realpath(os.path.expanduser(raw.strip()))
    anchors = [
        (label, path)
        for label, path in (
            ("pinned original OpenClaw home", pinned),
            ("OpenClaw home recorded by an earlier cleanup run", recorded),
            ("ownership backup", backup_home),
        )
        if path
    ]
    if not anchors:
        return "", "", backup_error
    first_label, home = anchors[0]
    for label, path in anchors[1:]:
        if path != home:
            return "", "", (
                f"the {label} names {path} but the {first_label} is {home}; refusing a possibly tampered backup"
            )
    reason = validate_restore_home(home)
    if reason:
        return "", "", reason
    return home, "pin" if pinned else "receipt" if recorded else "backup", ""


def _expand_home(path: str, system: System) -> str:
    """Expand a leading ``~`` against the invoking user's home."""
    if path == "~":
        return system.home()
    if path.startswith("~/"):
        return os.path.join(system.home(), path[2:])
    return path


def _fallback_openclaw_home(cfg, state: LegacyState, system: System) -> str:
    """The host OpenClaw home of an install with no pin or backup left.

    The removed ``sandbox setup --disable`` restored ownership, then deleted
    the backup and cleared the pin, but never removed the sandbox ACLs (rwX
    plus default entries) from the home. It reset ``claw.home_dir`` to the
    host home, so that (or ``~/.openclaw``) is where those ACLs remain.
    """
    sandbox_home = os.path.realpath(state.sandbox_home)
    candidates: list[str] = []
    home_dir = str(getattr(getattr(cfg, "claw", None), "home_dir", "") or "").strip()
    if home_dir:
        candidates.append(_expand_home(home_dir, system))
    candidates.append(os.path.join(system.home(), ".openclaw"))
    for candidate in candidates:
        if not os.path.isabs(candidate):
            continue
        real = os.path.realpath(candidate)
        if _under(real, sandbox_home) or validate_restore_home(real):
            continue
        try:
            if stat.S_ISDIR(os.lstat(real).st_mode):
                return real
        except OSError:
            continue
    return ""


def _acl_uids(system: System, path: str) -> set[int] | None:
    """Numeric uids with a named ACL entry (access or default) on *path*."""
    try:
        argv = unprivileged_argv(system, "getfacl", "-n", "-p", "--", path)
    except UntrustedCommandError:
        return None
    result = system.runner(argv)
    if result.returncode != 0:
        return None
    uids: set[int] = set()
    for line in result.stdout.splitlines():
        match = _ACL_USER_ENTRY.match(line.strip())
        if match:
            uids.add(int(match.group(1)))
    return uids


def _recover_sandbox_uid(paths: Sequence[str], system: System) -> tuple[int | None, str]:
    """Find the uid of a sandbox account deleted outside cleanup.

    Only a uid that maps to no account and owns, or has an ACL entry on, the
    sandbox or OpenClaw home qualifies, so a recovered uid can only ever
    match leftovers of the deleted account.
    """
    candidates: dict[int, list[str]] = {}
    for path in paths:
        if not path:
            continue
        try:
            owner = os.lstat(path).st_uid
        except OSError:
            continue
        for uid in sorted({owner} | (_acl_uids(system, path) or set())):
            if uid != 0 and not system.uid_exists(uid):
                candidates.setdefault(uid, []).append(path)
    if len(candidates) == 1:
        uid, where = next(iter(candidates.items()))
        return uid, (
            f"the sandbox user no longer exists; using uid {uid}, which maps to no account and owns or "
            f"has ACL entries on {', '.join(where)}"
        )
    if candidates:
        listed = ", ".join(str(uid) for uid in sorted(candidates))
        return None, (
            f"the sandbox user no longer exists and several unmapped uids ({listed}) own or have ACL entries "
            "on its old paths; remove the stale entries by hand (getfacl -R -n shows them)"
        )
    return None, ""


def _validated_ownership(
    backup: dict[str, Any] | None,
    home: str,
    sandbox_uid: int | None,
) -> tuple[Ownership | None, str]:
    if backup is None:
        return None, ""
    uid = _strict_int(backup.get("original_uid"))
    gid = _strict_int(backup.get("original_gid"))
    if uid is None or gid is None:
        return None, "ownership backup has non-integer uid/gid"
    if uid < 0 or gid < 0:
        return None, "ownership backup has negative uid/gid"
    if sandbox_uid is not None and uid == sandbox_uid:
        return None, "ownership backup names the sandbox user as the original owner"
    parents: list[tuple[str, int]] = []
    notes: list[str] = []
    raw_parents = backup.get("parents_modified") or []
    if not isinstance(raw_parents, list):
        return None, "ownership backup parents_modified is not a list"
    for entry in raw_parents:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        mode_text = entry.get("original_mode")
        if not isinstance(path, str) or not isinstance(mode_text, str) or not path:
            continue
        real_parent = os.path.realpath(path)
        if not home.startswith(real_parent.rstrip("/") + "/"):
            continue
        try:
            mode = int(mode_text, 8)
        except ValueError:
            continue
        try:
            info = os.stat(real_parent)
        except OSError:
            continue
        current = stat.S_IMODE(info.st_mode)
        if current == mode:
            continue
        # Legacy setup only ever added o+x to an ancestor that lacked it, so
        # the one restore a backup can justify is clearing that bit again, on
        # a directory the home's owner owns. Anything else would let a
        # rewritten backup make root chmod an arbitrary ancestor (even /).
        if real_parent in FORBIDDEN_ROOTS:
            reason = "it is a system directory"
        elif mode != current & ~stat.S_IXOTH or mode & 0o002:
            reason = f"the backup's mode {mode:o} is not the current mode with only o+x cleared"
        elif info.st_uid != uid:
            reason = f"it is owned by uid {info.st_uid}, not by the OpenClaw home's owner {uid}"
        else:
            parents.append((real_parent, mode))
            continue
        notes.append(f"left {real_parent} at mode {current:o}: {reason}")
    return Ownership(home=home, uid=uid, gid=gid, parent_modes=parents, parent_notes=notes), ""


def _ancestors(path: str) -> list[str]:
    out: list[str] = []
    current = os.path.dirname(path)
    while True:
        out.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            return out
        current = parent


def _sandbox_link_state(path: str) -> str:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    except PermissionError:
        return "unknown"
    except OSError:
        return "unknown"
    return "link" if stat.S_ISLNK(info.st_mode) else "not-a-link"


def _binary_state(system: System, *, probe: bool) -> BinaryState | None:
    path = system.binary_path
    try:
        info = os.lstat(path)
    except OSError:
        return None
    state = BinaryState(path=path)
    if not stat.S_ISREG(info.st_mode):
        state.reason = "is not a regular file"
        return state
    if not probe:
        state.reason = "was not inspected"
        return state
    result = system.runner([path, "--version"])
    text = (result.stdout or result.stderr or "").strip()
    version = text.split()[-1].lstrip("v") if text else ""
    state.version = version
    if result.returncode != 0 or not _LEGACY_VERSION.match(version):
        state.reason = f"reports version {version or 'unknown'!r}, not a legacy 0.0.x build"
        return state
    for manager, args in (("dpkg", ("-S", path)), ("rpm", ("-qf", path))):
        try:
            argv = unprivileged_argv(system, manager, *args)
        except UntrustedCommandError:
            continue
        owned = system.runner(argv)
        if owned.returncode == 0:
            state.package_owner = (owned.stdout.strip().split(":", 1)[0] or manager).strip()
            state.reason = f"owned by package {state.package_owner}; remove it with the package manager"
            return state
    state.removable = True
    return state


def _target_claw_paths(pinned: str, system: System) -> tuple[str, str]:
    default_home = os.path.join(system.home(), ".openclaw")
    if not pinned or os.path.realpath(default_home) == pinned:
        return "~/.openclaw", "~/.openclaw/openclaw.json"
    return pinned, os.path.join(pinned, "openclaw.json")


def _under(path: str, root: str) -> bool:
    if not path or not root:
        return False
    path = os.path.normpath(os.path.expanduser(path))
    root = os.path.normpath(root)
    return path == root or path.startswith(root.rstrip("/") + "/")


def _config_changes(cfg, state: LegacyState, pinned: str, system: System) -> dict[str, tuple[Any, Any]]:
    changes: dict[str, tuple[Any, Any]] = {}

    def want(key: str, current: Any, target: Any) -> None:
        if current != target:
            changes[key] = (current, target)

    gateway_host = str(getattr(cfg.gateway, "host", "") or "")
    guardrail_host = str(getattr(cfg.guardrail, "host", "") or "")
    if state.config_legacy:
        want("openshell.mode", cfg.openshell.mode, "")
    if state.config_legacy or _in_legacy_subnet(gateway_host):
        want("gateway.host", gateway_host, "127.0.0.1")
        want("gateway.port", cfg.gateway.port, DEFAULT_OPENCLAW_PORT)
    if state.config_legacy or _in_legacy_subnet(guardrail_host):
        want("guardrail.host", guardrail_host, "localhost")
    home_dir = str(getattr(cfg.claw, "home_dir", "") or "")
    config_file = str(getattr(cfg.claw, "config_file", "") or "")
    if _under(home_dir, state.sandbox_home) or _under(config_file, state.sandbox_home):
        target_home, target_config = _target_claw_paths(pinned or state.openclaw_home, system)
        want("claw.home_dir", home_dir, target_home)
        want("claw.config_file", config_file, target_config)
    original = str(getattr(cfg.claw, "openclaw_home_original", "") or "")
    if original:
        want("claw.openclaw_home_original", original, "")
    return changes


def detect(cfg, *, system: System | None = None, probe_binary: bool = False) -> LegacyState:
    """Inspect every legacy artifact without changing anything or using sudo.

    The legacy binary is only executed (``--version``) when *probe_binary*
    is set, i.e. when the operator asked for ``--remove-binary``.
    """
    system = system or System()
    data_dir = os.path.expanduser(str(cfg.data_dir))
    receipt = _read_receipt(os.path.join(data_dir, RECEIPT_NAME))
    openshell = getattr(cfg, "openshell", None)
    sandbox_home = str(getattr(openshell, "sandbox_home", "") or "") or DEFAULT_SANDBOX_HOME
    state = LegacyState(
        data_dir=data_dir,
        config_legacy=bool(openshell is not None and getattr(openshell, "mode", "") == "standalone"),
        sandbox_home=sandbox_home,
        receipt=receipt,
    )
    sandbox_pw = system.lookup_user(SANDBOX_USER)
    state.sandbox_user_exists = sandbox_pw is not None
    if sandbox_pw is not None:
        state.sandbox_uid = sandbox_pw.pw_uid
        state.sandbox_pw_dir = str(getattr(sandbox_pw, "pw_dir", "") or "")
    else:
        state.sandbox_uid = _strict_int(receipt.get("sandbox_uid"))
    state.invoking_user = system.invoking_user()
    state.legacy_gateway = _legacy_gateway(cfg, receipt)

    linux = system.host_os() == "linux"
    if linux:
        for name in SYSTEMD_UNITS:
            found = _marked_file(os.path.join(system.unit_dir, name), UNIT_MARKERS[name], system)
            if found is not None:
                state.units.append(found)
        for name in LAUNCHER_MARKERS:
            found = _marked_file(os.path.join(system.launcher_dir, name), LAUNCHER_MARKERS[name], system)
            if found is not None:
                state.launchers.append(found)
        state.recorded_pids = _recorded_pids(data_dir)
        state.netns, state.netns_note = _recorded_netns(data_dir, system)
        state.veths, state.veth_notes = _legacy_veths(system, state.netns)
        state.iptables_rules = iptables_rules(state.legacy_gateway["host"], state.legacy_gateway["port"])
        saved = _read_small_text(os.path.join(data_dir, "saved.route_localnet"))
        state.route_localnet_saved = saved if saved in ("0", "1") else ""
        state.route_localnet_current = _read_small_text(system.route_localnet_path)

        members = system.group_members(SANDBOX_USER)
        user = state.invoking_user
        state.user_in_sandbox_group = bool(members and user and user not in ("root", SANDBOX_USER) and user in members)
        state.binary = _binary_state(system, probe=probe_binary)
    state.artifacts = [rel for rel in DATA_DIR_ARTIFACTS if os.path.lexists(os.path.join(data_dir, rel))]

    backup, backup_error = _load_ownership_backup(data_dir)
    home, source, home_error = _resolve_openclaw_home(_pinned_home(cfg), _recorded_home(receipt), backup, backup_error)
    state.openclaw_home, state.openclaw_home_source, state.openclaw_home_error = home, source, home_error
    if linux and not home and not home_error and state.has_system_evidence and not state.step_done("ownership"):
        fallback = _fallback_openclaw_home(cfg, state, system)
        if fallback:
            state.openclaw_home, state.openclaw_home_source = fallback, "fallback"
    if linux and state.sandbox_uid is None and (state.has_system_evidence or state.openclaw_home):
        # A manual `userdel sandbox` before any cleanup run: the ACLs are
        # keyed by the numeric uid, never by a name that no longer resolves.
        state.sandbox_uid, state.sandbox_uid_note = _recover_sandbox_uid(
            [sandbox_home, state.openclaw_home], system,
        )
    if state.openclaw_home_source == "fallback" and state.sandbox_uid is None:
        state.openclaw_home = state.openclaw_home_source = ""
    if state.openclaw_home:
        try:
            info = os.lstat(state.openclaw_home)
            state.openclaw_home_exists = stat.S_ISDIR(info.st_mode)
        except OSError:
            state.openclaw_home_exists = False
        if backup is not None:
            state.ownership, state.ownership_error = _validated_ownership(
                backup, state.openclaw_home, state.sandbox_uid,
            )
        elif backup_error:
            state.ownership_error = backup_error
        state.acl_ancestors = [path for path in _ancestors(state.openclaw_home) if os.path.isdir(path)]
        # The sandbox user may have left the home untraversable for the
        # operator, so plan the rewrite whenever the home exists; it runs
        # after ownership is restored and treats a missing file as done. A
        # fallback home was already restored by the old --disable.
        if state.openclaw_home_exists and state.validated_home:
            state.openclaw_config = os.path.join(state.openclaw_home, "openclaw.json")
    elif state.openclaw_home_error:
        state.ownership_error = state.openclaw_home_error

    state.sandbox_link = os.path.join(sandbox_home, ".openclaw")
    state.sandbox_link_state = _sandbox_link_state(state.sandbox_link) if linux else "absent"
    roots = {os.path.normpath(sandbox_home), os.path.realpath(sandbox_home)}
    claw = getattr(cfg, "claw", None)
    state.claw_paths_in_sandbox_home = any(
        _under(_expand_home(str(getattr(claw, key, "") or "").strip(), system), root)
        for key in ("home_dir", "config_file")
        for root in roots
    )

    state.config_changes = _config_changes(cfg, state, _pinned_home(cfg), system)
    return state


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------


@dataclass
class Command:
    """One exact argv, optionally gated by a probe run immediately before it.

    ``run_when`` is ``"always"``, ``"check-ok"`` (run only when the probe
    exits 0, e.g. ``iptables -C``) or ``"check-fails"`` (run only when the
    probe exits non-zero, e.g. ``pgrep`` finding no processes). ``repeat``
    re-probes and re-runs a ``check-ok`` command so duplicate rules go too.
    A command with a ``refusal`` is itself a probe: when it exits non-zero
    the step stops and reports the refusal.
    """

    argv: tuple[str, ...]
    check: tuple[str, ...] = ()
    run_when: str = "always"
    repeat: int = 1
    precondition: Callable[[], str] | None = None
    refusal: str = ""

    def render(self) -> list[str]:
        if self.refusal:
            return [render_argv(self.argv), f"  (the step stops here unless it succeeds: {self.refusal})"]
        if not self.check:
            return [render_argv(self.argv)]
        gate = "succeeds" if self.run_when == "check-ok" else "fails"
        return [f"{render_argv(self.argv)}", f"  (only if `{render_argv(self.check)}` {gate})"]


@dataclass
class Action:
    """A Python-native change (no subprocess); ``description`` is what it does."""

    description: str
    run: Callable[[], str]


@dataclass
class Step:
    id: str
    title: str
    commands: list[Command] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    blocked: str = ""


def _step_title(step_id: str) -> str:
    return {
        "units": "Stop and remove the legacy systemd units and launcher scripts",
        "stopped": "Verify that nothing of the legacy sandbox is still running",
        "network": "Remove the sandbox network namespace, veth peer, and NAT rules",
        "ownership": "Restore OpenClaw home ownership and remove sandbox ACLs",
        "openclaw_json": "Restore the OpenClaw gateway settings in openclaw.json",
        "group": "Remove the invoking user from the sandbox group",
        "user": "Delete the sandbox user (--remove-user)",
        "binary": "Remove the legacy openshell-sandbox binary (--remove-binary)",
        "config": "Reset the DefenseClaw config to host mode",
        "artifacts": "Back up and remove legacy files from the data directory",
    }[step_id]


def _finish(step: Step, *, already_done: bool = False) -> Step | None:
    """Drop empty steps; turn a notes-only step into a visible skip."""
    if step.blocked or step.commands or step.actions:
        return step
    if step.notes and not already_done:
        step.blocked = "; ".join(step.notes)
        step.notes = []
        return step
    return None


def _units_step(state: LegacyState, system: System) -> Step | None:
    if not state.units and not state.launchers:
        return None
    step = Step("units", _step_title("units"))
    ours = [marked for marked in state.units if marked.removable]
    try:
        if ours:
            # Only units DefenseClaw generated are stopped; a foreign unit that
            # merely shares a name is reported and left alone.
            names = [name for name in SYSTEMD_UNITS if any(os.path.basename(m.path) == name for m in ours)]
            step.commands.append(Command(privileged_argv(system, "systemctl", "disable", "--now", *names)))
        for marked in (*state.units, *state.launchers):
            if marked.removable:
                step.commands.append(Command(privileged_argv(system, "rm", "-f", "--", marked.path)))
            else:
                step.notes.append(f"left {marked.path} in place: {marked.reason}")
        if ours:
            step.commands.append(Command(privileged_argv(system, "systemctl", "daemon-reload")))
    except UntrustedCommandError as exc:
        step.blocked = str(exc)
    return _finish(step)


def _still_running(state: LegacyState, system: System) -> list[str]:
    """What of the legacy sandbox still runs, one finding per item.

    Covers both launchers: the systemd units (a foreign or tampered unit the
    units step left alone included), the PIDs run-sandbox.sh and the old
    gateway recorded (its root ACL-fixer loop lives exactly as long as the
    recorded openshell-sandbox PID), and any process of the sandbox uid.
    Anything that cannot be checked counts as running.
    """
    found: list[str] = []
    for marked in state.units:
        name = os.path.basename(marked.path)
        try:
            argv = unprivileged_argv(system, "systemctl", "is-active", "--quiet", name)
        except UntrustedCommandError as exc:
            found.append(f"cannot check {name}: {exc}")
            continue
        if system.runner(argv).returncode == 0:
            found.append(f"{name} is active")
    for pid, program, source in state.recorded_pids:
        if not system.pid_alive(pid):
            continue
        cmdline = system.pid_cmdline(pid)
        if cmdline is not None and program and program not in cmdline:
            continue  # the PID was reused by an unrelated process
        found.append(f"PID {pid} ({program or 'unnamed'}) from {source} is running")
    if state.sandbox_uid is not None:
        try:
            argv = unprivileged_argv(system, "pgrep", "-u", str(state.sandbox_uid))
        except UntrustedCommandError as exc:
            found.append(f"cannot check for processes of uid {state.sandbox_uid}: {exc}")
        else:
            result = system.runner(argv)
            if result.returncode == 0:
                pids = result.stdout.split()
                shown = ", ".join(pids[:5]) + (", ..." if len(pids) > 5 else "")
                found.append(f"uid {state.sandbox_uid} still runs PID {shown}")
            elif result.returncode != 1:
                found.append(f"`{render_argv(argv)}` exited {result.returncode}")
    return found


def _stopped_step(state: LegacyState, system: System) -> Step | None:
    """Gate every later step on the legacy sandbox being fully stopped.

    Only the systemd units can be stopped for the operator; the non-systemd
    run-sandbox.sh launcher lives in the operator-writable data directory and
    must never run through sudo from here. Restoring ownership, ACLs, or
    config under a live sandbox would hand the home straight back to it.
    """
    checks: list[str] = []
    if state.units:
        names = " and ".join(os.path.basename(marked.path) for marked in state.units)
        checks.append(f"`systemctl is-active` reports {names} inactive")
    if state.recorded_pids:
        sources = ", ".join(sorted({source for _, _, source in state.recorded_pids}))
        checks.append(f"no PID recorded in {sources} is still running")
    if state.sandbox_uid is not None:
        checks.append(f"`pgrep -u {state.sandbox_uid}` finds no process")
    if not checks:
        return None
    step = Step("stopped", _step_title("stopped"))
    launcher = os.path.join(state.data_dir, "scripts", "run-sandbox.sh")

    def run() -> str:
        running = _still_running(state, system)
        if not running:
            return "the legacy sandbox is not running"
        how: list[str] = []
        if state.units:
            how.append("`sudo systemctl stop defenseclaw-sandbox.target openshell-sandbox.service`")
        if os.path.lexists(launcher):
            how.append(f"`sudo {shlex.quote(launcher)} stop` for the run-sandbox.sh launcher")
        how.append("or stop the listed processes yourself")
        stale = ""
        if any(finding.startswith("PID ") for finding in running):
            stale = " (if a listed PID now belongs to an unrelated process, delete that stale PID file)"
        raise RuntimeError(
            f"the legacy sandbox is still running ({'; '.join(running)}); stop it first with "
            + ", ".join(how)
            + f", then re-run cleanup{stale}"
        )

    step.actions.append(Action("check that " + "; ".join(checks), run))
    return step


def _network_step(state: LegacyState, system: System) -> Step | None:
    step = Step("network", _step_title("network"))
    if state.netns_note and state.has_system_evidence:
        step.notes.append(state.netns_note)
    try:
        if state.netns:
            # Stopping the service runs the legacy cleanup script, which may
            # already have removed the namespace; only delete what remains.
            step.commands.append(
                Command(
                    privileged_argv(system, "ip", "netns", "delete", state.netns),
                    check=unprivileged_argv(system, "test", "-e", os.path.join(system.netns_dir, state.netns)),
                    run_when="check-ok",
                )
            )
        for veth in state.veths:
            step.commands.append(
                Command(
                    privileged_argv(system, "ip", "link", "delete", veth),
                    check=unprivileged_argv(system, "ip", "link", "show", "dev", veth),
                    run_when="check-ok",
                )
            )
        rules_wanted = state.has_system_evidence and not state.step_done("network")
        if rules_wanted and state.iptables_rules and system.trusted("iptables"):
            for rule in state.iptables_rules:
                chain, *match = rule
                step.commands.append(
                    Command(
                        privileged_argv(system, "iptables", "-t", "nat", "-D", chain, *match),
                        check=privileged_argv(system, "iptables", "-t", "nat", "-C", chain, *match),
                        run_when="check-ok",
                        repeat=8,
                    )
                )
        if state.route_localnet_saved and state.route_localnet_saved != state.route_localnet_current:
            step.commands.append(
                Command(
                    privileged_argv(
                        system, "sysctl", "-w", f"{ROUTE_LOCALNET_SYSCTL}={state.route_localnet_saved}",
                    )
                )
            )
        elif not state.route_localnet_saved and (state.config_legacy or state.netns or state.veths):
            step.notes.append(
                f"no saved {ROUTE_LOCALNET_SYSCTL} value; leaving the current value "
                f"({state.route_localnet_current or 'unknown'}) unchanged"
            )
        if step.commands:
            # Advisory only: a veth this install cannot be tied to must never
            # keep the cleanup unfinished, so it is reported alongside work.
            step.notes.extend(state.veth_notes)
    except UntrustedCommandError as exc:
        step.blocked = str(exc)
    return _finish(step, already_done=state.step_done("network"))


def _ownership_step(state: LegacyState, system: System) -> Step | None:
    step = Step("ownership", _step_title("ownership"))
    done = state.step_done("ownership")
    link_needs_removal = state.sandbox_link_state == "link" or (
        state.sandbox_link_state == "unknown" and state.has_system_evidence and not done
    )
    if state.ownership_error:
        # Fail closed: a backup or pin that does not validate means the
        # privileged restore target cannot be trusted. Nothing in this step
        # runs, and the backup is kept so the operator can fix and re-run.
        step.blocked = f"ownership not restored: {state.ownership_error}"
        return step
    if state.sandbox_uid_note and state.openclaw_home and not done:
        step.notes.append(state.sandbox_uid_note)
    if state.openclaw_home_source == "fallback" and not done:
        step.notes.append(
            f"no pinned OpenClaw home or ownership backup is left (the old `sandbox setup --disable` "
            f"removed them); removing the sandbox ACLs from {state.openclaw_home}"
        )
    elif state.openclaw_home and state.ownership is None and state.openclaw_home_exists and not done:
        step.notes.append(
            f"no ownership backup; {state.openclaw_home} keeps its current owner "
            f"(restore it with: sudo chown -hR {state.invoking_user or '<user>'}: {state.openclaw_home})"
        )
    try:
        # The ACLs go first: the chown alone would leave the sandbox uid its
        # rwX (and default) entries on everything it no longer owns.
        if state.openclaw_home and not done:
            if state.sandbox_uid is None:
                # Never a bare `u:sandbox`: setfacl rejects a name that no
                # longer resolves, so the step could never complete.
                step.notes.append(
                    "the sandbox user no longer exists and its uid is unknown; check "
                    f"`getfacl -R -n {shlex.quote(state.openclaw_home)}` for entries of an unmapped uid"
                )
            elif not system.trusted("setfacl"):
                step.notes.append("setfacl is not installed; no sandbox ACLs can remain to remove")
            else:
                identifier = f"u:{state.sandbox_uid}"
                if state.openclaw_home_exists:
                    home = state.openclaw_home
                    step.commands.append(
                        Command(
                            privileged_argv(system, "setfacl", "-R", "-x", identifier, "--", home),
                            precondition=_home_unchanged(home),
                        )
                    )
                    step.commands.append(
                        Command(
                            privileged_argv(system, "setfacl", "-R", "-d", "-x", identifier, "--", home),
                            precondition=_home_unchanged(home),
                        )
                    )
                for ancestor in state.acl_ancestors:
                    step.commands.append(Command(privileged_argv(system, "setfacl", "-x", identifier, "--", ancestor)))
        ownership = state.ownership
        if ownership is not None and state.openclaw_home_exists and not done:
            from_owner = [f"--from={state.sandbox_uid}"] if state.sandbox_uid is not None else []
            step.commands.append(
                Command(
                    privileged_argv(
                        system, "chown", "-hR", *from_owner, f"{ownership.uid}:{ownership.gid}", "--", ownership.home,
                    ),
                    precondition=_home_unchanged(ownership.home),
                )
            )
            for path, mode in ownership.parent_modes:
                step.commands.append(Command(privileged_argv(system, "chmod", f"{mode:o}", "--", path)))
            step.notes.extend(ownership.parent_notes)
        if link_needs_removal:
            step.commands.append(
                Command(
                    privileged_argv(system, "rm", "-f", "--", state.sandbox_link),
                    check=privileged_argv(system, "test", "-L", state.sandbox_link),
                    run_when="check-ok",
                )
            )
        elif state.sandbox_link_state == "not-a-link":
            step.notes.append(f"{state.sandbox_link} is not a symlink; left in place")
    except UntrustedCommandError as exc:
        step.blocked = str(exc)
    return _finish(step, already_done=done)


def _home_unchanged(expected: str) -> Callable[[], str]:
    """F-0421: re-validate the chown/ACL target immediately before it runs."""

    def check() -> str:
        try:
            info = os.lstat(expected)
        except OSError as exc:
            return f"{expected} disappeared ({exc.strerror or exc})"
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            return f"{expected} is no longer a real directory"
        if os.path.realpath(expected) != expected:
            return f"{expected} now resolves to {os.path.realpath(expected)}"
        reason = validate_restore_home(expected)
        return reason

    return check


def _openclaw_json_step(state: LegacyState, earlier: Sequence[Step]) -> Step | None:
    if not state.openclaw_config or state.step_done("openclaw_json"):
        return None
    step = Step("openclaw_json", _step_title("openclaw_json"))
    if state.ownership_error:
        step.blocked = "waits for the OpenClaw home ownership restore"
        return step
    config_path = state.openclaw_config
    home_check = _home_unchanged(state.openclaw_home)
    ownership_planned = any(other.id == "ownership" and not other.blocked for other in earlier)

    def run() -> str:
        # The rewrite runs as the operator inside a tree the sandbox user
        # owned until a moment ago: only after the ownership restore held,
        # and only while the home is still the validated real directory.
        if ownership_planned and not state.step_done("ownership"):
            raise RuntimeError("skipped: the OpenClaw home ownership restore did not complete")
        reason = home_check()
        if reason:
            raise RuntimeError(f"refused: {reason}")
        return restore_openclaw_gateway(config_path)

    step.actions.append(
        Action(
            f"rewrite {config_path}: gateway.bind=loopback, gateway.port={DEFAULT_OPENCLAW_PORT}, "
            f"provider baseUrl {LEGACY_HOST_IP} -> localhost (as the invoking user, symlinks refused)",
            run,
        )
    )
    return step


def _sandbox_account_is_legacy(state: LegacyState) -> bool:
    """Whether the ``sandbox`` account/group can be attributed to this install.

    The name alone proves nothing: legacy setup reused any existing account
    called ``sandbox``, and unrelated software creates one too.
    """
    return state.has_system_evidence or _strict_int(state.receipt.get("sandbox_uid")) is not None


def _group_step(state: LegacyState, system: System) -> Step | None:
    if not state.user_in_sandbox_group or not _sandbox_account_is_legacy(state):
        return None
    step = Step("group", _step_title("group"))
    try:
        step.commands.append(Command(privileged_argv(system, "gpasswd", "-d", state.invoking_user, SANDBOX_USER)))
    except UntrustedCommandError as exc:
        step.blocked = str(exc)
    return step


def _user_blocker(state: LegacyState) -> str:
    """Why ``userdel -r`` must not be planned, or ""."""
    pw_dir = os.path.realpath(state.sandbox_pw_dir) if state.sandbox_pw_dir else ""
    expected = os.path.realpath(state.sandbox_home)
    if state.ownership_error:
        return f"waits for the OpenClaw home ownership and ACL restore ({state.ownership_error})"
    if not pw_dir or pw_dir in FORBIDDEN_ROOTS:
        return f"the sandbox account's home is {state.sandbox_pw_dir or 'unset'}; `userdel -r` would delete it"
    if pw_dir != expected:
        return (
            f"the sandbox account's home is {pw_dir}, not the configured sandbox home {expected}; it may not be "
            "the account legacy setup created, so `userdel -r` would delete a directory cleanup knows nothing about"
        )
    if state.openclaw_home and _under(state.openclaw_home, pw_dir):
        return f"the OpenClaw home {state.openclaw_home} lives inside {pw_dir}; `userdel -r` would delete it"
    if state.claw_paths_in_sandbox_home and not state.validated_home:
        return (
            f"claw.home_dir or claw.config_file points into {pw_dir} and no pinned OpenClaw home was found, so "
            "that directory may hold the only OpenClaw state; move it out before `userdel -r` deletes it"
        )
    if state.sandbox_link_state == "not-a-link":
        return f"{state.sandbox_link} is a real directory; `userdel -r` would delete it"
    return ""


def _user_removal_ready(state: LegacyState, system: System, ownership_planned: bool) -> Callable[[], str]:
    """Refuse ``userdel`` while the uid it frees still owns or has ACLs on the home.

    A deleted account's uid is handed to the next system account, which
    would inherit whatever the sandbox user kept in the OpenClaw home.
    """

    def check() -> str:
        if ownership_planned and not state.step_done("ownership"):
            return "the OpenClaw home ownership and ACL restore did not complete"
        home = state.openclaw_home
        if not home:
            return ""
        try:
            info = os.lstat(home)
        except OSError:
            return ""
        if not stat.S_ISDIR(info.st_mode):
            return ""
        if info.st_uid == state.sandbox_uid:
            return f"{home} is still owned by uid {state.sandbox_uid}"
        if state.sandbox_uid in (_acl_uids(system, home) or set()):
            return f"{home} still carries ACL entries for uid {state.sandbox_uid}"
        return ""

    return check


def _user_step(state: LegacyState, system: System, earlier: Sequence[Step]) -> Step | None:
    if state.sandbox_uid is None or not state.sandbox_user_exists or not _sandbox_account_is_legacy(state):
        return None
    step = Step("user", _step_title("user"))
    step.blocked = _user_blocker(state)
    if step.blocked:
        return step
    ownership_planned = any(other.id == "ownership" and not other.blocked for other in earlier)
    try:
        if state.sandbox_link_state == "unknown":
            # The operator cannot see into the sandbox home (0700 on most
            # distributions); look as root now that any symlink is gone.
            step.commands.append(
                Command(
                    privileged_argv(system, "test", "!", "-e", state.sandbox_link),
                    refusal=f"{state.sandbox_link} still exists and `userdel -r` would delete it",
                )
            )
        step.commands.append(
            Command(
                privileged_argv(system, "userdel", "-r", SANDBOX_USER),
                check=unprivileged_argv(system, "pgrep", "-u", str(state.sandbox_uid)),
                run_when="check-fails",
                precondition=_user_removal_ready(state, system, ownership_planned),
            )
        )
    except UntrustedCommandError as exc:
        step.blocked = str(exc)
        return step
    home = state.sandbox_pw_dir
    step.notes.append(
        f"deletes {home} and runs only once the ownership and ACL restore completed and "
        f"{state.openclaw_home or 'the OpenClaw home'} no longer carries uid {state.sandbox_uid}"
    )
    return step


def _binary_step(state: LegacyState, system: System) -> Step | None:
    binary = state.binary
    if binary is None:
        return None
    step = Step("binary", _step_title("binary"))
    if not binary.removable:
        step.blocked = f"{binary.path} {binary.reason}"
        return step
    try:
        step.commands.append(Command(privileged_argv(system, "rm", "-f", "--", binary.path)))
    except UntrustedCommandError as exc:
        step.blocked = str(exc)
    return step


# Steps the config reset waits for: the pinned claw.openclaw_home_original is
# the anchor that keeps a rewritten ownership backup from being trusted, and
# claw.* must keep pointing at the home until its restore is complete.
_CONFIG_WAITS_FOR = ("ownership", "openclaw_json")


def _config_step(state: LegacyState, cfg, earlier: Sequence[Step]) -> Step | None:
    if not state.config_changes:
        return None
    step = Step("config", _step_title("config"))
    if state.ownership_error:
        step.blocked = "waits for the OpenClaw home ownership restore"
        return step
    changes = dict(state.config_changes)
    rendered = ", ".join(f"{key}: {old!r} -> {new!r}" for key, (old, new) in changes.items())
    waits_for = [other.id for other in earlier if other.id in _CONFIG_WAITS_FOR and not other.blocked]

    def run() -> str:
        pending = [step_id for step_id in waits_for if not state.step_done(step_id)]
        if pending:
            raise RuntimeError(f"skipped: waits for the {' and '.join(pending)} step to complete")
        reset_config(cfg, changes)
        return "config saved"

    step.actions.append(Action(f"update config.yaml ({rendered})", run))
    return step


# Data-dir files an earlier step still needs; each is only discarded once those
# steps completed (or were not needed), so a failed step can be retried.
_ARTIFACT_DEPENDS_ON: dict[str, tuple[str, ...]] = {
    "saved.route_localnet": ("network",),
    "sandbox.netns": ("network",),
    # The PID files and run-sandbox.sh (the documented way to stop the
    # non-systemd launcher) stay until the sandbox is verified stopped.
    "sandbox.pids": ("stopped",),
    "openshell.pid": ("stopped",),
    "scripts/run-sandbox.sh": ("stopped",),
    # The backup locates the home for a retried openclaw.json rewrite.
    OWNERSHIP_BACKUP_NAME: ("ownership", "openclaw_json"),
}


def _artifacts_step(state: LegacyState, system: System, earlier: Sequence[Step]) -> Step | None:
    candidates = [
        rel for rel in state.artifacts if rel not in NON_EVIDENCE_ARTIFACTS or state.has_system_evidence
    ]
    if not candidates:
        return None
    step = Step("artifacts", _step_title("artifacts"))
    planned = {other.id for other in earlier if not other.blocked}
    blocked = {other.id for other in earlier if other.blocked}
    artifacts = [rel for rel in candidates if not blocked.intersection(_ARTIFACT_DEPENDS_ON.get(rel, ()))]
    kept = [rel for rel in candidates if rel not in artifacts]
    if not artifacts:
        return None
    data_dir = state.data_dir
    stamp = system.now().strftime("%Y%m%dT%H%M%SZ")
    backup_dir = os.path.join(data_dir, "backups", f"legacy-sandbox-{stamp}")

    def run() -> str:
        ready = [
            rel
            for rel in artifacts
            if all(dep not in planned or state.step_done(dep) for dep in _ARTIFACT_DEPENDS_ON.get(rel, ()))
        ]
        return backup_and_remove_artifacts(data_dir, ready, backup_dir)

    step.actions.append(
        Action(f"move {len(artifacts)} file(s) into {backup_dir}: " + ", ".join(artifacts), run),
    )
    for rel in kept:
        step.notes.append(f"kept {rel} until the step that needs it can run")
    return step


def plan(
    state: LegacyState,
    cfg,
    *,
    remove_user: bool = False,
    remove_binary: bool = False,
    system: System | None = None,
) -> list[Step]:
    """Return the ordered steps still needed for *state*.

    Nothing after the units step runs until the ``stopped`` step verifies
    that no part of the legacy sandbox is still running. Ownership is
    restored before ``openclaw.json`` is rewritten so that the rewrite never
    needs root inside a tree the sandbox user controlled.
    """
    system = system or System()
    steps: list[Step] = []
    builders: dict[str, Callable[[], Step | None]] = {
        "units": lambda: _units_step(state, system),
        "stopped": lambda: _stopped_step(state, system),
        "network": lambda: _network_step(state, system),
        "ownership": lambda: _ownership_step(state, system),
        "openclaw_json": lambda: _openclaw_json_step(state, steps),
        "group": lambda: _group_step(state, system),
        "user": lambda: _user_step(state, system, steps) if remove_user else None,
        "binary": lambda: _binary_step(state, system) if remove_binary else None,
        "config": lambda: _config_step(state, cfg, steps),
        "artifacts": lambda: _artifacts_step(state, system, steps),
    }
    for step_id in STEP_ORDER:
        step = builders[step_id]()
        if step is not None:
            steps.append(step)
    if all(step.id in ("units", "stopped") for step in steps):
        # Nothing runs after the units step, so there is nothing to guard.
        steps = [step for step in steps if step.id != "stopped"]
    return steps


# ---------------------------------------------------------------------------
# Python-native changes
# ---------------------------------------------------------------------------


def _parse_openclaw_json(text: str) -> Any:
    """Parse openclaw.json as OpenClaw does: JSON, or JSON with comments and trailing commas."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    from defenseclaw.connector_paths import _normalize_jsonc

    try:
        return json.loads(_normalize_jsonc(text))
    except ValueError as exc:
        raise ValueError(f"openclaw.json is neither JSON nor JSON with comments ({exc})") from exc


def restore_openclaw_gateway(openclaw_config: str) -> str:
    """Restore host-mode gateway settings in openclaw.json (F-0425).

    Runs as the invoking user after ownership is restored. The file is opened
    with ``O_NOFOLLOW`` and replaced atomically in its own directory, so a
    planted symlink can neither disclose nor redirect the write. JSON with
    comments or trailing commas is accepted, as OpenClaw accepts it; the
    rewrite is plain JSON.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(openclaw_config, flags)
    except FileNotFoundError:
        return "no openclaw.json to restore"
    except OSError as exc:
        raise RuntimeError(f"refusing to read {openclaw_config}: {exc.strerror or exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"refusing to rewrite {openclaw_config}: not a regular file")
        with os.fdopen(fd, encoding="utf-8") as fh:
            fd = -1
            text = fh.read()
    finally:
        if fd != -1:
            os.close(fd)
    document = _parse_openclaw_json(text)
    if not isinstance(document, dict):
        raise RuntimeError(f"{openclaw_config} is not a JSON object")
    updated = copy.deepcopy(document)
    gateway = updated.get("gateway")
    if not isinstance(gateway, dict):
        gateway = {}
        updated["gateway"] = gateway
    gateway["mode"] = "local"
    gateway["port"] = DEFAULT_OPENCLAW_PORT
    gateway["bind"] = "loopback"
    providers = (updated.get("models") or {}).get("providers") if isinstance(updated.get("models"), dict) else None
    provider = providers.get("defenseclaw") if isinstance(providers, dict) else None
    if isinstance(provider, dict) and isinstance(provider.get("baseUrl"), str):
        parsed = urlparse(provider["baseUrl"])
        if parsed.hostname == LEGACY_HOST_IP:
            provider["baseUrl"] = f"http://localhost:{parsed.port or 4000}{parsed.path or ''}"
    if updated == document:
        return "already in host mode"
    directory = os.path.dirname(openclaw_config)
    fd, tmp_path = tempfile.mkstemp(prefix=".openclaw.json.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(updated, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.chmod(tmp_path, stat.S_IMODE(info.st_mode))
        os.replace(tmp_path, openclaw_config)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return "gateway settings restored"


def reset_config(cfg, changes: dict[str, tuple[Any, Any]]) -> None:
    """Apply the planned config reset and persist it."""
    for key, (_old, new) in changes.items():
        section_name, attr = key.split(".", 1)
        setattr(getattr(cfg, section_name), attr, new)
    cfg.save()


def backup_and_remove_artifacts(data_dir: str, artifacts: Sequence[str], backup_dir: str) -> str:
    """Copy each legacy artifact into *backup_dir* (links as links), then remove it."""
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    moved = 0
    for rel in artifacts:
        source = os.path.join(data_dir, rel)
        try:
            info = os.lstat(source)
        except FileNotFoundError:
            continue
        target = os.path.join(backup_dir, rel)
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        if stat.S_ISLNK(info.st_mode):
            os.symlink(os.readlink(source), target)
        elif stat.S_ISREG(info.st_mode):
            shutil.copy2(source, target, follow_symlinks=False)
        else:
            continue
        os.unlink(source)
        moved += 1
    for rel in DATA_DIR_ARTIFACT_DIRS:
        directory = os.path.join(data_dir, rel)
        try:
            if os.path.isdir(directory) and not os.path.islink(directory) and not os.listdir(directory):
                os.rmdir(directory)
        except OSError:
            pass
    return f"moved {moved} file(s) to {backup_dir}"


def _write_receipt(path: str, receipt: dict[str, Any]) -> None:
    directory = os.path.dirname(path)
    fd, tmp_path = tempfile.mkstemp(prefix=".legacy-sandbox-cleanup.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(receipt, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


@dataclass
class ApplyResult:
    applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    dry_run: bool = False


def describe(steps: Sequence[Step]) -> list[str]:
    """Human-readable plan lines, with every command's exact argv."""
    lines: list[str] = []
    for index, step in enumerate(steps, 1):
        lines.append(f"{index}. {step.title}")
        if step.blocked:
            lines.append(f"     skipped: {step.blocked}")
            continue
        for command in step.commands:
            rendered = command.render()
            lines.append(f"     $ {rendered[0]}")
            lines.extend(f"       {extra.strip()}" for extra in rendered[1:])
        for action in step.actions:
            lines.append(f"     - {action.description}")
        for note in step.notes:
            lines.append(f"     note: {note}")
    return lines


def _run_command(command: Command, system: System) -> tuple[bool, str]:
    if command.precondition is not None:
        reason = command.precondition()
        if reason:
            return False, f"refused: {reason}"
    runs = 0
    for _ in range(max(command.repeat, 1)):
        if command.check:
            probe = system.runner(command.check)
            wanted = probe.returncode == 0 if command.run_when == "check-ok" else probe.returncode != 0
            if not wanted:
                if command.run_when == "check-fails":
                    return False, f"refused: `{render_argv(command.check)}` found a blocker"
                break
        result = system.runner(command.argv)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()
            return False, f"`{render_argv(command.argv)}` exited {result.returncode}" + (
                f": {detail[-1]}" if detail else ""
            )
        runs += 1
        if not command.check:
            break
    return True, "ran" if runs else "already clean"


def apply(
    steps: Sequence[Step],
    state: LegacyState,
    *,
    yes: bool,
    dry_run: bool,
    system: System | None = None,
    echo: Callable[[str], None] | None = None,
    confirm: Callable[[str], bool] | None = None,
) -> ApplyResult:
    """Print *steps*, ask for consent, run them, and record the receipt."""
    import click

    from defenseclaw import ux

    system = system or System()
    echo = echo or ux.echo
    confirm = confirm or (lambda prompt: click.confirm(prompt, default=False))
    result = ApplyResult(dry_run=dry_run)
    runnable = [step for step in steps if not step.blocked]

    for line in describe(steps):
        echo(f"  {line}")
    if dry_run:
        echo("  Dry run: nothing was changed.")
        return result
    if not runnable:
        return result
    if not yes and not confirm(f"Apply {len(runnable)} cleanup step(s) to this machine?"):
        raise SystemExit(1)
    sudo = system.trusted("sudo")
    needs_sudo = not system.is_root() and any(
        sudo and (command.argv[:1] == (sudo,) or command.check[:1] == (sudo,))
        for step in runnable
        for command in step.commands
    )
    if needs_sudo and not (system.authenticate or validate_sudo)(system):
        raise click.ClickException("sudo authentication failed; nothing was changed")

    receipt = copy.deepcopy(state.receipt) if state.receipt else {}
    receipt.setdefault("version", 1)
    receipt.setdefault("started_at", system.now().isoformat())
    receipt.setdefault("legacy_gateway", dict(state.legacy_gateway))
    if state.sandbox_uid is not None:
        receipt.setdefault("sandbox_uid", state.sandbox_uid)
    if state.validated_home:
        # An anchor that outlives the pin and the backup: a later run still
        # finds the home to retry on, and still refuses a rewritten backup.
        receipt.setdefault("openclaw_home", state.openclaw_home)
    receipt.setdefault("steps", {})
    # Later actions consult completed steps through the live receipt.
    state.receipt = receipt
    _write_receipt(state.receipt_path, receipt)

    for step in steps:
        if step.blocked:
            result.skipped.append(step.id)
            continue
        ok = True
        details: list[str] = []
        for command in step.commands:
            success, detail = _run_command(command, system)
            details.append(detail)
            if not success:
                ok = False
                echo(f"  ✗ {step.title}: {detail}")
                break
        if ok:
            for action in step.actions:
                try:
                    details.append(action.run())
                except Exception as exc:  # noqa: BLE001 - report and keep the receipt accurate
                    ok = False
                    echo(f"  ✗ {step.title}: {exc}")
                    break
        receipt["steps"][step.id] = {
            "status": "done" if ok else "failed",
            "at": system.now().isoformat(),
            "detail": "; ".join(d for d in details if d)[:1000],
        }
        receipt["updated_at"] = system.now().isoformat()
        _write_receipt(state.receipt_path, receipt)
        if ok:
            result.applied.append(step.id)
            echo(f"  ✓ {step.title}")
            continue
        result.failed.append(step.id)
        if step.id in _CRITICAL_STEPS:
            # Everything after assumes the sandbox is no longer running;
            # resetting ownership or config under a live sandbox would
            # strand it half-configured.
            echo("  Stopping: later steps require the legacy sandbox to be stopped.")
            break
    # Blocked steps are work left for a later run, so they keep it unfinished.
    receipt["completed"] = not result.failed and all(step.id in result.applied for step in steps)
    _write_receipt(state.receipt_path, receipt)
    return result


_CRITICAL_STEPS = frozenset({"units", "stopped"})


def quick_evidence(cfg) -> list[str]:
    """Cheap signs of a legacy install for doctor and status.

    Reads only the config and this install's data directory: no subprocess,
    no sudo, no host-global paths, so it is safe on every platform and in
    read-only diagnostics. :func:`detect` does the full inspection.
    """
    from defenseclaw.config import legacy_standalone_configured

    evidence: list[str] = []
    if legacy_standalone_configured(cfg):
        evidence.append("config openshell.mode=standalone")
    data_dir = os.path.expanduser(str(getattr(cfg, "data_dir", "") or ""))
    if not data_dir:
        return evidence
    for rel in (OWNERSHIP_BACKUP_NAME, "sandbox.netns", "systemd/openshell-sandbox.service"):
        if os.path.lexists(os.path.join(data_dir, rel)):
            evidence.append(f"{rel} in the data directory")
    receipt = _read_receipt(os.path.join(data_dir, RECEIPT_NAME))
    if receipt and not receipt.get("completed"):
        evidence.append("an unfinished legacy-cleanup receipt")
    return evidence


def complete_idle_receipt(state: LegacyState, system: System | None = None) -> bool:
    """Mark an unfinished receipt complete when no cleanup step is left.

    A run that fails or skips a step leaves the receipt unfinished, which
    doctor reports; once a later detect plans nothing, that is stale.
    """
    if not state.receipt or state.receipt.get("completed"):
        return False
    system = system or System()
    receipt = copy.deepcopy(state.receipt)
    receipt["completed"] = True
    receipt["updated_at"] = system.now().isoformat()
    _write_receipt(state.receipt_path, receipt)
    state.receipt = receipt
    return True


def hints(state: LegacyState, *, remove_user: bool, remove_binary: bool) -> list[str]:
    """Opt-in cleanup the operator did not ask for, worth mentioning."""
    out: list[str] = []
    if not remove_user and state.sandbox_user_exists and state.has_system_evidence:
        out.append(f"the {SANDBOX_USER!r} user still exists; re-run with --remove-user to delete it")
    if not remove_binary and state.binary is not None:
        out.append(f"{state.binary.path} is still installed; re-run with --remove-binary to remove it")
    return out


def review_notes(state: LegacyState) -> list[str]:
    """What to review before OpenClaw runs on the host again.

    In legacy mode the sandboxed agent owned (and had rwX ACLs on) the whole
    real OpenClaw home, so cleanup hands back a tree it could have seeded
    with plugins, skills, hooks, or MCP server commands. Cleanup only resets
    the gateway settings in openclaw.json.
    """
    home = state.openclaw_home
    if not home:
        return []
    present = [rel for rel in REVIEW_PATHS if os.path.lexists(os.path.join(home, rel))]
    listed = f", including {', '.join(present)}" if present else ""
    return [
        f"while sandboxed, the agent could write anywhere in {home}{listed}; run the scans below "
        "before OpenClaw runs on this host again",
    ]


# Scans come first: `setup guardrail` restarts OpenClaw, which loads whatever
# the sandboxed agent left in the home.
NEXT_STEPS = (
    ("Scan the skills the sandboxed agent could have changed", "defenseclaw skill scan --all"),
    ("Scan the OpenClaw plugins it could have changed or added", "defenseclaw plugin scan --all"),
    ("Scan the MCP servers it could have added to openclaw.json", "defenseclaw mcp scan --all"),
    (
        "Point the guardrail back at the host proxy; this re-registers the DefenseClaw plugin and restarts "
        "the gateway and OpenClaw",
        "defenseclaw setup guardrail",
    ),
)
