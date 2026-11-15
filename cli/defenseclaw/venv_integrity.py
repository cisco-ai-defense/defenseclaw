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

"""Prove that the installed Python packages hold the files of their wheels.

uv links every package of a DefenseClaw environment from its long-lived cache
(hard links on Linux and Windows), so one write into an installed file, in any
environment built from that cache, changes the cached copy too. uv trusts a
cached package without reading its files again, and every later environment,
the fresh one an upgrade builds included, gets the changed file. A Windows
upgrade to 1.0.9 got LiteLLM 1.91.5's ``rust_bridge/__init__.py`` and
``loader.py`` inside LiteLLM 1.103.10 that way; ``import mcpscanner`` failed
and nothing noticed (rel-1-0-10 GAP-0006).

Each ``*.dist-info/RECORD`` lists the size and SHA-256 of every file of the
wheel. This module compares the installed files with it: the size of every
file and the digest of every Python source (the files an import reads; the
digests of the large binaries would cost the install seconds, and a file of
another wheel almost never has the same size).

It is standard library only and runs as a script, which the installers call
after they build an environment (``python -I venv_integrity.py SITE``): exit 0
when every package is intact, 3 with the damaged distributions on standard
output (one name per line) and the files on standard error, 2 on a usage error.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import sys
import time
from pathlib import Path

DAMAGED_EXIT = 3

DOCS_URL = "https://cisco-ai-defense.github.io/defenseclaw/docs"


def install_repair_hint(what: str, *, windows: bool) -> str:
    """The command that repairs *what* (a part of this install).

    On macOS and Linux the release upgrade resolver reinstalls the release at
    the installed version too (the built-in ``defenseclaw upgrade`` stops early
    when the version is already current, so it cannot repair a missing part);
    on Windows, running the install command again does (from 1.0 the 0.8.x
    Setup package and its ``/repair`` are retired). Both build a fresh
    environment and download again what their check finds damaged. The
    caller names the platform: doctor decides it from its own view of the
    host, as every other doctor row does.
    """

    if windows:
        return (
            "repair the install by running the install command again "
            f"({DOCS_URL}/get-started/windows/install-lifecycle/#repair)"
        )
    return (
        f"repair {what} with the release upgrade resolver, `bash defenseclaw-upgrade.sh --yes` "
        f"(get and verify it as {DOCS_URL}/get-started/upgrade/ shows)"
    )


def import_error(statement: str, env: dict[str, str] | None = None, timeout: float = 60.0) -> str | None:
    """Run *statement* in a child of this interpreter (isolated mode).

    Returns ``""`` when it imports, the last line of its error when it does
    not, and ``None`` when it did not finish in *timeout* seconds. A damaged
    package cannot break the caller this way. Raises OSError when the child
    cannot start.
    """
    import subprocess

    try:
        probe = subprocess.run(
            [sys.executable, "-I", "-c", statement],
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    if probe.returncode == 0:
        return ""
    lines = [line.strip() for line in (probe.stderr or "").splitlines() if line.strip()]
    return lines[-1][:300] if lines else f"exit {probe.returncode}"


# ``defenseclaw doctor`` runs the import probe of the MCP scanner SDK; the
# import loads LiteLLM and takes seconds, so a probe that passed is remembered
# per environment (GAP-0938). The record holds the interpreter, the DefenseClaw
# version, the stat of the package folder and of the RECORD of each
# distribution the probe imports, and the mtime and entry count of
# site-packages (a dependency outside the key that is removed or upgraded
# changes it); a reinstall, an upgrade or a repair changes at least one of
# them and the probe runs again. A pass also expires after a day, because a
# write into an installed file leaves none of those stamps changed (the
# uv-cache hard links behind GAP-0006). A failure is never remembered, so a
# repair shows at once. A ``__pycache__`` created beside the packages (a first
# run as another user, such as sudo) changes the site-packages stamp and costs
# one more probe, no more.
PROBE_CACHE_NAME = "scanner_import_probe.json"
PROBE_PASS_MAX_AGE = 24 * 3600


def _stamp(path: str | os.PathLike[str] | None) -> list[int] | None:
    """``[mtime_ns, size]`` of *path*, ``None`` when it cannot be read."""
    if not path:
        return None
    try:
        info = os.stat(path)
    except OSError:
        return None
    return [info.st_mtime_ns, info.st_size]


def _site_stamp() -> list[int] | None:
    """``[mtime_ns, entry count]`` of the site-packages folder, ``None`` when unreadable."""
    site = site_packages()
    try:
        with os.scandir(site) as entries:
            count = sum(1 for _ in entries)
        return [os.stat(site).st_mtime_ns, count]
    except OSError:
        return None


def probe_key(package: str, dists: tuple[str, ...], defenseclaw_version: str) -> dict[str, object]:
    """What the import of *package* depends on, as plain JSON.

    For each of *dists* (the distributions the import loads) the key holds the
    version and the stat of its ``RECORD``; the *package* folder is stamped
    too. Nothing here imports the package.
    """
    import importlib.metadata as importlib_metadata
    import importlib.util

    key: dict[str, object] = {"python": sys.executable, "defenseclaw": defenseclaw_version}
    try:
        spec = importlib.util.find_spec(package)
    except (ImportError, ValueError):
        spec = None
    folders = list(spec.submodule_search_locations or []) if spec else []
    key["package"] = _stamp(folders[0]) if folders else None
    key["site"] = _site_stamp()
    for name in dists:
        try:
            dist = importlib_metadata.distribution(name)
        except importlib_metadata.PackageNotFoundError:
            key[name] = None
            continue
        record = next(
            (f for f in (dist.files or []) if f.name == "RECORD" and f.parent.name.endswith(".dist-info")),
            None,
        )
        key[name] = [dist.version, _stamp(dist.locate_file(record) if record else None)]
    return key


def _read_probe_cache(path: str, key: dict[str, object], now: float) -> bool:
    """``True`` when a pass for *key* is remembered and fresh; the probe runs again otherwise."""
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            return False
        with open(path, encoding="utf-8") as handle:
            record = json.load(handle)
        if not isinstance(record, dict) or record.get("key") != key or record.get("error", "") != "":
            return False
        at = record.get("at")
        if isinstance(at, bool) or not isinstance(at, (int, float)):
            return False
        return 0 <= now - at <= PROBE_PASS_MAX_AGE
    except (OSError, ValueError):
        return False


def cached_import_error(
    statement: str,
    cache_path: str,
    key: dict[str, object],
    env: dict[str, str] | None = None,
    timeout: float = 60.0,
) -> str | None:
    """:func:`import_error`, remembered in *cache_path* while *key* holds.

    Only a pass is stored: a failure or a timeout (``None``) always probes
    again. A cache that cannot be read or written only costs the probe; it
    never changes the result.
    """
    now = time.time()
    if cache_path:
        if _read_probe_cache(cache_path, key, now):
            return ""
    error = import_error(statement, env=env, timeout=timeout)
    if error == "" and cache_path:
        try:
            from defenseclaw.file_permissions import atomic_write_private_bytes

            body = json.dumps({"key": key, "at": now}, sort_keys=True).encode("utf-8")
            atomic_write_private_bytes(cache_path, body)
        except OSError:
            pass
    return error


def site_packages() -> str:
    """The site-packages folder of the running interpreter."""
    import sysconfig

    return sysconfig.get_path("purelib")


def _dist_name(info: Path) -> str:
    try:
        with open(info / "METADATA", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    break
                if line.lower().startswith("name:"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return info.name[: -len(".dist-info")].rsplit("-", 1)[0]


def _digest(path: Path) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            sha.update(block)
    return "sha256=" + base64.urlsafe_b64encode(sha.digest()).rstrip(b"=").decode("ascii")


def _problem(path: Path, digest: str, size: str) -> str:
    try:
        actual = path.stat().st_size
    except FileNotFoundError:
        return "missing"
    except OSError as exc:
        return f"unreadable ({exc.strerror or exc})"
    if size.isdigit() and actual != int(size):
        return f"{actual} bytes, the wheel has {size}"
    if path.suffix == ".py" and digest.startswith("sha256="):
        try:
            if _digest(path) != digest:
                return "content differs from the wheel"
        except OSError as exc:
            return f"unreadable ({exc.strerror or exc})"
    return ""


def damaged_files(site: str | os.PathLike[str], names: set[str] | None = None) -> dict[str, list[str]]:
    """``{distribution: ["path (why)", ...]}`` for the packages in *site*
    whose files differ from their RECORD; only *names* (normalized) when given."""
    root = Path(site)
    damaged: dict[str, list[str]] = {}
    for info in sorted(root.glob("*.dist-info")):
        record = info / "RECORD"
        if not record.is_file():
            continue
        name = _dist_name(info)
        if names is not None and normalize(name) not in names:
            continue
        try:
            with open(record, encoding="utf-8", newline="") as handle:
                rows = list(csv.reader(handle))
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            damaged.setdefault(name, []).append(f"{record.name} unreadable ({exc})")
            continue
        for row in rows:
            if len(row) < 3 or not row[1]:
                continue  # RECORD itself, INSTALLER and the like carry no digest
            why = _problem(Path(os.path.normpath(root / row[0])), row[1], row[2])
            if why:
                damaged.setdefault(name, []).append(f"{row[0]} ({why})")
    return damaged


def normalize(name: str) -> str:
    """The PEP 503 form of a distribution name."""
    out = "".join("-" if ch in "_." else ch for ch in name.lower())
    while "--" in out:
        out = out.replace("--", "-")
    return out


def describe(damaged: dict[str, list[str]], limit: int = 3) -> str:
    """One line naming the damaged packages and their first files."""
    parts = []
    for name, files in sorted(damaged.items()):
        more = f" and {len(files) - limit} more" if len(files) > limit else ""
        parts.append(f"{name}: " + ", ".join(files[:limit]) + more)
    return "; ".join(parts)


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] in {"-h", "--help"}:
        print("usage: venv_integrity.py SITE_PACKAGES", file=sys.stderr)
        return 0 if argv[:1] in (["-h"], ["--help"]) else 2
    damaged = damaged_files(argv[0])
    for name in sorted(damaged):
        print(name)
        for line in damaged[name][:20]:
            print(f"{name}: {line}", file=sys.stderr)
    return DAMAGED_EXIT if damaged else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
