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

"""``defenseclaw upgrade`` and ``defenseclaw rollback``.

This is the only upgrade code that stays on a machine between releases, so it
must never need to change. It picks a release, downloads that release's
installer, checks it against the release's ``checksums.txt``, and runs it.
Everything else (what to download, how to swap, migrate, and roll back) lives
in the installer of the release being installed, so a fix to any of it ships
with the next release.

Standard library only, and imported before the rest of the CLI, so it keeps
working when anything else in the installed version is broken.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

DEFAULT_REPO = "cisco-ai-defense/defenseclaw"
REPO_ENV = "DEFENSECLAW_REPO"
# Tests only: take the installer and checksums.txt from this directory and
# pass it to the installer as --local.
LOCAL_DIR_ENV = "DEFENSECLAW_UPGRADE_LOCAL_DIR"
_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_TIMEOUT = 30

USAGE = """Usage: defenseclaw upgrade [--version X.Y.Z] [--yes]
       defenseclaw rollback [--yes]

upgrade   Download and run the installer of the latest release (or X.Y.Z).
rollback  Restore the install that the last upgrade replaced.
"""


class ShimError(RuntimeError):
    """A user-facing failure; nothing on the machine was changed."""


def run(argv: list[str]) -> int:
    """Run ``upgrade`` or ``rollback`` with the arguments after the command."""

    command, args = argv[0], argv[1:]
    try:
        options = _parse(command, args)
        if options is None:
            print(USAGE, end="")
            return 0
        if command == "rollback":
            return _rollback(yes=options["yes"])
        return _upgrade(options["version"], yes=options["yes"])
    except ShimError as exc:
        print(f"  ✗ {exc}", file=sys.stderr)
        print("    Nothing was changed.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


def _parse(command: str, args: list[str]) -> dict[str, object] | None:
    options: dict[str, object] = {"version": None, "yes": False}
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("-h", "--help"):
            return None
        if arg in ("-y", "--yes"):
            options["yes"] = True
        elif command == "upgrade" and arg == "--version" and index + 1 < len(args):
            index += 1
            options["version"] = args[index]
        elif command == "upgrade" and arg.startswith("--version="):
            options["version"] = arg.split("=", 1)[1]
        else:
            raise ShimError(f"unknown option {arg!r} for 'defenseclaw {command}' (see --help)")
        index += 1
    version = options["version"]
    if version is not None:
        version = str(version).removeprefix("v")
        if not _VERSION.match(version):
            raise ShimError(f"--version must look like 1.2.3, got {options['version']!r}")
        options["version"] = version
    return options


def _upgrade(version: str | None, *, yes: bool) -> int:
    from defenseclaw import __version__ as installed

    repo = os.environ.get(REPO_ENV) or DEFAULT_REPO
    local_dir = os.environ.get(LOCAL_DIR_ENV)
    explicit = version is not None
    if version is None:
        version = _local_version(local_dir) if local_dir else _latest_version(repo)
    if _key(version) < (1, 0, 0):
        raise ShimError(f"DefenseClaw {installed} cannot install {version}; 1.x installs only 1.0.0 or later")
    if not explicit and _key(version) <= _key(installed):
        print(f"  ✓ DefenseClaw {installed} is up to date (latest release: {version}).")
        return 0

    print(f"  → Installing DefenseClaw {version} (installed: {installed})")
    workdir = tempfile.mkdtemp(prefix="defenseclaw-upgrade-")
    installer = _fetch_installer(repo, version, local_dir, workdir)
    extra = ["--local", local_dir] if local_dir else []
    return _run_installer(installer, (["--yes"] if yes else []) + extra, workdir)


def _rollback(*, yes: bool) -> int:
    home = os.path.expanduser(os.environ.get("DEFENSECLAW_HOME") or "~/.defenseclaw")
    name = _installer_name()
    installer = os.path.join(home, "installer", name)
    if not os.path.isfile(installer):
        raise ShimError(
            f"no saved installer at {installer}; download {name} from the release you want and run it "
            "with --rollback"
        )
    workdir = tempfile.mkdtemp(prefix="defenseclaw-rollback-")
    copy = os.path.join(workdir, name)
    shutil.copyfile(installer, copy)
    return _run_installer(copy, ["--rollback"] + (["--yes"] if yes else []), workdir)


def _run_installer(path: str, args: list[str], workdir: str) -> int:
    if os.name == "nt":
        # The running CLI holds files in .venv open; start the installer in its
        # own console and exit so it can replace them.
        powershell = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
        )
        ps_args = [_powershell_flag(arg) for arg in args]
        subprocess.Popen(  # noqa: S603 - fixed interpreter and verified script
            [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path, *ps_args],
            creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            cwd=workdir,
        )
        print("  → The installer continues in a new window.")
        return 0
    bash = "/bin/bash" if os.path.exists("/bin/bash") else (shutil.which("bash") or "bash")
    sys.stdout.flush()
    sys.stderr.flush()
    os.chdir(workdir)
    os.execv(bash, [bash, path, *args])
    return 0  # pragma: no cover - execv does not return


def _powershell_flag(arg: str) -> str:
    return {"--yes": "-Yes", "--rollback": "-Rollback", "--local": "-Local"}.get(arg, arg)


def _installer_name() -> str:
    return "install.ps1" if os.name == "nt" else "install.sh"


def _fetch_installer(repo: str, version: str, local_dir: str | None, workdir: str) -> str:
    name = _installer_name()
    installer = os.path.join(workdir, name)
    checksums = os.path.join(workdir, "checksums.txt")
    if local_dir:
        for asset, destination in ((name, installer), ("checksums.txt", checksums)):
            try:
                shutil.copyfile(os.path.join(local_dir, asset), destination)
            except OSError as exc:
                raise ShimError(f"could not read {asset} from {local_dir}: {exc}") from None
    else:
        base = f"https://github.com/{repo}/releases/download/{version}"
        for asset, destination in ((name, installer), ("checksums.txt", checksums)):
            _download(f"{base}/{asset}", destination)
    expected = _expected_sha256(checksums, name)
    with open(installer, "rb") as stream:
        actual = hashlib.sha256(stream.read()).hexdigest()
    if actual != expected:
        raise ShimError(f"{name} for {version} does not match checksums.txt")
    return installer


def _expected_sha256(checksums: str, name: str) -> str:
    with open(checksums, encoding="utf-8") as stream:
        for line in stream:
            parts = line.split()
            if len(parts) == 2 and parts[1].lstrip("*") == name and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
                return parts[0]
    raise ShimError(f"checksums.txt has no entry for {name}")


def _tls_context() -> ssl.SSLContext:
    """System trust (and SSL_CERT_FILE), plus certifi's bundle when installed."""

    context = ssl.create_default_context()
    try:
        import certifi

        context.load_verify_locations(certifi.where())
    except Exception:  # noqa: BLE001 - certifi is optional
        pass
    return context


def _download(url: str, destination: str) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "defenseclaw-upgrade"})
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT, context=_tls_context()) as response, open(  # noqa: S310
            destination, "wb"
        ) as out:
            shutil.copyfileobj(response, out)
    except (urllib.error.URLError, OSError) as exc:
        raise ShimError(f"could not download {url}: {exc}") from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802 - stdlib signature
        return None


def latest_version(repo: str | None = None, *, timeout: float = _TIMEOUT) -> str:
    """Return the tag GitHub marks as the latest release.

    Reads the ``releases/latest`` redirect (no API rate limit), falling back
    to a GET of the same page and then to the REST API.
    """

    repo = repo or os.environ.get(REPO_ENV) or DEFAULT_REPO
    for method in ("HEAD", "GET"):
        tag = _latest_from_redirect(repo, method, timeout)
        if tag:
            return tag
    tag = _latest_from_api(repo, timeout)
    if tag:
        return tag
    raise ShimError(f"could not look up the latest release of {repo}")


def _latest_from_redirect(repo: str, method: str, timeout: float) -> str | None:
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=_tls_context())
    )
    request = urllib.request.Request(
        f"https://github.com/{repo}/releases/latest",
        method=method,
        headers={"User-Agent": "defenseclaw-upgrade"},
    )
    location = ""
    try:
        with opener.open(request, timeout=timeout) as response:
            location = response.headers.get("Location", "")
    except urllib.error.HTTPError as exc:
        if exc.code in (301, 302, 303, 307, 308):
            location = exc.headers.get("Location", "")
    except (urllib.error.URLError, OSError):
        return None
    tag = location.rstrip("/").rsplit("/tag/", 1)[-1] if "/tag/" in location else ""
    tag = tag.removeprefix("v")
    return tag if _VERSION.match(tag) else None


def _latest_from_api(repo: str, timeout: float) -> str | None:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/releases/latest",
        headers={"User-Agent": "defenseclaw-upgrade", "Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_tls_context()) as response:  # noqa: S310
            tag = str(json.load(response).get("tag_name", "")).removeprefix("v")
    except (urllib.error.URLError, OSError, ValueError, AttributeError):
        return None
    return tag if _VERSION.match(tag) else None


def _latest_version(repo: str) -> str:
    return latest_version(repo)


def _local_version(local_dir: str) -> str:
    """Read the version stamped into a local installer (tests only)."""

    try:
        with open(os.path.join(local_dir, _installer_name()), encoding="utf-8") as stream:
            text = stream.read()
    except OSError as exc:
        raise ShimError(f"could not read the installer in {local_dir}: {exc}") from None
    match = re.search(r"""(?:DC_VERSION|\$DcVersion)\s*=\s*["']([0-9.]+)["']""", text)
    if not match or not _VERSION.match(match.group(1)):
        raise ShimError(f"the installer in {local_dir} is not stamped with a version")
    return match.group(1)


def _key(version: str) -> tuple[int, int, int]:
    match = _VERSION.match(version)
    if not match:
        return (0, 0, 0)
    return int(match.group(1)), int(match.group(2)), int(match.group(3))
