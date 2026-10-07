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
import http.client
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
# Deprecated alias of config.yaml update.source: a GitHub owner/name.
REPO_ENV = "DEFENSECLAW_REPO"
OFFICIAL_SOURCE = "https://github.com/" + DEFAULT_REPO
# The release signing identity is compiled in. update.source and
# DEFENSECLAW_REPO only change where release bytes are fetched from; a
# mirror serves the same signed checksums.txt and its bundle.
RELEASE_SIGNER = r"^https://github\.com/cisco-ai-defense/defenseclaw/\.github/workflows/release\.yaml@refs/heads/main$"
RELEASE_ISSUER = "https://token.actions.githubusercontent.com"
# Tests only: take the installer and checksums.txt from this directory and
# pass it to the installer as --local.
LOCAL_DIR_ENV = "DEFENSECLAW_UPGRADE_LOCAL_DIR"
_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_TIMEOUT = 30

RECOVER_CORRUPT_AUDIT_NOTE = (
    "  --recover-corrupt-audit is no longer needed: the gateway moves a corrupt audit store "
    "aside and starts a new one by itself (see defenseclaw doctor)."
)

USAGE = """Usage: defenseclaw upgrade [--version X.Y.Z] [--yes]
       defenseclaw rollback [--yes]

upgrade   Download and run the installer of the latest release (or X.Y.Z).
rollback  Restore the install that the last upgrade replaced.
"""


# A machine-wide managed (MDM-deployed) installation announces itself: on
# Linux and macOS with the runtime descriptor it publishes, on Windows with
# the HKLM marker its lifecycle registers. Either means the organization
# installs and updates DefenseClaw on this computer.
MANAGED_DESCRIPTORS = (
    "/etc/defenseclaw/managed-runtime.json",
    "/opt/cisco/defenseclaw/etc/managed-runtime.json",
)
WINDOWS_MANAGED_MARKER_KEY = r"SOFTWARE\Cisco\DefenseClaw\Enterprise"


class ShimError(RuntimeError):
    """A user-facing failure; nothing on the machine was changed."""

    exit_code = 1


class ShimUsageError(ShimError):
    """A bad option or argument: exit 2, like every other Click command."""

    exit_code = 2


def managed_deployment() -> str | None:
    """Name the machine-wide managed deployment on this host, or None.

    The one managed-host check for per-user upgrade and rollback: the
    runtime descriptor path on Linux and macOS, the registered profile on
    Windows.
    """

    if os.name == "nt":
        return _windows_managed_profile()
    return managed_descriptor()


def managed_lifecycle_command() -> str:
    """The managed package's lifecycle command prefix (``enterprise linux`` or
    ``enterprise macos``), or "" on Windows, where Setup is the lifecycle."""

    if os.name == "nt":
        return ""
    if sys.platform == "darwin":
        return "/opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise macos"
    return "/opt/defenseclaw/bin/defenseclaw-gateway enterprise linux"


def managed_descriptor() -> str | None:
    """Return the managed runtime descriptor on this Linux or macOS host, if any."""

    if os.name == "nt":
        return None
    for path in MANAGED_DESCRIPTORS:
        if os.path.isfile(path) and not os.path.islink(path):
            return path
    return None


def _windows_managed_profile() -> str | None:
    try:
        import winreg

        access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, WINDOWS_MANAGED_MARKER_KEY, 0, access) as key:
            try:
                value, _kind = winreg.QueryValueEx(key, "Profile")
            except OSError:
                value = ""
        return str(value) or "managed"
    except (ImportError, OSError):
        return None


def run(argv: list[str]) -> int:
    """Run ``upgrade`` or ``rollback`` with the arguments after the command."""

    command, args = argv[0], argv[1:]
    _tolerant_output()
    try:
        options = _parse(command, args)
        if options is None:
            print(USAGE, end="")
            return 0
        deployment = managed_deployment()
        if deployment:
            raise ShimError(
                f"this computer's DefenseClaw is managed by your organization ({deployment}); "
                "your IT department installs and updates it through the managed deployment channel"
            )
        if command == "rollback":
            return _rollback(yes=options["yes"])
        return _upgrade(options["version"], yes=options["yes"])
    except ShimError as exc:
        print(f"  ✗ {exc}", file=sys.stderr)
        print("    Nothing was changed.", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        return 130


def _tolerant_output() -> None:
    """Never fail on a character the console cannot encode (Windows cp1252)."""

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


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
        elif command == "upgrade" and arg == "--recover-corrupt-audit":
            # Hidden, kept for 0.8.x muscle memory and scripts: recovery is now automatic.
            print(RECOVER_CORRUPT_AUDIT_NOTE, file=sys.stderr)
        else:
            raise ShimUsageError(f"unknown option {arg!r} for 'defenseclaw {command}' (see --help)")
        index += 1
    version = options["version"]
    if version is not None:
        version = str(version).removeprefix("v")
        if not _VERSION.match(version):
            raise ShimUsageError(f"--version must look like 1.2.3, got {options['version']!r}")
        options["version"] = version
    return options


def release_source() -> str:
    """The base URL release bytes come from: config.yaml ``update.source``,
    else ``DEFENSECLAW_REPO`` (deprecated; a GitHub owner/name), else the
    official repository."""

    configured = _configured_update_source()
    if configured:
        return configured.rstrip("/")
    repo = os.environ.get(REPO_ENV, "").strip()
    if repo:
        return _source_url(repo)
    return OFFICIAL_SOURCE


def _source_url(source: str) -> str:
    """A base URL; a bare owner/name is a GitHub repository."""

    source = source.strip().rstrip("/")
    return source if source.startswith("https://") else f"https://github.com/{source}"


def _configured_update_source() -> str:
    try:
        import yaml

        home = os.path.expanduser(os.environ.get("DEFENSECLAW_HOME") or "~/.defenseclaw")
        config = os.environ.get("DEFENSECLAW_CONFIG", "").strip() or os.path.join(home, "config.yaml")
        with open(os.path.expanduser(config), encoding="utf-8") as stream:
            raw = yaml.safe_load(stream)
    except Exception:  # noqa: BLE001 - a missing or unreadable config keeps the official source
        return ""
    update = raw.get("update") if isinstance(raw, dict) else None
    source = str(update.get("source") or "").strip() if isinstance(update, dict) else ""
    return source if source.startswith("https://") else ""


def _upgrade(version: str | None, *, yes: bool) -> int:
    from defenseclaw import __version__ as installed

    repo = release_source()
    local_dir = os.environ.get(LOCAL_DIR_ENV)
    explicit = version is not None
    if version is None:
        version = _local_version(local_dir) if local_dir else _latest_version(repo)
    if not explicit and _key(version) <= _key(installed):
        # GAP-1801: a newest release older than this install (0.8.x before
        # 1.0 is published) is "nothing newer", not a refused downgrade.
        older = " is older" if _key(version) < _key(installed) else ""
        print(f"  ✓ DefenseClaw {installed} is up to date (latest release: {version}{older}). Nothing was changed.")
        print("    To install a specific 1.x release: defenseclaw upgrade --version X.Y.Z")
        return 0
    if _key(version) < (1, 0, 0):
        raise ShimError(f"DefenseClaw {installed} cannot install {version}; 1.x installs only 1.0.0 or later")

    print(f"  → Installing DefenseClaw {version} (installed: {installed})")
    workdir = tempfile.mkdtemp(prefix="defenseclaw-upgrade-")
    try:
        installer = _fetch_installer(repo, version, local_dir, workdir)
    except BaseException:
        shutil.rmtree(workdir, ignore_errors=True)
        raise
    extra = ["--local", local_dir] if local_dir else []
    return _run_installer(installer, (["--yes"] if yes else []) + extra, workdir)


def _data_home() -> str:
    """The data folder, normalized so Windows paths print with backslashes only (GAP-1842)."""
    return os.path.normpath(os.path.expanduser(os.environ.get("DEFENSECLAW_HOME") or "~/.defenseclaw"))


def _rollback(*, yes: bool) -> int:
    home = _data_home()
    name = _installer_name()
    installer = os.path.join(home, "installer", name)
    if not os.path.isfile(installer):
        # A source ('make all') install saves no installer. After a rollback to
        # one, the install it replaced (now in previous/) still has its own, and
        # that one rolls forward again (GAP-2459).
        installer = os.path.join(home, "previous", "installer", name)
    if not os.path.isfile(installer):
        saved = os.path.join(home, "installer")
        raise ShimError(
            f"no saved installer in {saved} or {os.path.join(home, 'previous', 'installer')}; "
            f"download {name} from the release you want and run it with --rollback"
        )
    previous = os.path.join(home, "previous")
    if os.name == "nt" and os.path.isdir(os.path.join(previous, "legacy-setup")):
        # install.ps1 refuses this rollback in its own window, which a terminal
        # without a desktop never sees; refuse here with the same way back.
        try:
            with open(os.path.join(previous, "VERSION"), encoding="utf-8-sig") as handle:
                back_to = handle.read().strip()
        except OSError:
            back_to = "0.8.x"
        raise ShimError(legacy_setup_rollback_refusal(back_to, previous, release_source()))
    workdir = tempfile.mkdtemp(prefix="defenseclaw-rollback-")
    copy = os.path.join(workdir, name)
    try:
        shutil.copyfile(installer, copy)
    except BaseException as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        if isinstance(exc, OSError):
            raise ShimError(f"could not copy the saved installer {installer}: {exc}") from None
        raise
    return _run_installer(copy, ["--rollback"] + (["--yes"] if yes else []), workdir)


def legacy_setup_rollback_refusal(back_to: str, previous: str, repo: str) -> str:
    """Why a rollback to DefenseClaw Setup (0.8.7-0.8.10) is manual, and how (install.ps1 says the same)."""
    return (
        f"The previous install is DefenseClaw Setup {back_to}, which cannot be restored automatically. "
        f"To go back to it, run 'defenseclaw uninstall', then download DefenseClawSetup-x64.exe from "
        f"{_source_url(repo)}/releases/tag/{back_to} and run it in your desktop session. "
        f"Its files and your data from before the upgrade are in {previous}"
    )


def _run_installer(path: str, args: list[str], workdir: str) -> int:
    # The installer downloads the release assets: hand it update.source
    # through its DEFENSECLAW_REPO input (an owner/name or an https base URL).
    configured = _configured_update_source()
    if configured:
        os.environ[REPO_ENV] = configured.rstrip("/")
    if os.name == "nt":
        # The running CLI holds files in .venv open; start the installer in its
        # own console and exit so it can replace them.
        powershell = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
        )
        ps_args = [_powershell_flag(arg) for arg in args]
        # A PowerShell 7 session puts its own module folders in PSModulePath.
        # Windows PowerShell 5.1 then cannot load its built-in modules (Get-Acl
        # fails), so let it build its default module path.
        env = {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
        if _windows_terminal_without_desktop():
            # An SSH session has no desktop: the new window never appears and
            # the result would only be in the install log (GAP-1993). Keep the
            # staged installer and give the command that runs it right here.
            command = " ".join(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", f'"{path}"', *ps_args]
            )
            raise ShimError(
                "this terminal has no desktop (SSH session), so the installer's window would not be "
                "visible here.\n"
                "    Run the installer in this terminal instead; it shows the result and sets the exit code:\n"
                f"      {command}"
            )
        try:
            subprocess.Popen(  # noqa: S603 - fixed interpreter and verified script
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path, *ps_args],
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
                cwd=workdir,
                env=env,
            )
        except OSError as exc:
            shutil.rmtree(workdir, ignore_errors=True)
            raise ShimError(f"could not start {powershell}: {exc}") from None
        home = _data_home()
        print("  → The installer continues in a new window, which shows the result when it ends.")
        print(f"    Its log is saved in {os.path.join(home, 'logs')} (install-<time>.log).")
        print("    Confirm the result afterwards with: defenseclaw --version")
        return 0
    bash = "/bin/bash" if os.path.exists("/bin/bash") else (shutil.which("bash") or "bash")
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        os.chdir(workdir)
        os.execv(bash, [bash, path, *args])
    except OSError as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        raise ShimError(f"could not run {bash}: {exc}") from None
    return 0  # pragma: no cover - execv does not return


def _windows_terminal_without_desktop() -> bool:
    """An OpenSSH session on Windows: a new console window is never shown there."""
    return any(os.environ.get(name) for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"))


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
        base = f"{_source_url(repo)}/releases/download/{version}"
        for asset, destination in ((name, installer), ("checksums.txt", checksums)):
            _download(f"{base}/{asset}", destination)
    _verify_release_signature(repo, version, local_dir, workdir, checksums)
    expected = _expected_sha256(checksums, name)
    with open(installer, "rb") as stream:
        actual = hashlib.sha256(stream.read()).hexdigest()
    if actual != expected:
        raise ShimError(f"{name} for {version} does not match checksums.txt")
    _check_installer_version(installer, version)
    return installer


_STAMPED_VERSION = re.compile(r'^(?:(?:readonly )?DC_VERSION=|\$DcVersion = )"([^"]*)"\s*$', re.MULTILINE)


def _check_installer_version(installer: str, version: str) -> None:
    """Refuse an installer stamped with another release than *version*.

    Every release is signed by the same identity, so a verified signature
    alone would let a mirror (update.source) serve an older release under the
    requested version. An unstamped copy (a local test build) is accepted.
    """

    with open(installer, encoding="utf-8", errors="replace") as stream:
        match = _STAMPED_VERSION.search(stream.read())
    stamped = match.group(1) if match else ""
    if not stamped or stamped == "__DEFENSECLAW_VERSION__":
        return
    if stamped.lstrip("v") != version.lstrip("v"):
        raise ShimError(f"the installer served for {version} is release {stamped}; refusing a mismatched release")


def _cosign() -> str | None:
    """cosign 2.0 or later on PATH, or ``None``."""

    path = shutil.which("cosign")
    if not path:
        return None
    try:
        output = subprocess.run(  # noqa: S603 - fixed arguments
            [path, "version"], capture_output=True, text=True, timeout=_TIMEOUT, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"GitVersion:\s*v?(\d+)\.", output)
    return path if match and int(match.group(1)) >= 2 else None


def _verify_release_signature(repo: str, version: str, local_dir: str | None, workdir: str, checksums: str) -> None:
    """With cosign installed, check checksums.txt's release signature before trusting it.

    The installers check the same signature, but only once they are running;
    this covers the installer itself. Every published release carries
    ``checksums.txt.bundle``; a local directory without one is a test build.
    """

    cosign = _cosign()
    if cosign is None:
        if local_dir:
            return
        if _source_url(repo) != OFFICIAL_SOURCE:
            # checksums.txt from a mirror proves nothing without its signature.
            raise ShimError(
                f"releases from {_source_url(repo)} are verified by their signature: install cosign 2.0 or later, "
                "or clear update.source (and DEFENSECLAW_REPO) to use the official releases"
            )
        print("  ! cosign 2.0 or later is not installed; the installer is checked against checksums.txt only")
        return
    bundle = os.path.join(workdir, "checksums.txt.bundle")
    if local_dir:
        source = os.path.join(local_dir, "checksums.txt.bundle")
        if not os.path.isfile(source):
            return
        shutil.copyfile(source, bundle)
    else:
        _download(f"{_source_url(repo)}/releases/download/{version}/checksums.txt.bundle", bundle)
    try:
        result = subprocess.run(  # noqa: S603 - fixed verifier, arguments built from constants and paths
            [
                cosign,
                "verify-blob",
                "--bundle",
                bundle,
                "--certificate-identity-regexp",
                RELEASE_SIGNER,
                "--certificate-oidc-issuer",
                RELEASE_ISSUER,
                checksums,
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ShimError(f"could not run cosign to verify release {version}: {exc}") from None
    finally:
        # The installer removes its launch dir only when it holds nothing else.
        try:
            os.remove(bundle)
        except OSError:
            pass
    if result.returncode != 0:
        raise ShimError(f"the release signature on checksums.txt for {version} did not verify")


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
    except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
        raise ShimError(f"could not download {url}: {exc}") from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802 - stdlib signature
        return None


def latest_version(repo: str | None = None, *, timeout: float = _TIMEOUT) -> str:
    """Return the tag GitHub marks as the latest release.

    Reads the ``releases/latest`` redirect (no API rate limit), falling back
    to a GET of the same page and then to the REST API.
    """

    repo = repo or release_source()
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
        f"{_source_url(repo)}/releases/latest",
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
    except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError):
        return None
    tag = location.rstrip("/").rsplit("/tag/", 1)[-1] if "/tag/" in location else ""
    tag = tag.removeprefix("v")
    return tag if _VERSION.match(tag) else None


def _latest_from_api(repo: str, timeout: float) -> str | None:
    source = _source_url(repo)
    if not source.startswith("https://github.com/"):
        return None
    request = urllib.request.Request(
        f"https://api.github.com/repos/{source.removeprefix('https://github.com/')}/releases/latest",
        headers={"User-Agent": "defenseclaw-upgrade", "Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_tls_context()) as response:  # noqa: S310
            tag = str(json.load(response).get("tag_name", "")).removeprefix("v")
    except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError, AttributeError):
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
