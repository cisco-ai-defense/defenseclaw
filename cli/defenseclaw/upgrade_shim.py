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
in the installer. Windows downgrades first run the saved current installer,
whose recovery checks must run before an older installer takes over.

Standard library only, and imported before the rest of the CLI, so it keeps
working when anything else in the installed version is broken.

A downgrade is the one case the older release's installer cannot handle on
its own: it refuses a config.yaml that sets a key it does not have. So this
shim sets aside the keys of ``NEWER_CONFIG_KEYS`` the older release lacks
(``SET_ASIDE_FILE`` in the data folder) before it runs that installer, and
``defenseclaw migrate`` of a release that has them puts them back.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

DEFAULT_REPO = "cisco-ai-defense/defenseclaw"
# Deprecated alias of config.yaml update.source: a GitHub owner/name.
REPO_ENV = "DEFENSECLAW_REPO"
# DEFENSECLAW_REPO is a GitHub owner/name or an https:// mirror base URL. Any
# other value (an http:// URL, a path) used to be appended to github.com and
# ended in an HTTP 404 (GAP-1065). The value is never echoed: a mirror URL can
# carry credentials.
_VALID_REPO_ENV = re.compile(r"^(https://\S+|[^\s/:@]+/[^\s/:@]+)$")
REPO_ENV_REFUSAL = (
    f"{REPO_ENV} must be a GitHub owner/name or an https:// mirror URL (an http:// URL is not accepted). "
    f"Fix or unset {REPO_ENV}, or set update.source to an https:// URL"
)
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
# Configuration keys added after 1.0.2, with the first release that has each.
# The installer of an older release refuses a config.yaml that sets one
# ("unknown field", GAP-0137), so a downgrade sets them aside first.
# guardrail.chains and connectors (connectors.agent_gateway) are set aside
# whole: an older release refuses the block itself, so taking only the inner
# key out would leave an empty block behind.
NEWER_CONFIG_KEYS = (
    ("openshell.trusted_ca_bundle", (1, 0, 3)),
    ("guardrail.internal_domains", (1, 0, 6)),
    ("guardrail.chains", (1, 0, 6)),
    ("connectors", (1, 0, 6)),
)
# Where a downgrade keeps the keys it set aside, in the data folder:
# {"version": 1, "for": "<older release>", "keys": {"<dotted key>": value}}.
SET_ASIDE_FILE = "config-set-aside.json"
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


# The glyphs these status lines start with, and what shows instead where a
# stream cannot show them.
_ASCII_GLYPHS = str.maketrans({"✓": "OK", "✗": "x", "→": "->", "—": "-", "…": "..."})


class _AsciiGlyphs:
    """A text stream that writes the status glyphs in ASCII."""

    def __init__(self, stream) -> None:
        self._stream = stream

    def write(self, text):
        return self._stream.write(text.translate(_ASCII_GLYPHS) if isinstance(text, str) else text)

    def __getattr__(self, name):
        return getattr(self._stream, name)


def _shows_glyphs(stream) -> bool:
    """Whether *stream* can show the status glyphs.

    PowerShell decodes the piped output of a native command with the console
    code page, and Python writes a redirected stream in the ANSI code page,
    so on Windows only a console shows them; elsewhere the stream's encoding
    must have them.
    """

    try:
        if os.name == "nt" and not stream.isatty():
            return False
        "✓✗→".encode(stream.encoding or "ascii")
    except (AttributeError, LookupError, UnicodeEncodeError, ValueError, OSError):
        return False
    return True


def _tolerant_output() -> None:
    """Never fail on a character the console cannot encode (Windows cp1252).

    Where a stream cannot show the status glyphs they are written in ASCII:
    replacing them printed a "?" at the start of the upgrade and rollback
    lines in PowerShell 7 (GAP-0002).
    """

    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
        if stream is not None and not isinstance(stream, _AsciiGlyphs) and not _shows_glyphs(stream):
            setattr(sys, name, _AsciiGlyphs(stream))


_VERSION_NEEDS_VALUE = "--version needs a release number, for example: defenseclaw upgrade --version 1.2.3"


def _parse(command: str, args: list[str]) -> dict[str, object] | None:
    options: dict[str, object] = {"version": None, "yes": False}
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("-h", "--help"):
            return None
        if arg in ("-y", "--yes"):
            options["yes"] = True
        elif command == "upgrade" and arg == "--version":
            # A missing value is not an unknown option (GAP-2258): the flag is
            # valid, so say what it needs. "--version --yes" is the same mistake.
            if index + 1 >= len(args) or args[index + 1].startswith("-"):
                raise ShimUsageError(_VERSION_NEEDS_VALUE)
            index += 1
            options["version"] = args[index]
        elif command == "upgrade" and arg.startswith("--version="):
            options["version"] = arg.split("=", 1)[1]
            if not options["version"]:
                raise ShimUsageError(_VERSION_NEEDS_VALUE)
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
        if not _VALID_REPO_ENV.match(repo):
            raise ShimUsageError(REPO_ENV_REFUSAL)
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
    if _key(version) < _key(installed):
        _refuse_unguarding_downgrade(version)

    print(f"  → Installing DefenseClaw {version} (installed: {installed})")
    workdir = tempfile.mkdtemp(prefix="defenseclaw-upgrade-")
    extra = ["--local", local_dir] if local_dir else []
    try:
        if os.name == "nt" and _key(version) < _key(installed):
            # Older installers cannot read current recovery receipts. Let this
            # install's controller quiesce the gateway and check them before
            # it delegates to the verified installer of the requested release.
            saved = os.path.join(_data_home(), "installer", "install.ps1")
            installer = os.path.join(workdir, "install.ps1")
            try:
                _copy_windows_saved_installer(saved, installer)
                _check_saved_installer(installer, saved, _data_home(), installed)
                _check_installer_version(installer, installed)
            except (OSError, ShimError) as exc:
                raise ShimError(
                    f"cannot safely use the current saved installer {saved}: {exc}. "
                    f"Repair DefenseClaw {installed} with its installer before retrying this downgrade"
                ) from None
            extra = ["--version", version, *extra]
        else:
            installer = _fetch_installer(repo, version, local_dir, workdir)
    except BaseException:
        shutil.rmtree(workdir, ignore_errors=True)
        raise
    if _key(version) < _key(installed):
        try:
            _set_aside_newer_keys(version)
        except BaseException:
            shutil.rmtree(workdir, ignore_errors=True)
            raise
    # Only a downgrade to a release that keeps the newer hook helper waits
    # for its installer and drops the helper (rel-1-0-4:GAP-2503).
    newer = installed if _key(version) < min(_key(installed), HOOK_HELPER_KEPT_BEFORE) else None
    return _run_installer(installer, (["--yes"] if yes else []) + extra, workdir, newer=newer)


def _refuse_unguarding_downgrade(version: str) -> None:
    """Stop a downgrade to a release that cannot guard an agent set up here.

    ``defenseclaw rollback`` runs the same check (``migrate
    --check-rollback-to``); a downgrade runs the older release's installer,
    which has none, so this install checks before anything changes
    (rel-1-0-6 GAP-0128: OpenCode V2 under 1.0.5 ran unguarded). The check
    belongs to the rest of the CLI: when that cannot load, the downgrade goes
    on as before, since it may be the way out of a broken install.
    """

    try:
        from defenseclaw.migrations import MigrationError, check_opencode_rollback
    except Exception:  # noqa: BLE001 - a broken CLI must not block the way back
        return
    try:
        check_opencode_rollback(_data_home(), version, downgrade=True)
    except MigrationError as exc:
        raise ShimError(str(exc)) from None


def _active_config_path() -> str:
    override = os.environ.get("DEFENSECLAW_CONFIG", "").strip()
    return os.path.expanduser(override) if override else os.path.join(_data_home(), "config.yaml")


def _set_aside_newer_keys(version: str) -> None:
    """Take the keys DefenseClaw ``version`` does not have out of config.yaml.

    Its installer would refuse the configuration ("unknown field", GAP-0137).
    The values go to ``SET_ASIDE_FILE`` first, then one validated write
    removes the keys; ``defenseclaw migrate`` of a release that has them
    puts them back. When the keys cannot be set aside, the upgrade stops
    with the command that removes them, and nothing is changed.
    """

    target = _key(version)
    config = _active_config_path()
    try:
        import yaml

        with open(config, encoding="utf-8") as stream:
            raw = yaml.safe_load(stream)
    except Exception:  # noqa: BLE001 - no config or one that does not parse: the installer's check names it
        return
    found: dict[str, object] = {}
    for dotted, since in NEWER_CONFIG_KEYS:
        if target >= since:
            continue
        node: object = raw
        for part in dotted.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        if node not in (None, ""):
            found[dotted] = node
    if not found:
        return
    names = ", ".join(found)
    stop = (
        f"DefenseClaw {version} does not have {names}, so its installer would refuse config.yaml; "
        f"remove it with 'defenseclaw config unset {' '.join(found)}' and run the upgrade again"
    )
    held = os.path.join(_data_home(), SET_ASIDE_FILE)
    try:
        from defenseclaw.config_writer import ACTOR_MIGRATION, Change, apply
    except Exception as exc:  # noqa: BLE001 - a broken install: say what to remove by hand
        raise ShimError(f"{stop} (the keys could not be set aside: {exc})") from None
    previous: bytes | None = None
    try:
        with open(held, "rb") as stream:
            previous = stream.read()
        kept = json.loads(previous.decode("utf-8")).get("keys")
    except FileNotFoundError:
        kept = None
    except (OSError, ValueError, AttributeError):
        kept = None
    keys = dict(kept) if isinstance(kept, dict) else {}
    keys.update(found)
    try:
        _write_private_json(held, {"version": 1, "for": version, "keys": keys})
    except OSError as exc:
        raise ShimError(f"{stop} (could not write {held}: {exc})") from None
    try:
        apply(
            [Change(key, unset=True) for key in found],
            ACTOR_MIGRATION,
            f"set aside for the downgrade to {version}",
            path=config,
        )
    except Exception as exc:  # noqa: BLE001 - config.yaml is unchanged; so is the record
        try:
            if previous is None:
                os.remove(held)
            else:
                _write_private_bytes(held, previous)
        except OSError:
            pass
        raise ShimError(f"{stop} (the keys could not be set aside: {exc})") from None
    print(f"  → DefenseClaw {version} does not have {names}: set aside in {held}.")
    print(
        "    Installing a release that has it puts it back. If the installer stops, "
        "or after a rollback, put it back with: defenseclaw migrate"
    )


def _write_private_json(path: str, document: dict[str, object]) -> None:
    _write_private_bytes(path, (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def _write_private_bytes(path: str, data: bytes) -> None:
    """Write ``path`` owner-only and atomically."""

    fd, tmp = tempfile.mkstemp(prefix=".config-set-aside.", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _data_home() -> str:
    """The data folder, normalized so Windows paths print with backslashes only (GAP-1842)."""
    return os.path.normpath(os.path.expanduser(os.environ.get("DEFENSECLAW_HOME") or "~/.defenseclaw"))


def _windows_regular_file_info(path: str) -> os.stat_result:
    """Validate the saved controller's locator without accepting reparse aliases."""
    path = os.path.abspath(path)
    ancestors = []
    parent = os.path.dirname(path)
    while True:
        ancestors.append(parent)
        above = os.path.dirname(parent)
        if above == parent:
            break
        parent = above
    for entry in [*reversed(ancestors), path]:
        info = os.lstat(entry)
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise OSError(f"saved installer path contains a reparse point: {entry}")
        expected_type = stat.S_ISREG if entry == path else stat.S_ISDIR
        if not expected_type(info.st_mode):
            raise OSError(f"saved installer path has an unexpected file type: {entry}")
    return info


def _read_windows_regular_file(path: str, limit: int) -> bytes:
    before = _windows_regular_file_info(path)
    if before.st_size > limit:
        raise OSError(f"saved installer metadata exceeds its size limit: {path}")
    with open(path, "rb") as source:
        opened = os.fstat(source.fileno())
        body = source.read(limit + 1)
        after = os.fstat(source.fileno())
    named = _windows_regular_file_info(path)
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
    witness = tuple(getattr(before, field) for field in fields)
    # On Windows Python can expose creation time through lstat's st_ctime
    # and change time through fstat's. Compare each source with itself.
    if (
        len(body) != before.st_size
        or before.st_ctime_ns != named.st_ctime_ns
        or opened.st_ctime_ns != after.st_ctime_ns
        or any(tuple(getattr(info, field) for field in fields) != witness for info in (opened, after, named))
    ):
        raise OSError(f"saved installer changed while being copied: {path}")
    return body


def _copy_windows_saved_installer(source: str, destination: str) -> None:
    body = _read_windows_regular_file(source, 4 * 1024 * 1024)
    with open(destination, "xb") as target:
        target.write(body)


def _rollback(*, yes: bool) -> int:
    from defenseclaw import __version__ as installed

    home = _data_home()
    name = _installer_name()
    installer = os.path.join(home, "installer", name)
    if os.name == "nt":
        try:
            _windows_regular_file_info(installer)
            use_previous = False
        except FileNotFoundError:
            use_previous = True
        except OSError as exc:
            raise ShimError(
                f"cannot safely use the current saved installer {installer}: {exc}. "
                "Repair the current DefenseClaw install before retrying rollback"
            ) from None
    else:
        use_previous = not os.path.isfile(installer)
    if use_previous:
        # A source ('make all') install saves no installer. After a rollback to
        # one, the install it replaced (now in previous/) still has its own, and
        # that one rolls forward again (GAP-2459).
        installer = os.path.join(home, "previous", "installer", name)
        if os.name == "nt":
            try:
                back_to = (
                    _read_windows_regular_file(os.path.join(home, "previous", "VERSION"), 128)
                    .decode("utf-8-sig")
                    .strip()
                )
            except (OSError, UnicodeError):
                back_to = ""
            if not _VERSION.fullmatch(back_to) or _key(back_to) < _key(installed):
                raise ShimError(
                    "the current saved Windows installer is missing, and the previous install cannot safely control "
                    "this rollback. Repair the current DefenseClaw install before retrying rollback"
                )
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
        if os.name == "nt":
            _copy_windows_saved_installer(installer, copy)
            _check_installer_version(copy, back_to if use_previous else installed)
        else:
            shutil.copyfile(installer, copy)
    except BaseException as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        if isinstance(exc, (OSError, ShimError)):
            hint = ". Repair the current DefenseClaw install before retrying rollback" if os.name == "nt" else ""
            raise ShimError(f"could not copy the saved installer {installer}: {exc}{hint}") from None
        raise
    try:
        # until 1.1: an installer that 1.0.3 or older saved in previous/ has
        # no digest record; one a later release saved is checked.
        if use_previous:
            _check_saved_installer(copy, installer, os.path.join(previous, "data"), None)
        else:
            _check_saved_installer(copy, installer, home, installed)
    except BaseException:
        shutil.rmtree(workdir, ignore_errors=True)
        raise
    return _run_installer(copy, ["--rollback"] + (["--yes"] if yes else []), workdir)


INSTALLER_RECORD = os.path.join("receipts", "installer.sha256")


def _check_saved_installer(copy: str, saved: str, data_dir: str, reinstall: str | None) -> None:
    """Refuse a saved installer whose bytes are not the ones its install saved (GAP-1067).

    The installer records the SHA-256 of the copy it saves in
    ``<data>/receipts/installer.sha256`` (record_saved_installer,
    Save-InstallerDigest), and every swap moves that record with the install
    it belongs to. *copy* is the file that will run, already copied out of
    *saved*, so a change after this check cannot reach it. *reinstall* is the
    release whose installer saves a verified copy again; ``None`` accepts a
    missing record (an installer saved by 1.0.3 or older).
    """

    record = os.path.join(data_dir, INSTALLER_RECORD)
    again = (
        f"Save a verified copy again with: defenseclaw upgrade --version {reinstall} --yes, then run this command again"
        if reinstall
        else f"download {_installer_name()} from the release you want and run it with --rollback"
    )
    try:
        if os.name == "nt":
            raw = _read_windows_regular_file(record, 256)
        else:
            with open(record, "rb") as handle:
                raw = handle.read(257)
    except FileNotFoundError:
        if reinstall is None:
            return
        raise ShimError(
            f"there is no record of the installer DefenseClaw saved in {saved} ({record} is missing), "
            f"so it is not run; nothing was changed. {again}"
        ) from None
    except OSError as exc:
        raise ShimError(
            f"could not read the record of the saved installer {record}: {exc}; nothing was changed. {again}"
        ) from None
    fields = raw.decode("ascii", errors="replace").split()
    expected = fields[0].lower() if len(raw) <= 256 and len(fields) == 2 and fields[1] == _installer_name() else ""
    with open(copy, "rb") as stream:
        actual = hashlib.sha256(stream.read()).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or actual != expected:
        raise ShimError(
            f"the saved installer {saved} is not the one DefenseClaw saved (its SHA-256 is {actual}; {record} "
            f"records {expected or 'no valid digest'}): it was changed after the install, so it is not run; "
            f"nothing was changed. {again}"
        )


def legacy_setup_rollback_refusal(back_to: str, previous: str, repo: str) -> str:
    """Why a rollback to DefenseClaw Setup (0.8.7-0.8.10) is manual, and how (install.ps1 says the same)."""
    return (
        f"The previous install is DefenseClaw Setup {back_to}, which cannot be restored automatically. "
        f"To go back to it, run 'defenseclaw uninstall', then download DefenseClawSetup-x64.exe from "
        f"{_source_url(repo)}/releases/tag/{back_to} and run it in your desktop session. "
        f"Its files and your data from before the upgrade are in {previous}"
    )


def _run_installer(path: str, args: list[str], workdir: str, *, newer: str | None = None) -> int:
    # The installer downloads the release assets: hand it update.source
    # through its DEFENSECLAW_REPO input (an owner/name or an https base URL).
    configured = _configured_update_source()
    if configured:
        os.environ[REPO_ENV] = configured.rstrip("/")
    # until 1.1: older OmniGent setups may select their config relative to
    # the caller's directory. Bind these paths before the installer handoff.
    for name in ("OMNIGENT_CONFIG_HOME", "OMNIGENT_CONFIG"):
        value = os.environ.get(name, "")
        if value and not os.path.isabs(value):
            os.environ[name] = os.path.abspath(os.path.expanduser(value))
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
    if newer:
        # A downgrade from newer: the older installer keeps the hook helper of
        # this release, so the shim waits for it (rel-1-0-4:GAP-2503).
        rc = _wait_for_installer([bash, path, *args])
        shutil.rmtree(workdir, ignore_errors=True)
        if rc == 0:
            _drop_newer_hook_helper(newer)
        return rc
    try:
        # path is absolute; keep the caller's directory for relative vendor
        # paths handed to an installer from an older release.
        os.execv(bash, [bash, path, *args])
    except OSError as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        raise ShimError(f"could not run {bash}: {exc}") from None
    return 0  # pragma: no cover - execv does not return


def _wait_for_installer(argv: list[str]) -> int:
    try:
        proc = subprocess.Popen(argv)  # noqa: S603 - fixed interpreter and verified script
    except OSError as exc:
        raise ShimError(f"could not run {argv[0]}: {exc}") from None
    while True:
        try:
            return proc.wait()
        except KeyboardInterrupt:
            # The installer gets the same Ctrl-C and finishes or undoes its swap.
            continue


HOOK_HELPER = os.path.join("hooks", "_hardening.sh")
# A gateway of 1.0.4 or older keeps the newer hooks/_hardening.sh. 1.0.5 and
# later ship the same helper (schema v10), and a gateway with only plugin
# connectors (OpenCode) set up never writes one: once the shim dropped it,
# that gateway refused to start (rel-1-0-6:GAP-0047). A release that changes
# the helper's schema line must revisit this floor and install.sh's.
HOOK_HELPER_KEPT_BEFORE = (1, 0, 5)
_HOOK_HELPER_MAX_BYTES = 4 << 20


def _drop_newer_hook_helper(newer: str) -> None:
    """After a downgrade from ``newer``, let the older gateway write its own hook helper.

    A gateway of 1.0.4 or older keeps a hooks/_hardening.sh whose schema line
    is newer than its own, and the helper of a newer release runs native
    commands the older binaries do not have: after ``defenseclaw upgrade
    --version 1.0.2`` every hook call was refused as "the gateway is running
    but did not answer" until the helper was removed and the gateway restarted
    (rel-1-0-4:GAP-2503). The helper goes only when it is byte for byte the one
    the replaced install (previous/, ``newer``) has. Until 1.1: remove with the
    1.0.2, 1.0.3 and 1.0.4 downgrade paths.
    """
    home = _data_home()
    live = os.path.join(home, HOOK_HELPER)
    left = os.path.join(home, "previous", "data", HOOK_HELPER)
    try:
        with open(os.path.join(home, "previous", "VERSION"), encoding="utf-8") as handle:
            if handle.read(64).strip() != newer:
                return
        if not all(stat.S_ISREG(os.lstat(path).st_mode) for path in (live, left)):
            return
        with open(live, "rb") as mine, open(left, "rb") as theirs:
            if mine.read(_HOOK_HELPER_MAX_BYTES + 1) != theirs.read(_HOOK_HELPER_MAX_BYTES + 1):
                return
        os.unlink(live)
    except OSError:
        return
    gateway = os.path.join(os.path.expanduser("~"), ".local", "bin", "defenseclaw-gateway")
    print(f"  → Removed the hook helper of DefenseClaw {newer}; the gateway writes its own when it starts")
    if not _gateway_running(home):
        return
    try:
        rc = subprocess.call([gateway, "restart"])  # noqa: S603 - the installed gateway
    except OSError:
        rc = 1
    if rc != 0:
        print("  ! The gateway did not restart; hook calls are refused until it does. Run: defenseclaw-gateway restart")


def _gateway_running(home: str) -> bool:
    try:
        with open(os.path.join(home, "gateway.pid"), encoding="utf-8") as handle:
            text = handle.read(4096).strip()
        pid = json.loads(text).get("pid") if text.startswith("{") else int(text)
        if not isinstance(pid, int) or pid <= 0:
            return False
        os.kill(pid, 0)
    except (OSError, ValueError, AttributeError):
        return False
    return True


def _windows_terminal_without_desktop() -> bool:
    """An OpenSSH session on Windows: a new console window is never shown there."""
    return any(os.environ.get(name) for name in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"))


def _powershell_flag(arg: str) -> str:
    return {"--yes": "-Yes", "--rollback": "-Rollback", "--local": "-Local", "--version": "-Version"}.get(arg, arg)


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
    _check_installer_version(installer, version, test_build=bool(local_dir))
    return installer


_STAMPED_VERSION = re.compile(r'^(?:(?:readonly )?DC_VERSION=|\$DcVersion = )"([^"]*)"\s*$', re.MULTILINE)


def _check_installer_version(installer: str, version: str, *, test_build: bool = False) -> None:
    """Refuse an installer stamped with another release than *version*.

    Every release is signed by the same identity, so a verified signature
    alone would let a mirror (update.source) serve an older release under the
    requested version. A downloaded installer must carry the stamp, as in the
    bash and PowerShell upgraders; only a local test build (``--local``) may
    be unstamped.
    """

    with open(installer, encoding="utf-8", errors="replace") as stream:
        match = _STAMPED_VERSION.search(stream.read())
    stamped = match.group(1) if match else ""
    if test_build and (not stamped or stamped == "__DEFENSECLAW_VERSION__"):
        return
    if stamped.lstrip("v") != version.lstrip("v"):
        raise ShimError(
            f"the installer served for {version} is release {stamped or 'unknown'}; refusing a mismatched release"
        )


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
