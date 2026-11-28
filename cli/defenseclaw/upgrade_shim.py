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
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from defenseclaw.guardrail_profiles import ProfileRefreshResult

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
# Every key the schema has and the previous release's schema lacks is listed
# (test_every_key_new_since_1_0_9_is_set_aside_on_a_downgrade); 1.0.9 refuses
# each 1.0.10 key below, at gateway start and on every config write.
# A key inside a list item or a map value is named with [] (every item of
# the list) or * (every value of the map), for example routing.models[].bedrock
# and guardrail.profiles.*.routing; the set-aside names each concrete key
# (routing.models[0].bedrock) and the name of the item it came from, so
# migrate puts it back only on that item (rel-1-0-10:GAP-0644).
NEWER_CONFIG_KEYS = (
    ("openshell.trusted_ca_bundle", (1, 0, 3)),
    # The sandbox vault block (openshell.vault, with auto_capture) is new in 1.0.11.
    ("openshell.vault", (1, 0, 11)),
    ("guardrail.internal_domains", (1, 0, 6)),
    ("guardrail.chains", (1, 0, 6)),
    ("connectors", (1, 0, 6)),
    ("connectors.openclaw", (1, 0, 10)),
    ("guardrail.cascade", (1, 0, 10)),
    ("guardrail.secret_flow", (1, 0, 10)),
    ("guardrail.effects_rules_tier", (1, 0, 10)),
    ("guardrail.judge.intent_scope", (1, 0, 10)),
    ("decision_model.block_risk_score", (1, 0, 10)),
    ("decision_model.escalate_rule_flagged", (1, 0, 10)),
    ("decision_model.flow_guard", (1, 0, 10)),
    ("decision_model.history_tool_results", (1, 0, 10)),
    ("decision_model.history_turns", (1, 0, 10)),
    ("decision_model.protocol", (1, 0, 10)),
    ("guardrail.profiles.*.routing", (1, 0, 10)),
    ("observability.local.keep_rejected_records", (1, 0, 10)),
    ("observability.local.rejected_records_max_rows", (1, 0, 10)),
    ("observability.pricing", (1, 0, 10)),
    ("observability.tokenomics", (1, 0, 10)),
    ("routing.admin", (1, 0, 10)),
    ("routing.allow_user_override", (1, 0, 10)),
    ("routing.categories", (1, 0, 10)),
    ("routing.classifier", (1, 0, 10)),
    ("routing.context", (1, 0, 10)),
    ("routing.default_alias", (1, 0, 10)),
    ("routing.min_confidence", (1, 0, 10)),
    ("routing.models[].apis", (1, 0, 10)),
    ("routing.models[].bedrock", (1, 0, 10)),
    ("routing.models[].credential", (1, 0, 10)),
    ("routing.on_classifier_error", (1, 0, 10)),
    ("routing.route_only", (1, 0, 10)),
    ("routing.sensitive", (1, 0, 10)),
    ("routing.systemone", (1, 0, 10)),
    ("guardrail.history_seen_max", (1, 0, 10)),
    ("guardrail.max_body_values", (1, 0, 10)),
    ("openshell.admin.actor_secrets", (1, 0, 10)),
    ("openshell.admin.ask_hosts", (1, 0, 10)),
    ("openshell.admin.ask_timeout", (1, 0, 10)),
    ("openshell.admin.idle_suspend_after", (1, 0, 10)),
    ("openshell.admin.idle_suspend_tasks", (1, 0, 10)),
    ("openshell.admin.runtimes", (1, 0, 10)),
    ("openshell.admin.sandbox_class", (1, 0, 10)),
    ("openshell.admin.unattended_asks", (1, 0, 10)),
    ("openshell.admin.git_push", (1, 0, 11)),
    ("openshell.admin.url_rules", (1, 0, 10)),
    ("substrate", (1, 0, 10)),
    ("enterprise.openshell.allow_downgrade", (1, 0, 11)),
    ("ai_discovery.include_skill_content_hashes", (1, 0, 11)),
    ("ai_discovery.include_skill_manifests", (1, 0, 11)),
    ("guardrail.include_hook_event_content", (1, 0, 11)),
    ("notifications.substrate", (1, 0, 11)),
    # Under substrate (1.0.10), so a downgrade to 1.0.10 kept it (GAP-2035).
    ("substrate.bundles.oci", (1, 0, 11)),
    # The same: 1.0.10 has substrate and refuses these (fold of the skill scan,
    # sign-in and spend/usage units; test_every_key_new_since_1_0_10 lists them).
    ("substrate.identity.kube_sign_in", (1, 0, 11)),
    ("substrate.skills", (1, 0, 11)),
    ("substrate.usage", (1, 0, 11)),
    # The same: 1.0.10 has substrate, substrate.admin, .egress and .identity, all
    # closed, and refuses these 1.0.11 blocks under them (GAP-1066).
    ("substrate.activity", (1, 0, 11)),
    ("substrate.admin.git_push", (1, 0, 11)),
    ("substrate.egress.no_swap_hosts", (1, 0, 11)),
    ("substrate.extproc.rate_limits", (1, 0, 11)),
    ("substrate.files", (1, 0, 11)),
    ("substrate.git", (1, 0, 11)),
    ("substrate.identity.revocation", (1, 0, 11)),
    ("substrate.interactive", (1, 0, 11)),
    ("substrate.launcher", (1, 0, 11)),
    ("substrate.relay_cert_reissue", (1, 0, 11)),
    ("substrate.relay_tls", (1, 0, 11)),
    ("substrate.secret_templates", (1, 0, 11)),
    ("substrate.self_service_secrets", (1, 0, 11)),
)
# More keys added after 1.0.9, in the same path language: a "*" segment is
# one entry of a map of named entries (a connector, a profile). 1.0.9
# refuses a cascade block under any scope, as it refuses guardrail.cascade
# itself (GAP-0544, GAP-0583); a downgrade sets each entry's block aside
# under its own dotted key. (The System One decision_model keys and the
# profile routing block are in NEWER_CONFIG_KEYS.)
NEWER_CONFIG_SUBTREES = (
    ("guardrail.connectors.*.cascade", (1, 0, 10)),
    ("guardrail.profiles.*.cascade", (1, 0, 10)),
    ("guardrail.profiles.*.connectors.*.cascade", (1, 0, 10)),
    ("application_protection.guardrail.cascade", (1, 0, 10)),
    ("application_protection.connectors.*.guardrail.cascade", (1, 0, 10)),
    # A profile's sandbox keys past 1.0.9 are feat/substrate's (the
    # openshell.admin twins in NEWER_CONFIG_KEYS).
    ("guardrail.profiles.*.sandbox.actor_secrets", (1, 0, 10)),
    ("guardrail.profiles.*.sandbox.ask_hosts", (1, 0, 10)),
    ("guardrail.profiles.*.sandbox.ask_timeout", (1, 0, 10)),
    ("guardrail.profiles.*.sandbox.git_push", (1, 0, 11)),
    ("guardrail.profiles.*.sandbox.idle_suspend_after", (1, 0, 10)),
    ("guardrail.profiles.*.sandbox.idle_suspend_tasks", (1, 0, 10)),
    ("guardrail.profiles.*.sandbox.runtimes", (1, 0, 10)),
    ("guardrail.profiles.*.sandbox.sandbox_class", (1, 0, 10)),
    ("guardrail.profiles.*.sandbox.unattended_asks", (1, 0, 10)),
    ("guardrail.profiles.*.sandbox.url_rules", (1, 0, 10)),
)
# Values an older release refuses or cannot run, under keys it has
# (rel-1-0-10:GAP-0767, GAP-0769), with the first release that has them:
# - a routing.decisions item with a condition type other than these (1.0.10
#   adds connector, api_family and request): the whole decision is set aside
#   (by its name and place) and migrate puts it back where it was;
# - routing.enabled true with routing.classifier rules or systemone: the
#   classifier is set aside (NEWER_CONFIG_KEYS), so the older release would
#   start the vLLM Semantic Router, which needs Docker; routing is switched
#   off for it and migrate switches it back on.
OLDER_DECISION_CONDITION_TYPES = ("keyword",)
NEWER_DECISION_CONDITIONS_SINCE = (1, 0, 10)
IN_PROCESS_CLASSIFIERS = ("rules", "systemone")
IN_PROCESS_CLASSIFIERS_SINCE = (1, 0, 10)
# Keys inside a list item an older release refuses where setting the key aside alone would
# change what the item means, with the first release that has them: the whole item is set
# aside (by its index) and migrate puts it back in its place.
# - guardrail.profile_assignments[].match.substrate: 1.0.9's match is closed and needs one
#   key, and its keys combine with AND, so without substrate the match is empty (1.0.9
#   refuses config.yaml) or selects the host subjects of its other keys, which a Substrate
#   assignment never selects.
NEWER_ITEM_KEYS = (("guardrail.profile_assignments[].match.substrate", (1, 0, 10)),)
# Where a downgrade keeps the keys it set aside, in the data folder:
# {"version": 1, "for": "<older release>", "keys": {"<dotted key>": value},
#  "items": {"<list item key>": "<its name>"},  (keys inside a list item)
#  "decisions": [{"index": N, "value": {...}}],  (routing.decisions items set aside whole)
#  "assignments": [{"index": N, "profile": "<profile>", "value": {...}}],  (NEWER_ITEM_KEYS)
#  "switched": {"routing.enabled": true}}        (values switched off for the older release)
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
    changed_nothing = True


class ShimOutcomeUnknownError(ShimError):
    """The installer was started and ended, or is still running, with a result the shim cannot prove.

    The machine may have changed, so the failure must not say it did not.
    ``installer_ended``: it ended with an exit code, so nothing is still
    running and it restored the install it was replacing (the swapped rule
    packs go back, as for any failed installer).
    """

    changed_nothing = False
    installer_ended = False


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
        if exc.changed_nothing:
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
    # The command as the user ran it, for a message that sends them back
    # through this shim and the current controller.
    rerun = " ".join(["defenseclaw upgrade", *(["--version", version] if version else []), *(["--yes"] if yes else [])])
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
    released, was_running = False, False
    if _key(version) < _key(installed):
        try:
            released, was_running = _release_route_only(version, yes=yes)
            _set_aside_newer_keys(version)
        except BaseException:
            shutil.rmtree(workdir, ignore_errors=True)
            if released and was_running:
                _start_gateway_again("this release's")
            raise
    packs = None
    if _key(version) < _key(installed):
        try:
            packs = _use_target_rule_packs(repo, version, local_dir, workdir)
        except BaseException:
            # Ctrl-C while the older release's wheel downloads: the gateway
            # _release_route_only stopped must not stay down (GAP-1081).
            shutil.rmtree(workdir, ignore_errors=True)
            if released and was_running:
                _start_gateway_again("this release's")
            raise
    # Only a downgrade to a release that keeps the newer hook helper waits
    # for its installer and drops the helper (rel-1-0-4:GAP-2503); one that
    # put the route-only settings back waits too: it stopped the gateway, so
    # the older installer saw none running and does not start one.
    newer = installed if _key(version) < min(_key(installed), HOOK_HELPER_KEPT_BEFORE) else None
    rc = 1
    outcome_unknown = False
    try:
        args = (["--yes"] if yes else []) + extra
        # With swapped rule packs the shim waits too: it puts them back when
        # the installer fails (an exec would leave no one to do it). On
        # Windows it does not wait at all: the saved installer checks that no
        # DefenseClaw program runs from the venv before it opens a log, and this
        # shim is such a program, so it hands the packs to a watcher outside
        # the venv and ends (GAP-1084).
        rc = _run_installer(
            installer,
            args,
            workdir,
            newer=newer,
            rerun=rerun,
            wait=released or packs is not None,
            detach=os.name == "nt" and _key(version) < _key(installed),
            packs=packs,
        )
    except ShimOutcomeUnknownError as unknown:
        # An installer that may still be running may have changed things: leave the packs.
        outcome_unknown = not unknown.installer_ended
        raise
    finally:
        if packs is not None and rc != 0 and not outcome_unknown:
            _put_back_rule_packs(packs, version)
        if released and was_running:
            # The installed gateway: the older one after a success, this
            # release's (which writes the route settings again) otherwise.
            _start_gateway_again(f"DefenseClaw {version}" if rc == 0 else "this release's")
    return rc


# Route-only (1.0.10) points Claude Code and Codex at the gateway route
# listener in their own settings; a release before it has no such listener,
# so the agent got 401 on every call after a rollback or a downgrade
# (rel-1-0-10 GAP-0602).
ROUTE_ONLY_SINCE = (1, 0, 10)


def _route_only_rendered() -> list[str]:
    """The connectors whose agent settings still hold a route-only render."""

    def home(variable: str, default_dir: str) -> str:
        configured = os.environ.get(variable, "").strip()
        if configured:
            return os.path.abspath(os.path.expanduser(os.path.expandvars(configured)))
        return os.path.join(os.path.expanduser("~"), default_dir)

    def read(path: str) -> str:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                return handle.read(4 << 20)
        except OSError:
            return ""

    found = []
    claude = read(os.path.join(home("CLAUDE_CONFIG_DIR", ".claude"), "settings.json"))
    if "/r/claudecode" in claude or "X-DC-Route-Auth" in claude:
        found.append("claudecode")
    if "defenseclaw_route" in read(os.path.join(home("CODEX_HOME", ".codex"), "config.toml")):
        found.append("codex")
    return found


class _RouteOnlyPartlyRestoredError(ShimError):
    """Some agent settings were put back, others were not."""

    changed_nothing = False


def _release_route_only(target: str, *, yes: bool) -> tuple[bool, bool]:
    """Put back the agent model settings route-only changed before the
    installer of ``target``, a release without route-only, runs (a Unix
    downgrade; the older installer cannot do it, and a rollback or a Windows
    downgrade runs this release's installer, whose prepare-rollback step
    does). Returns whether it put settings back, and whether the gateway
    was running (the caller starts it again after the installer).

    It asks first unless ``yes``, then stops the gateway, so its connector
    repair cannot write the settings again, and checks the files. When they
    cannot be put back it starts the gateway again and refuses.
    """

    if os.name == "nt" or (_VERSION.fullmatch(target) and _key(target) >= ROUTE_ONLY_SINCE):
        return False, False
    rendered = _route_only_rendered()
    if not rendered:
        return False, False
    names = ", ".join(rendered)
    if not yes:
        if not sys.stdin.isatty():
            raise ShimError(
                f"DefenseClaw {target} has no route-only, so the {names} model settings route-only changed must be "
                "put back first; run this command again with --yes"
            )
        answer = input(
            f"  ? DefenseClaw {target} has no route-only: put back the {names} model settings and downgrade? [y/N] "
        )
        if answer.strip().lower() not in ("y", "yes"):
            raise ShimError("downgrade cancelled")
    from defenseclaw.gateway_path import canonical_install_path, path_gateway

    gateway = path_gateway(honor_override=False) or canonical_install_path()
    was_running = _gateway_running(_data_home())
    if was_running and _gateway_call(gateway, "stop") != 0:
        raise ShimError("the gateway did not stop, so the route-only settings could not be put back safely")
    _gateway_call(gateway, "connector", "route-restore", "--all")
    left = _route_only_rendered()
    if left:
        restarted = not was_running or _gateway_call(gateway, "start") == 0
        disable = " && ".join(f"defenseclaw routing disable --connector {name}" for name in left)
        error = ShimError if left == rendered and restarted else _RouteOnlyPartlyRestoredError
        raise error(
            f"the {', '.join(left)} settings still point at the DefenseClaw route-only listener, which DefenseClaw "
            f"{target} does not have, so the agent would get 401 on every call. Run: {disable} (or remove the "
            "DefenseClaw base URL and route header from those settings by hand), then run this command again"
            + ("" if restarted else ". The gateway is stopped: defenseclaw-gateway start")
        )
    print(f"  → Put back the {names} model settings that route-only changed (DefenseClaw {target} has no route-only).")
    print("    Restart the agent. Installing 1.0.10 or later again routes it again from config.yaml.")
    return True, was_running


def _gateway_call(gateway: str, *args: str) -> int:
    try:
        return subprocess.call([gateway, *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)  # noqa: S603 - the installed gateway
    except (OSError, subprocess.TimeoutExpired):
        return 1


def _start_gateway_again(which: str) -> None:
    from defenseclaw.gateway_path import canonical_install_path, path_gateway

    gateway = path_gateway(honor_override=False) or canonical_install_path()
    if _gateway_call(gateway, "start") != 0:
        print(f"  ! {which} gateway did not start; run: defenseclaw-gateway start", file=sys.stderr)


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


# Every item of a list ([]) in a NEWER_CONFIG_KEYS entry; * is every value of a map.
_EVERY_ITEM = None


def _path_segments(path: str) -> list[str | int | None]:
    """``a.b[0].c`` as ``["a", "b", 0, "c"]``; ``[]`` is ``_EVERY_ITEM``."""

    segments: list[str | int | None] = []
    for part in path.split("."):
        name, bracket, rest = part.partition("[")
        if name:
            segments.append(name)
        while bracket:
            index, _, after = rest.partition("]")
            segments.append(int(index) if index.isdigit() else _EVERY_ITEM)
            _, bracket, rest = after.partition("[")
    return segments


def config_value(raw: object, path: str) -> object:
    """The value at a concrete key (``routing.models[0].bedrock``) of a loaded config.yaml, or None."""

    node = raw
    for segment in _path_segments(path):
        if isinstance(segment, int):
            node = node[segment] if isinstance(node, list) and segment < len(node) else None
        else:
            node = node.get(segment) if isinstance(node, dict) else None
    return node


def newer_config_key(path: str) -> tuple[str, tuple[int, int, int]] | None:
    """The NEWER_CONFIG_KEYS entry a concrete key is, or None."""

    concrete = _path_segments(path)
    for pattern, since in (*NEWER_CONFIG_KEYS, *NEWER_CONFIG_SUBTREES):
        segments = _path_segments(pattern)
        if len(segments) == len(concrete) and all(
            (want is _EVERY_ITEM and isinstance(got, int))
            or (want == "*" and isinstance(got, str))
            or (isinstance(want, str) and want != "*" and want == got)
            for want, got in zip(segments, concrete)
        ):
            return pattern, since
    return None


def _newer_key_values(raw: object, pattern: str) -> tuple[dict[str, object], dict[str, str]]:
    """The concrete keys of ``raw`` a NEWER_CONFIG_KEYS entry names, set to a value, and the name of
    every list item on the way to one (so it can be put back on the same item)."""

    found: dict[str, object] = {}
    items: dict[str, str] = {}

    def walk(node: object, segments: list[str | int | None], path: str, names: dict[str, str]) -> None:
        if not segments:
            if node not in (None, ""):
                found[path] = node
                items.update(names)
            return
        head, rest = segments[0], segments[1:]
        if head is _EVERY_ITEM:
            for index, item in enumerate(node if isinstance(node, list) else []):
                key = f"{path}[{index}]"
                name = item.get("name") if isinstance(item, dict) else None
                walk(item, rest, key, {**names, key: name} if isinstance(name, str) else names)
        elif head == "*":
            for name in sorted(k for k in node if isinstance(k, str)) if isinstance(node, dict) else ():
                # Connector and profile names have no dots (the schema), so the
                # dotted key of an entry is never ambiguous.
                if name and "." not in name:
                    walk(node[name], rest, f"{path}.{name}", names)
        elif isinstance(node, dict):
            walk(node.get(head), rest, f"{path}.{head}" if path else str(head), names)

    walk(raw, _path_segments(pattern), "", {})
    return found, items


def _newer_decisions(raw: object, target: tuple[int, int, int]) -> list[dict[str, object]]:
    """The routing.decisions items the older release ``target`` refuses: a condition type it lacks."""

    if target >= NEWER_DECISION_CONDITIONS_SINCE:
        return []
    routing = raw.get("routing") if isinstance(raw, dict) else None
    decisions = routing.get("decisions") if isinstance(routing, dict) else None
    out: list[dict[str, object]] = []
    for index, item in enumerate(decisions if isinstance(decisions, list) else []):
        conditions = item.get("conditions") if isinstance(item, dict) else None
        if any(
            isinstance(c, dict) and str(c.get("type") or "").lower() not in OLDER_DECISION_CONDITION_TYPES
            for c in (conditions if isinstance(conditions, list) else [])
        ):
            out.append({"index": index, "value": item})
    return out


def _newer_assignments(raw: object, target: tuple[int, int, int]) -> list[dict[str, object]]:
    """The guardrail.profile_assignments items the older release ``target`` refuses: a match on
    Substrate actors (NEWER_ITEM_KEYS), set aside whole, never narrowed to its other keys."""

    if target >= NEWER_ITEM_KEYS[0][1]:
        return []
    guardrail = raw.get("guardrail") if isinstance(raw, dict) else None
    assignments = guardrail.get("profile_assignments") if isinstance(guardrail, dict) else None
    out: list[dict[str, object]] = []
    for index, item in enumerate(assignments if isinstance(assignments, list) else []):
        match = item.get("match") if isinstance(item, dict) else None
        if isinstance(match, dict) and "substrate" in match:
            out.append({"index": index, "profile": item.get("profile"), "value": item})
    return out


def _switched_off(raw: object, target: tuple[int, int, int]) -> dict[str, object]:
    """Values the older release ``target`` cannot run, to switch off for it: routing on with an
    in-process classifier it does not have (it would start the Docker vLLM Semantic Router)."""

    if target >= IN_PROCESS_CLASSIFIERS_SINCE:
        return {}
    routing = raw.get("routing") if isinstance(raw, dict) else None
    in_process = isinstance(routing, dict) and routing.get("classifier") in IN_PROCESS_CLASSIFIERS
    if in_process and routing.get("enabled") is True:
        return {"routing.enabled": True}
    return {}


def newer_config_values(raw: object, target: tuple[int, int, int]) -> dict[str, object]:
    """The keys of config ``raw`` that release ``target`` does not have, by concrete key."""

    found: dict[str, object] = {}
    for pattern, since in (*NEWER_CONFIG_KEYS, *NEWER_CONFIG_SUBTREES):
        if target < since:
            found.update(_newer_key_values(raw, pattern)[0])
    return found


def is_newer_config_key(key: str) -> bool:
    """Whether ``key`` (a concrete key a downgrade set aside) is one this release has."""

    return newer_config_key(key) is not None


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
    items: dict[str, str] = {}
    for pattern, since in (*NEWER_CONFIG_KEYS, *NEWER_CONFIG_SUBTREES):
        if target >= since:
            continue
        values, names = _newer_key_values(raw, pattern)
        found.update(values)
        items.update(names)
    decisions = _newer_decisions(raw, target)
    assignments = _newer_assignments(raw, target)
    switched = _switched_off(raw, target)
    if not found and not decisions and not assignments and not switched:
        return
    names = ", ".join(
        [*found]
        + [f"routing decision {d['value'].get('name')}" for d in decisions if isinstance(d["value"], dict)]
        + [f"the Substrate profile assignment of {a['profile']}" for a in assignments]
        + (["routing on with the classifier " + str(raw["routing"]["classifier"])] if switched else [])
    )
    # In the order the validated writer accepts: a decision of a newer condition type needs
    # the classifier that is about to go.
    fixes = ["remove the routing.decisions entries whose conditions are not keyword ones"] if decisions else []
    if assignments:
        fixes.append("remove the guardrail.profile_assignments entries that match substrate")
    if switched:
        fixes.append("defenseclaw routing disable")
    if found:
        fixes.append(f"defenseclaw config unset {' '.join(found)}")
    stop = (
        f"DefenseClaw {version} does not have {names}, so its installer would refuse config.yaml "
        f"or its gateway could not run it; {'; '.join(fixes)}, and run the upgrade again"
    )
    held = os.path.join(_data_home(), SET_ASIDE_FILE)
    try:
        from defenseclaw.config_writer import ACTOR_MIGRATION, Change, apply
    except Exception as exc:  # noqa: BLE001 - a broken install: say what to remove by hand
        raise ShimError(f"{stop} (the keys could not be set aside: {exc})") from None
    previous: bytes | None = None
    document: object = {}
    try:
        with open(held, "rb") as stream:
            previous = stream.read()
        document = json.loads(previous.decode("utf-8"))
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        document = {}
    if not isinstance(document, dict):
        document = {}
    kept, kept_items = document.get("keys"), document.get("items")
    kept_decisions, kept_switched = document.get("decisions"), document.get("switched")
    kept_assignments = document.get("assignments")
    keys = dict(kept) if isinstance(kept, dict) else {}
    keys.update(found)
    record: dict[str, object] = {"version": 1, "for": version, "keys": keys}
    named = dict(kept_items) if isinstance(kept_items, dict) else {}
    named.update(items)
    if named:
        record["items"] = named
    held_decisions = [d for d in kept_decisions if isinstance(d, dict)] if isinstance(kept_decisions, list) else []
    held_decisions += decisions
    if held_decisions:
        record["decisions"] = held_decisions
    held_assignments = (
        [a for a in kept_assignments if isinstance(a, dict)] if isinstance(kept_assignments, list) else []
    )
    held_assignments += assignments
    if held_assignments:
        record["assignments"] = held_assignments
    held_switched = dict(kept_switched) if isinstance(kept_switched, dict) else {}
    held_switched.update(switched)
    if held_switched:
        record["switched"] = held_switched
    changes = [Change(key, unset=True) for key in found]
    if decisions:
        drop = {d["index"] for d in decisions}
        left = [item for index, item in enumerate(raw["routing"]["decisions"]) if index not in drop]
        changes.append(Change("routing.decisions", left) if left else Change("routing.decisions", unset=True))
    if assignments:
        drop = {a["index"] for a in assignments}
        left = [item for index, item in enumerate(raw["guardrail"]["profile_assignments"]) if index not in drop]
        path = "guardrail.profile_assignments"
        changes.append(Change(path, left) if left else Change(path, unset=True))
    changes += [Change(key, False) for key in switched]
    try:
        _write_private_json(held, record)
    except OSError as exc:
        raise ShimError(f"{stop} (could not write {held}: {exc})") from None
    try:
        apply(
            changes,
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
    if switched:
        print(
            f"    Routing is switched off for {version}: without the classifier above it would need Docker "
            "(the vLLM Semantic Router). Turn it on there with 'defenseclaw routing setup' if you want it."
        )
    print(
        "    Installing a release that has it puts it back. If the installer stops, "
        "or after a rollback, put it back with: defenseclaw migrate"
    )


# Where a release wheel keeps the guardrail rule packs it ships.
_WHEEL_RULE_PACKS = "defenseclaw/_data/policies/guardrail/"
# A wheel is about 6 MB and its rule packs about 1 MB; these only stop a damaged archive.
_RULE_PACKS_MAX_FILE = 8 * 1024 * 1024
_RULE_PACKS_MAX_TOTAL = 64 * 1024 * 1024


def _use_target_rule_packs(repo: str, version: str, local_dir: str | None, workdir: str) -> ProfileRefreshResult | None:
    """Put DefenseClaw ``version``'s own rule packs in place of the unedited ones (GAP-1077).

    The older release's migrate keeps every rule pack whose files it does not
    know as the user's edit, and it does not know the ones this release
    seeded, so a downgrade left them in force. That release cannot change, so
    the packs are replaced here, before its installer runs; a pack the user
    edited is not touched and the older release keeps it too. Best effort: a
    pack that cannot be replaced is the old behaviour, never a failed downgrade.
    Returns what was swapped, for ``_put_back_rule_packs`` when the installer fails.
    """

    swapped = None
    try:
        from defenseclaw.guardrail_profiles import ProfileRefreshResult

        swapped = ProfileRefreshResult()
        _restore_rule_packs(repo, version, local_dir, workdir, swapped)
    except Exception as exc:  # noqa: BLE001 - the downgrade goes on; the installer reports what it kept
        print(
            f"  ! Could not put the rule packs of DefenseClaw {version} in place ({exc}); "
            "the installer keeps the current ones"
        )
    except BaseException:
        # Ctrl-C part way through the swap: the downgrade ends, so no older release's pack stays.
        if swapped is not None:
            _put_back_rule_packs(swapped, version)
        raise
    return swapped if swapped is not None and swapped.refreshed else None


def _rule_pack_policy_dir() -> str:
    from defenseclaw.migrations import _configured_policy_dir, _read_config_text

    return _configured_policy_dir(_data_home(), _read_config_text(_active_config_path()) or "")


def _rule_pack_undo_spec(swapped: ProfileRefreshResult | None) -> str | None:
    """What the watcher needs to put the swapped packs back: the folder, the backup, each pack's digest after the swap.

    ``None`` when nothing was swapped or the folder cannot be found.
    """

    if swapped is None or not swapped.refreshed or not swapped.backup_dir:
        return None
    try:
        guardrail = os.path.join(_rule_pack_policy_dir(), "guardrail")
    except Exception:  # noqa: BLE001 - no watcher job; the packs stay as the swap left them
        return None
    digests = {name: swapped.refreshed_digests[name] for name in swapped.refreshed if name in swapped.refreshed_digests}
    if not digests:
        return None
    return json.dumps({"dir": guardrail, "backup": swapped.backup_dir, "packs": digests})


def _put_back_rule_packs(swapped: ProfileRefreshResult, version: str) -> None:
    """The downgrade did not happen: this release's rule packs go back in place of the target's (GAP-1081)."""

    from defenseclaw.guardrail_profiles import undo_profile_refresh

    try:
        restored, problems = undo_profile_refresh(_rule_pack_policy_dir(), swapped)
    except Exception as exc:  # noqa: BLE001 - say so; the copies stay in the backup folder
        restored, problems = [], [str(exc)]
    if restored:
        print(f"  → The downgrade did not finish: rule packs {', '.join(restored)} are this release's again")
    for problem in problems:
        print(f"  ! Rule pack not put back: {problem}; the previous copies are in {swapped.backup_dir}")


def _fetch_checksums(repo: str, version: str, local_dir: str | None, workdir: str) -> str:
    """``workdir/checksums.txt`` of release ``version``, its signature verified as for an installer.

    ``_fetch_installer`` writes it for every path that downloads an installer;
    a Windows downgrade runs the saved installer instead (GAP-1081).
    """

    checksums = os.path.join(workdir, "checksums.txt")
    if os.path.isfile(checksums):
        return checksums
    if local_dir:
        try:
            shutil.copyfile(os.path.join(local_dir, "checksums.txt"), checksums)
        except OSError as exc:
            raise ShimError(f"could not read checksums.txt from {local_dir}: {exc}") from None
    else:
        _download(f"{_source_url(repo)}/releases/download/{version}/checksums.txt", checksums)
    _verify_release_signature(repo, version, local_dir, workdir, checksums)
    return checksums


def _restore_rule_packs(
    repo: str, version: str, local_dir: str | None, workdir: str, result: ProfileRefreshResult | None = None
) -> None:
    from defenseclaw.guardrail_profiles import restore_unedited_profiles, unedited_profiles
    from defenseclaw.migrations import _configured_policy_dir, _read_config_text

    data = _data_home()
    policy_dir = _configured_policy_dir(data, _read_config_text(_active_config_path()) or "")
    if not unedited_profiles(policy_dir):
        return
    name = f"defenseclaw-{version}-py3-none-any.whl"
    wheel = os.path.join(workdir, name)
    checksums = _fetch_checksums(repo, version, local_dir, workdir)
    if local_dir:
        try:
            shutil.copyfile(os.path.join(local_dir, name), wheel)
        except OSError as exc:
            raise ShimError(f"could not read {name} from {local_dir}: {exc}") from None
    else:
        _download(f"{_source_url(repo)}/releases/download/{version}/{name}", wheel)
    with open(wheel, "rb") as stream:
        actual = hashlib.sha256(stream.read()).hexdigest()
    if actual != _expected_sha256(checksums, name):
        raise ShimError(f"{name} does not match checksums.txt")
    packs = os.path.join(workdir, "target-rule-packs")
    _extract_rule_packs(wheel, packs)
    result = restore_unedited_profiles(policy_dir, os.path.join(data, "backups"), packs, result)
    for error in result.errors:
        print(f"  ! Rule pack not replaced: {error}")
    if result.refreshed:
        print(
            f"  → Rule packs {', '.join(result.refreshed)} are DefenseClaw {version}'s again "
            f"(previous copies in {result.backup_dir})"
        )
    if result.kept_modified:
        print(f"  → Kept your edited rule packs {', '.join(result.kept_modified)}")


def _extract_rule_packs(wheel: str, destination: str) -> None:
    """Unpack the rule packs of a release wheel into ``destination``; nothing else leaves the archive."""

    total = 0
    root = os.path.realpath(destination)
    with zipfile.ZipFile(wheel) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.startswith(_WHEEL_RULE_PACKS):
                continue
            relative = info.filename[len(_WHEEL_RULE_PACKS) :]
            target = os.path.realpath(os.path.join(root, *relative.split("/")))
            if not relative or os.path.commonpath([root, target]) != root:
                raise ShimError(f"{wheel} holds a rule pack path outside its folder: {info.filename}")
            total += info.file_size
            if info.file_size > _RULE_PACKS_MAX_FILE or total > _RULE_PACKS_MAX_TOTAL:
                raise ShimError(f"{wheel} holds more rule pack data than a release ships")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with archive.open(info) as source, open(target, "wb") as out:
                shutil.copyfileobj(source, out)
    if not os.path.isdir(root):
        raise ShimError(f"{wheel} holds no rule packs")


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
    rerun = "defenseclaw rollback" + (" --yes" if yes else "")
    # The route-only agent settings go back in the saved installer's
    # prepare-rollback step, after its prompt and with the gateway stopped.
    return _run_installer(copy, ["--rollback"] + (["--yes"] if yes else []), workdir, rerun=rerun)


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


# How long the shim waits for a started Windows installer to open its log. Before
# it has one the installer can wait up to 300 seconds for an earlier uninstall's
# cleanup (Wait-UninstallCleanup in install.ps1) and then fails; an installer run
# with --yes that fails keeps its console for up to 120 seconds (Wait-BeforeClose)
# before the process exits. The wait covers both and a margin, so the exit code is
# known before the shim reports.
_INSTALLER_CLEANUP_WAIT = 300.0
_INSTALLER_ERROR_WINDOW = 120.0
_INSTALLER_LOG_WAIT = _INSTALLER_CLEANUP_WAIT + _INSTALLER_ERROR_WINDOW + 30.0
_INSTALLER_LOG_POLL = 0.25
# A log's new bytes are read in chunks that overlap by more than a transcript
# header line is long, so a header cut by a chunk edge is still found.
_INSTALLER_LOG_CHUNK = 1 << 20
_INSTALLER_LOG_OVERLAP = 256


def _terminal_command(script: str, ps_args: list[str]) -> str:
    """The command that runs *script* in the current terminal, for a message."""
    return " ".join(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", f'"{script}"', *ps_args])


_RECOVERY_COMPANIONS = ("checksums.txt", "checksums.txt.bundle")


def _stage_recovery_copy(path: str) -> tuple[str, str] | None:
    """Copy the verified installer and its checksum files to a directory only the shim owns (GAP-1011).

    install.ps1 deletes the temporary directory it runs from (a leaf named
    defenseclaw-upgrade-* or defenseclaw-rollback-*) before the process ends,
    so a command printed for a file in that directory names a file that is
    gone. This directory has a different leaf name, which that cleanup never
    matches. Returns (installer copy, SHA-256 of the verified bytes), or
    ``None`` when the copy could not be made.
    """
    directory: str | None = None
    try:
        directory = tempfile.mkdtemp(prefix="defenseclaw-recovery-")
        with open(path, "rb") as stream:
            body = stream.read()
        copy = os.path.join(directory, os.path.basename(path))
        with open(copy, "xb") as target:
            target.write(body)
        for name in _RECOVERY_COMPANIONS:
            try:
                shutil.copyfile(os.path.join(os.path.dirname(path), name), os.path.join(directory, name))
            except FileNotFoundError:
                continue
    except OSError:
        if directory:
            shutil.rmtree(directory, ignore_errors=True)
        return None
    return copy, hashlib.sha256(body).hexdigest()


def _drop_recovery_copy(recovery: tuple[str, str] | None) -> None:
    if recovery:
        shutil.rmtree(os.path.dirname(recovery[0]), ignore_errors=True)


# Runs hidden after the shim has exited. It waits for the installer the shim
# started; when that ends with exit code 0 it removes the recovery copy, and
# when it fails it puts back the rule packs the shim swapped in (the folder, the
# backup and each pack's digest come in DC_WATCH_PACKS), then keeps the copy,
# which the failed run's message names (GAP-1011). A pack that changed since
# the swap is left alone. It uses language operators and .NET calls only, so no
# PowerShell module has to load, and it holds no file under the venv, which the
# installer's in-use check would refuse to replace (GAP-1084).
# The process handle is read before the wait: without it a process found by id
# reports no exit code at all, which would read as a failure.
# Its own exit code says what it did: 0 removed the copy, 3 could not watch
# the installer, 4 the installer failed (copy kept, packs put back), 5 the
# folder is not a recovery copy, 6 the removal failed.
# Get-Digest is profile_digest of guardrail_profiles.py: sha256 over each file's
# "relative path, NUL, sha256 hex, newline", sorted by path, dot files skipped.
_RECOVERY_WATCHER = (
    "$ErrorActionPreference = 'Stop'; "
    "function Get-Digest([string]$root) { "
    "$root = [System.IO.Path]::GetFullPath($root).TrimEnd('\\'); "
    "$map = @{}; "
    "foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -File -Force) { "
    "$rel = $f.FullName.Substring($root.Length + 1).Replace('\\', '/'); "
    "$skip = $false; "
    "foreach ($part in $rel.Split('/')) { if ($part.StartsWith('.') -or $part -eq '__pycache__') { $skip = $true } }; "
    "if (-not $skip) { $map[$rel] = $f.FullName } }; "
    "$keys = [string[]]@($map.Keys); [System.Array]::Sort($keys, [System.StringComparer]::Ordinal); "
    "$sha = [System.Security.Cryptography.SHA256]::Create(); "
    "$ms = New-Object System.IO.MemoryStream; "
    "foreach ($k in $keys) { "
    "$h = [System.BitConverter]::ToString($sha.ComputeHash([System.IO.File]::ReadAllBytes($map[$k]))); "
    "$h = $h.Replace('-', '').ToLower(); "
    "$b = [System.Text.Encoding]::UTF8.GetBytes($k + [string][char]0 + $h + [string][char]10); "
    "$ms.Write($b, 0, $b.Length) }; "
    "return [System.BitConverter]::ToString($sha.ComputeHash($ms.ToArray())).Replace('-', '').ToLower() }; "
    "function Restore-Packs { "
    "$s = $env:DC_WATCH_PACKS | ConvertFrom-Json; "
    "foreach ($n in @($s.packs.PSObject.Properties)) { "
    "try { "
    "$dst = Join-Path $s.dir $n.Name; $bk = Join-Path $s.backup $n.Name; "
    "$st = Join-Path $s.dir ('.' + $n.Name + '.undo'); "
    "if (-not (Test-Path -LiteralPath $bk -PathType Container)) { continue }; "
    "if ((Get-Digest $dst) -ne $n.Value) { continue }; "
    "if (Test-Path -LiteralPath $st) { Remove-Item -LiteralPath $st -Recurse -Force }; "
    "Move-Item -LiteralPath $dst -Destination $st; "
    "try { Move-Item -LiteralPath $bk -Destination $dst } "
    "catch { Move-Item -LiteralPath $st -Destination $dst; throw }; "
    "Remove-Item -LiteralPath $st -Recurse -Force "
    "} catch { } }; "
    "try { [System.IO.Directory]::Delete($s.backup) } catch { } }; "
    "try { $p = [System.Diagnostics.Process]::GetProcessById([int]$env:DC_WATCH_PID) } catch { exit 3 }; "
    "if (@('powershell', 'pwsh') -notcontains $p.ProcessName) { exit 3 }; "
    "$null = $p.Handle; "
    "$p.WaitForExit(); "
    "if ($p.ExitCode -ne 0) { if ($env:DC_WATCH_PACKS) { try { Restore-Packs } catch { } }; exit 4 }; "
    "$d = $env:DC_WATCH_DIR; "
    "if (-not $d) { exit 0 }; "
    "if (-not [System.IO.Path]::GetFileName($d).StartsWith('defenseclaw-recovery-')) { exit 5 }; "
    "try { [System.IO.Directory]::Delete($d, $true) } catch { exit 6 }; "
    "exit 0"
)


def _watch_recovery_copy(
    powershell: str, pid: int, recovery: tuple[str, str] | None, env: dict[str, str], packs: str | None = None
) -> subprocess.Popen[bytes] | None:
    """Start the hidden process that removes *recovery* when the installer *pid* ends with exit code 0.

    *packs* (``_rule_pack_undo_spec``) makes it put the swapped rule packs back
    when the installer fails.

    The shim returns while the installer still runs (it must free the files of
    the running CLI), so only a process that outlives it can see the result.
    It is not started from the CLI's own interpreter, which would hold files
    the installer replaces, and its working directory is the system folder, so
    it never holds the folder it removes. ``None`` when it could not start: the
    copy then stays, as it does after a failed run.
    """
    if not recovery and not packs:
        return None
    watch_env = dict(env)
    watch_env["DC_WATCH_PID"] = str(pid)
    watch_env.pop("DC_WATCH_DIR", None)
    watch_env.pop("DC_WATCH_PACKS", None)
    if recovery:
        watch_env["DC_WATCH_DIR"] = os.path.dirname(recovery[0])
    if packs:
        watch_env["DC_WATCH_PACKS"] = packs
    try:
        return subprocess.Popen(  # noqa: S603 - fixed interpreter and fixed script
            [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _RECOVERY_WATCHER],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            cwd=os.environ.get("SystemRoot", r"C:\Windows"),
            env=watch_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None


def _recovery_copy_verifies(recovery: tuple[str, str] | None) -> bool:
    if not recovery:
        return False
    try:
        with open(recovery[0], "rb") as stream:
            return hashlib.sha256(stream.read()).hexdigest() == recovery[1]
    except OSError:
        return False


def _install_logs(logs: str) -> dict[str, int]:
    """The install logs (name -> size) in *logs*."""
    sizes: dict[str, int] = {}
    try:
        names = os.listdir(logs)
    except OSError:
        return sizes
    for name in names:
        if name.startswith("install-") and name.endswith(".log"):
            try:
                sizes[name] = os.stat(os.path.join(logs, name)).st_size
            except OSError:
                continue
    return sizes


def _log_opened_by(logs: str, known: dict[str, int], pid: int, scanned: dict[str, int] | None = None) -> bool:
    """Whether the process *pid* wrote a transcript header into *logs* since *known*.

    The installer names a log to the second and opens it with ``-Append``, so
    a name already in *known* may be the installer's own log, and a log that
    appeared or grew may be another run's. The transcript header names the
    process (``Process ID: <pid>``): only the bytes added since the snapshot
    count, however many another run added before this header, and only a
    header with this process's id. *scanned* (name -> bytes read so far) lets
    a poll read only what is new.
    """
    if scanned is None:
        scanned = {}
    marker = re.compile(rb"Process ID:\s*" + str(pid).encode("ascii") + rb"(?!\d)")
    for name, size in _install_logs(logs).items():
        floor = known.get(name, 0)
        if size < floor:  # replaced by a shorter file: all of it is new
            floor = 0
        done = scanned.get(name, floor)
        if size < done:
            done = floor
        if size == done:
            continue
        pos = max(floor, done - _INSTALLER_LOG_OVERLAP)
        try:
            with open(os.path.join(logs, name), "rb") as stream:
                stream.seek(pos)
                while True:
                    chunk = stream.read(_INSTALLER_LOG_CHUNK)
                    # A UTF-16 transcript spaces every character with a NUL.
                    if marker.search(chunk.replace(b"\x00", b"")):
                        return True
                    pos += len(chunk)
                    if len(chunk) < _INSTALLER_LOG_CHUNK:
                        break
                    pos -= _INSTALLER_LOG_OVERLAP
                    stream.seek(pos)
        except OSError:
            continue
        scanned[name] = pos
    return False


# The Windows installer checks that nothing runs from the venv before it
# changes anything (Wait-VenvFree), and this process and its console launchers
# run from it. A downgrade's controller does that check before it opens a log,
# so a shim that waited for the log there kept them running and the two waited
# on each other until the installer gave up: "DefenseClaw is in use by
# defenseclaw.exe, defenseclaw.exe, python.exe" (GAP-2117). So the shim hands
# over: DC_INSTALLER_HANDOFF names this process (pid and creation time) and a
# named event; the installer sets the event, which lets the shim exit, and waits
# for exactly that process before its check. Nothing is left out of the check.
_HANDOFF_ENV = "DC_INSTALLER_HANDOFF"
_HANDOFF_EVENT_PREFIX = "Local\\DefenseClaw-installer-handoff-"
_ERROR_ALREADY_EXISTS = 183


def _installer_handoff() -> tuple[str, Callable[[], bool]] | None:
    """The handoff for a started Windows installer: (its DC_INSTALLER_HANDOFF value, whether the event is set).

    None where it cannot be made (no Windows API): the installer then gets no
    handoff, and the shim waits for its log as before.
    """
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except (ImportError, AttributeError, OSError):
        return None
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.CreateEventW.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR)
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    times = [wintypes.FILETIME() for _ in range(4)]
    if not kernel32.GetProcessTimes(kernel32.GetCurrentProcess(), *(ctypes.byref(item) for item in times)):
        return None
    created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
    name = _HANDOFF_EVENT_PREFIX + os.urandom(16).hex()
    event = kernel32.CreateEventW(None, True, False, name)
    if not event:
        return None
    if ctypes.get_last_error() == _ERROR_ALREADY_EXISTS:
        # Another process made this name first: its event is not ours to wait on.
        kernel32.CloseHandle(event)
        return None
    # The handle stays open until this process exits, so the event lives as long as the shim.
    return f"{os.getpid()}:{created}:{name}", lambda: kernel32.WaitForSingleObject(event, 0) == 0


def _await_installer_log(
    proc: subprocess.Popen[bytes],
    logs: str,
    known: dict[str, int],
    handed_off: Callable[[], bool] | None = None,
) -> tuple[bool, int | None]:
    """Wait until the started installer opens its install log, takes the handoff, or ends.

    Returns (started, exit code or None while it still runs): started is an
    open log or a taken handoff (*handed_off* returns True once the installer
    set the event; it then waits for this process to exit). It gives up
    waiting after ``_INSTALLER_LOG_WAIT`` seconds, which outlasts the
    installer's own 300-second wait for an earlier uninstall and its 120-second
    error window; the caller reports an installer that still runs then as
    unconfirmed.
    """
    deadline = time.monotonic() + _INSTALLER_LOG_WAIT
    scanned: dict[str, int] = {}
    while True:
        rc = proc.poll()
        if _log_opened_by(logs, known, proc.pid, scanned):
            return True, rc
        if handed_off is not None and handed_off():
            return True, proc.poll()
        if rc is not None:
            return False, rc
        if time.monotonic() >= deadline:
            return False, None
        time.sleep(_INSTALLER_LOG_POLL)


def _run_installer(
    path: str,
    args: list[str],
    workdir: str,
    *,
    rerun: str,
    newer: str | None = None,
    wait: bool = False,
    detach: bool = False,
    packs: ProfileRefreshResult | None = None,
) -> int:
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
            command = _terminal_command(path, ps_args)
            raise ShimError(
                "this terminal has no desktop (SSH session), so the installer's window would not be "
                "visible here.\n"
                "    Run the installer in this terminal instead; it shows the result and sets the exit code:\n"
                f"      {command}"
            )
        home = _data_home()
        logs = os.path.join(home, "logs")
        known = _install_logs(logs)
        # The installer deletes the directory it runs from; keep a verified
        # copy elsewhere for the recovery command of a failed run.
        recovery = _stage_recovery_copy(path)
        # The installer waits for this process to exit before it checks the
        # venv, so a downgrade's controller does not wait on it (GAP-2117).
        handoff = _installer_handoff()
        installer_env = dict(env)
        if handoff:
            installer_env[_HANDOFF_ENV] = handoff[0]
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed interpreter and verified script
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path, *ps_args],
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
                cwd=workdir,
                env=installer_env,
            )
        except OSError as exc:
            shutil.rmtree(workdir, ignore_errors=True)
            _drop_recovery_copy(recovery)
            raise ShimError(f"could not start {powershell}: {exc}") from None
        # The shim ends while the installer runs, so a process that outlives it
        # removes the copy once the installer has ended with exit code 0, and
        # puts the swapped rule packs back when it fails.
        undo = _rule_pack_undo_spec(packs) if detach else None
        watcher = _watch_recovery_copy(powershell, proc.pid, recovery, env, undo)
        if detach:
            # The saved installer of this release checks that no DefenseClaw
            # program runs from the venv before it opens its log (and the log
            # that opens is the older installer's, with another process id).
            # This shim is such a program: waiting for a log here would hold the
            # check and fail the installer (GAP-1084). Leave now; the result is
            # shown in the installer's window and kept by the watcher.
            print("  → The installer was started in a new window; this command ends now so it can replace its files.")
            print("    It has not reported a result yet: that window shows it when it ends.")
            if undo and watcher is not None:
                print("    If it fails, this release's rule packs are put back.")
            elif undo:
                print("  ! Could not start the process that puts the rule packs back: if the installer fails they stay")
            if recovery:
                print(
                    "    If the window shows an error, run the kept installer copy, verified against SHA-256 "
                    f"{recovery[1]}, in this terminal:\n      {_terminal_command(recovery[0], ps_args)}\n"
                    f"    or run this command again:\n      {rerun}"
                )
            print("    Confirm the result afterwards with: defenseclaw --version")
            return 0
        # A started process is not a running install (GAP-1011): the installer
        # opens its log only after it has the install lock, and an installer
        # that ends before then leaves nothing but a window that closes.
        print(f"  → Waiting for the installer to open its log (up to {int(_INSTALLER_LOG_WAIT)} s)...", flush=True)
        opened, rc = _await_installer_log(proc, logs, known, handoff[1] if handoff else None)
        if opened:
            # An open log is a start, not a result: the installer may still
            # fail and delete the folder it runs from, so the verified copy
            # stays until the installer ends with exit code 0. The watcher
            # started above removes it then; an installer that already ended
            # with 0 is handled here.
            if rc == 0:
                _drop_recovery_copy(recovery)
                print("  → The installer ran in its own window and ended with exit code 0.")
                print(f"    Its log is saved in {logs} (install-<time>.log).")
            elif rc is not None:
                print(f"  → The installer ran in its own window and ended with exit code {rc}; the window shows why.")
                print(f"    Its log is saved in {logs} (install-<time>.log).")
            else:
                # GAP-1068: the installer cannot replace the files this
                # process runs from while it waits, so the install goes on
                # after this command ends: say so, and how to read the result.
                print("  → The installer continues in a new window: the install is not finished yet.")
                print(
                    "    It usually takes 2 to 5 minutes. It stops the gateway and starts it again, so wait for it "
                    "to end before you run defenseclaw doctor."
                )
                print(f"    The window shows the result when it ends; its log is saved in {logs} (install-<time>.log).")
        elif rc == 0:
            shutil.rmtree(workdir, ignore_errors=True)
            _drop_recovery_copy(recovery)
            print("  → The installer ran in its own window and ended with exit code 0 without opening an install log.")
        elif rc is not None:
            # No log is not proof that nothing changed: the installer goes on
            # without a transcript when it cannot write one. Keep the staged
            # installer, so the result can be read in this terminal.
            shutil.rmtree(workdir, ignore_errors=True)
            if recovery and _recovery_copy_verifies(recovery):
                route = (
                    "run the kept installer copy, verified against SHA-256 "
                    f"{recovery[1]}, in this terminal:\n      {_terminal_command(recovery[0], ps_args)}\n"
                    f"    or run this command again:\n      {rerun}\n"
                )
            else:
                # A release installer of a lower target cannot read the recovery
                # receipts of this install: go back through the shim, which
                # picks the current controller again.
                _drop_recovery_copy(recovery)
                route = f"run this command again (the kept copy is not available):\n      {rerun}\n"
            ended = ShimOutcomeUnknownError(
                f"the installer ended with exit code {rc} before it opened its log. It may have stopped before "
                "changing anything, or later if it could not write its log, so the result is not known; the "
                "reason was shown only in its window, which has closed. Check the install with: "
                "defenseclaw --version and defenseclaw doctor. To read the result, "
                f"{route}"
                "    The installer first restores an install it was replacing."
            )
            ended.installer_ended = True
            raise ended
        else:
            # Still running, so no result: the verified copy stays.
            raise ShimOutcomeUnknownError(
                f"the installer is still running and has not opened its log after {int(_INSTALLER_LOG_WAIT)} "
                "seconds, so the start is not confirmed: it may wait on an earlier uninstall's cleanup or another "
                "install, or hold an error in its window. Read that window and let the installer end before you "
                "start another install; then check: defenseclaw --version and defenseclaw doctor"
            )
        print("    Confirm the result afterwards with: defenseclaw --version and defenseclaw doctor")
        return 0
    bash = "/bin/bash" if os.path.exists("/bin/bash") else (shutil.which("bash") or "bash")
    sys.stdout.flush()
    sys.stderr.flush()
    if newer or wait:
        # A downgrade from newer: the older installer keeps the hook helper of
        # this release, so the shim waits for it (rel-1-0-4:GAP-2503). wait:
        # the caller undoes its own step when the installer fails (GAP-0602).
        rc = _wait_for_installer([bash, path, *args])
        shutil.rmtree(workdir, ignore_errors=True)
        if rc == 0 and newer:
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
