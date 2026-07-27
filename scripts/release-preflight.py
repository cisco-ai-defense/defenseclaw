#!/usr/bin/env python3
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

"""Fail-closed operator and workflow preflight for DefenseClaw releases.

The release workflow remains the publication authority. This command verifies
that an operator is on the exact reviewed ``main`` commit, that the remote
namespace and authenticated upgrade baselines are usable, and that the signed
stable-channel ref has its required live repository rules. It prints the exact
manual dispatch command but never dispatches a workflow or mutates a release.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

try:
    from scripts import release_api_retry, release_candidate
except ModuleNotFoundError:  # Direct ``python scripts/release-preflight.py`` execution.
    import release_api_retry  # type: ignore[no-redef]
    import release_candidate  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPOSITORY = "cisco-ai-defense/defenseclaw"
RULESET_POLICY_PATH = ROOT / "release" / "release-channel-ruleset-policy.json"
RELEASE_CHANNEL_BRANCH = "release-channel"
WINDOWS_FRESH_INSTALL_ONLY_THROUGH = "0.8.8"
GITHUB_API_PAGE_SIZE = 100
MAX_GITHUB_API_ROWS = 1000
VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
GITHUB_CLI_UNTRUSTED_ENVIRONMENT = frozenset(
    {
        "GH_HOST",
        "GH_REPO",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "GIT_SSL_CAPATH",
        "GIT_SSL_NO_VERIFY",
        "BASH_ENV",
        "ENV",
        "CDPATH",
        "GLOBIGNORE",
        "BASH_COMPAT",
        "POSIXLY_CORRECT",
        "PROMPT_COMMAND",
        "BASH_XTRACEFD",
        "IFS",
        "GODEBUG",
        "GOFLAGS",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONINSPECT",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONWARNINGS",
        "PYTHONBREAKPOINT",
        "PERL5OPT",
        "PERL5DB",
        "PERL5LIB",
        "PERLLIB",
        "SSLKEYLOGFILE",
    }
)
GITHUB_CLI_UNTRUSTED_ENVIRONMENT_CASEFOLD = frozenset(
    variable.casefold() for variable in GITHUB_CLI_UNTRUSTED_ENVIRONMENT
)
GITHUB_CLI_UNTRUSTED_ENVIRONMENT_PREFIXES_CASEFOLD = (
    "cosign_",
    "dyld_",
    "ld_",
    "sigstore_",
    "tuf_",
)
EXPECTED_POLICY_FIELDS = {
    "schema_version",
    "source_type",
    "source",
    "target",
    "target_ref",
    "repository_condition",
    "required_rules",
    "publisher_bypass",
}
EXPECTED_BYPASS_FIELDS = {"actor_type", "actor_id", "bypass_mode"}
Runner = Callable[..., subprocess.CompletedProcess[str]]


class ReleasePreflightError(RuntimeError):
    """The release request is not ready for a production dispatch."""


def _version_key(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise ReleasePreflightError(f"version must be canonical X.Y.Z without a v prefix: {value!r}")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def _boolean(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("expected exactly true or false")


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleasePreflightError(f"could not read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleasePreflightError(f"{label} must contain a JSON object")
    return value


def load_ruleset_policy(path: Path = RULESET_POLICY_PATH) -> dict[str, Any]:
    """Load the closed live-ruleset contract tracked with release source."""

    policy = _load_json_object(path, "release-channel ruleset policy")
    bypass = policy.get("publisher_bypass")
    rules = policy.get("required_rules")
    repository_condition = policy.get("repository_condition")
    if (
        set(policy) != EXPECTED_POLICY_FIELDS
        or policy.get("schema_version") != 2
        or policy.get("source_type") != "Organization"
        or policy.get("source") != "cisco-ai-defense"
        or policy.get("target") != "branch"
        or policy.get("target_ref") != "refs/heads/release-channel"
        or repository_condition
        != {
            "include": ["defenseclaw"],
            "exclude": [],
            "protected": True,
        }
        or not isinstance(rules, list)
        or len(rules) != len(set(rules))
        or set(rules) != {"creation", "update", "deletion", "non_fast_forward"}
        or not isinstance(bypass, dict)
        or set(bypass) != EXPECTED_BYPASS_FIELDS
        or bypass.get("actor_type") != "Integration"
        or not isinstance(bypass.get("actor_id"), int)
        or isinstance(bypass.get("actor_id"), bool)
        or bypass["actor_id"] <= 0
        or bypass.get("bypass_mode") != "always"
    ):
        raise ReleasePreflightError("release-channel ruleset policy is malformed")
    return policy


def validate_release_channel_rulesets(
    rulesets: object,
    *,
    effective_rules: object,
    policy: Mapping[str, Any] | None = None,
    require_publisher_bypass: bool = True,
) -> tuple[int, str]:
    """Require one active exact channel ruleset, plus publisher custody when visible.

    GitHub omits ``bypass_actors`` from repository-ruleset responses unless the
    caller can write the ruleset. Routine operator and workflow preflight verify
    the exact active channel ruleset and observable protections. The explicit
    administrator audit requires the complete publisher binding, and the later
    channel publish proves that the workflow integration still has bypass.
    """

    expected = dict(policy or load_ruleset_policy())
    if not isinstance(rulesets, list) or any(not isinstance(item, dict) for item in rulesets):
        raise ReleasePreflightError("GitHub ruleset inventory must be an object array")
    if not isinstance(effective_rules, list) or any(not isinstance(item, dict) for item in effective_rules):
        raise ReleasePreflightError("GitHub effective-rule inventory must be an object array")
    required_rules = set(expected["required_rules"])
    required_bypass = expected["publisher_bypass"]
    matching: list[tuple[int, str]] = []
    active_branch_ruleset_ids: set[int] = set()
    for ruleset in rulesets:
        conditions = ruleset.get("conditions")
        ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
        repository_name = conditions.get("repository_name") if isinstance(conditions, dict) else None
        rules = ruleset.get("rules")
        bypasses = ruleset.get("bypass_actors")
        identifier = ruleset.get("id")
        name = ruleset.get("name")
        if (
            ruleset.get("target") == "branch"
            and ruleset.get("enforcement") == "active"
            and isinstance(identifier, int)
            and not isinstance(identifier, bool)
            and identifier > 0
        ):
            active_branch_ruleset_ids.add(identifier)
        if (
            ruleset.get("target") != expected["target"]
            or ruleset.get("source_type") != expected["source_type"]
            or ruleset.get("source") != expected["source"]
            or ruleset.get("enforcement") != "active"
            or not isinstance(ref_name, dict)
            or ref_name.get("include") != [expected["target_ref"]]
            or ref_name.get("exclude") != []
            or repository_name != expected["repository_condition"]
            or not isinstance(rules, list)
            or any(not isinstance(rule, dict) for rule in rules)
            or not isinstance(identifier, int)
            or isinstance(identifier, bool)
            or not isinstance(name, str)
            or not name
        ):
            continue
        observed_rules = {rule.get("type") for rule in rules if isinstance(rule.get("type"), str)}
        if len(rules) != len(required_rules) or observed_rules != required_rules:
            continue
        if require_publisher_bypass:
            if not isinstance(bypasses, list) or len(bypasses) != 1:
                continue
            actor = bypasses[0]
            if (
                not isinstance(actor, dict)
                or {key: actor.get(key) for key in EXPECTED_BYPASS_FIELDS} != required_bypass
            ):
                continue
        matching.append((identifier, name))
    if len(matching) != 1:
        publisher_requirement = " plus the reviewed GitHub Actions publisher bypass" if require_publisher_bypass else ""
        raise ReleasePreflightError(
            "GitHub must expose exactly one active ruleset targeting only "
            "refs/heads/release-channel with creation, update, deletion, and "
            f"non-fast-forward restrictions{publisher_requirement}; found {len(matching)}"
        )
    identifier, name = matching[0]
    effective_branch_rules: list[dict[str, Any]] = []
    for rule in effective_rules:
        ruleset_id = rule.get("ruleset_id")
        if not isinstance(ruleset_id, int) or isinstance(ruleset_id, bool) or ruleset_id <= 0:
            raise ReleasePreflightError("GitHub effective-rule inventory contains an invalid ruleset ID")
        if ruleset_id not in active_branch_ruleset_ids:
            raise ReleasePreflightError(
                "GitHub effective-rule inventory references a ruleset "
                "absent from the observed active branch-ruleset inventory"
            )
        effective_branch_rules.append(rule)
    effective_ids = {rule["ruleset_id"] for rule in effective_branch_rules}
    effective_types = {
        rule.get("type")
        for rule in effective_branch_rules
        if rule["ruleset_id"] == identifier and isinstance(rule.get("type"), str)
    }
    if effective_ids != {identifier} or effective_types != required_rules:
        raise ReleasePreflightError(
            "release-channel has overlapping or incomplete effective branch rules; "
            "the exact reviewed ruleset must be its only active branch-ruleset authority"
        )
    return identifier, name


def _run(
    command: Sequence[str],
    *,
    runner: Runner = subprocess.run,
    cwd: Path = ROOT,
    env: Mapping[str, str] | None = None,
) -> str:
    try:
        completed = runner(
            list(command),
            cwd=cwd,
            env=None if env is None else dict(env),
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleasePreflightError(f"could not execute {' '.join(command)}: {exc}") from exc
    if completed.returncode != 0:
        detail = " ".join((completed.stderr or completed.stdout).strip().split())
        if len(detail) > 500:
            detail = f"{detail[:500]}..."
        raise ReleasePreflightError(
            f"{' '.join(command)} failed with exit {completed.returncode}" + (f": {detail}" if detail else "")
        )
    return completed.stdout


def _fetch_paginated_github_array(
    endpoint: str,
    *,
    label: str,
    runner: Runner,
) -> list[dict[str, Any]]:
    """Fetch every object page from one GitHub endpoint under a closed bound."""

    rows: list[dict[str, Any]] = []
    page_separator = "&" if "?" in endpoint else "?"
    maximum_pages = MAX_GITHUB_API_ROWS // GITHUB_API_PAGE_SIZE
    for page in range(1, maximum_pages + 2):
        raw = _run(
            [
                "gh",
                "api",
                "-H",
                "Accept: application/vnd.github+json",
                (f"{endpoint}{page_separator}per_page={GITHUB_API_PAGE_SIZE}&page={page}"),
            ],
            runner=runner,
        )
        try:
            page_rows = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ReleasePreflightError(f"GitHub {label} page {page} is invalid JSON: {exc}") from exc
        if (
            not isinstance(page_rows, list)
            or len(page_rows) > GITHUB_API_PAGE_SIZE
            or any(not isinstance(row, dict) for row in page_rows)
        ):
            raise ReleasePreflightError(f"GitHub {label} page {page} is not a bounded object array")
        if page > maximum_pages:
            if page_rows:
                raise ReleasePreflightError(f"GitHub {label} exceeds the {MAX_GITHUB_API_ROWS}-row safety bound")
            break
        rows.extend(page_rows)
        if len(page_rows) < GITHUB_API_PAGE_SIZE:
            break
    return rows


def fetch_release_channel_rulesets(
    repository: str,
    *,
    runner: Runner = subprocess.run,
) -> list[dict[str, Any]]:
    """Fetch complete repository rulesets through bounded authenticated calls."""

    rows = _fetch_paginated_github_array(
        f"repos/{repository}/rulesets?includes_parents=true",
        label="ruleset listing",
        runner=runner,
    )
    details: list[dict[str, Any]] = []
    for row in rows:
        identifier = row.get("id")
        if not isinstance(identifier, int) or isinstance(identifier, bool) or identifier <= 0:
            raise ReleasePreflightError("GitHub ruleset listing contains an invalid ID")
        detail_raw = _run(
            [
                "gh",
                "api",
                "-H",
                "Accept: application/vnd.github+json",
                f"repos/{repository}/rulesets/{identifier}",
            ],
            runner=runner,
        )
        try:
            detail = json.loads(detail_raw)
        except json.JSONDecodeError as exc:
            raise ReleasePreflightError(f"GitHub ruleset {identifier} is invalid JSON: {exc}") from exc
        if not isinstance(detail, dict) or detail.get("id") != identifier:
            raise ReleasePreflightError(f"GitHub ruleset {identifier} detail is inconsistent")
        details.append(detail)
    return details


def fetch_effective_release_channel_rules(
    repository: str,
    *,
    runner: Runner = subprocess.run,
) -> list[dict[str, Any]]:
    """Fetch the aggregate rules GitHub applies to the stable-channel branch."""

    return _fetch_paginated_github_array(
        f"repos/{repository}/rules/branches/{RELEASE_CHANNEL_BRANCH}",
        label="effective release-channel rules",
        runner=runner,
    )


def validate_request(
    *,
    operation: str,
    version: str,
    repository: str,
    ref: str,
    commit: str,
    immutable_releases_confirmed: bool,
    rulesets: object,
    effective_rules: object,
    expected_commit: str,
    require_publisher_bypass: bool = True,
) -> tuple[int, str]:
    """Validate immutable request inputs and the live channel protection."""

    _version_key(version)
    if operation not in {"release", "repair-channel"}:
        raise ReleasePreflightError(f"unsupported release operation: {operation!r}")
    if repository != DEFAULT_REPOSITORY:
        raise ReleasePreflightError(f"release repository must be exactly {DEFAULT_REPOSITORY}, got {repository!r}")
    if ref != "refs/heads/main":
        raise ReleasePreflightError(f"release operations must run from refs/heads/main, got {ref!r}")
    if COMMIT_RE.fullmatch(commit) is None:
        raise ReleasePreflightError("release commit must be an exact lowercase 40-character SHA")
    if COMMIT_RE.fullmatch(expected_commit) is None or expected_commit != commit:
        raise ReleasePreflightError("expected release commit must be the exact workflow commit selected by main")
    if operation == "release" and not immutable_releases_confirmed:
        raise ReleasePreflightError("release immutability must be confirmed before a release dispatch")
    if operation == "repair-channel" and immutable_releases_confirmed:
        raise ReleasePreflightError("repair-channel must not carry the release-only immutability confirmation")
    return validate_release_channel_rulesets(
        rulesets,
        effective_rules=effective_rules,
        require_publisher_bypass=require_publisher_bypass,
    )


def select_upgrade_baselines(
    *,
    policy_path: Path,
    target: str,
) -> list[str]:
    """Select and persist the target-specific authenticated POSIX matrix."""

    document = _load_json_object(policy_path, "effective upgrade baseline policy")
    expected_fields = {
        "schema_version",
        "published_baselines",
        "published_baseline_config_versions",
        "platform_published_baselines",
    }
    versions = document.get("published_baselines")
    configs = document.get("published_baseline_config_versions")
    platforms = document.get("platform_published_baselines")
    windows = platforms.get("windows") if isinstance(platforms, dict) else None
    if (
        set(document) != expected_fields
        or document.get("schema_version") != 2
        or not isinstance(versions, list)
        or not versions
        or any(not isinstance(item, str) for item in versions)
        or len(versions) != len(set(versions))
        or versions != sorted(versions, key=_version_key, reverse=True)
        or not isinstance(configs, dict)
        or set(configs) != set(versions)
        or any(
            not isinstance(configs[version], int) or isinstance(configs[version], bool) or configs[version] < 1
            for version in versions
        )
        or not isinstance(platforms, dict)
        or set(platforms) != {"windows"}
        or not isinstance(windows, list)
        or any(
            not isinstance(version, str) or VERSION_RE.fullmatch(version) is None or version not in versions
            for version in windows
        )
        or len(windows) != len(set(windows))
        or windows != [version for version in versions if version in set(windows)]
    ):
        raise ReleasePreflightError("effective upgrade baseline policy is malformed")
    target_key = _version_key(target)
    older = [item for item in versions if _version_key(item) < target_key]
    if not older:
        raise ReleasePreflightError(f"no authenticated published baseline is older than target {target}")
    selected = [max(older, key=_version_key)]
    for anchor, label in (
        ("0.8.6", "field-recovery"),
        ("0.8.5", "hard-cut"),
        ("0.8.4", "bridge"),
    ):
        if _version_key(anchor) >= target_key:
            continue
        if anchor not in older:
            raise ReleasePreflightError(f"authenticated {label} baseline {anchor} is unavailable")
        if anchor not in selected:
            selected.append(anchor)
    for family in ((0, 7), (0, 6), (0, 5)):
        family_versions = [item for item in older if _version_key(item)[:2] == family]
        if not family_versions:
            raise ReleasePreflightError(f"authenticated {family[0]}.{family[1]}.x family baseline is unavailable")
        anchor = max(family_versions, key=_version_key)
        if anchor not in selected:
            selected.append(anchor)
    expected_lanes = 6 if target == "0.8.7" else 7
    if len(selected) != expected_lanes:
        raise ReleasePreflightError(
            f"target {target} requires exactly {expected_lanes} distinct POSIX release lanes; selected {len(selected)}"
        )
    if target_key > _version_key(WINDOWS_FRESH_INSTALL_ONLY_THROUGH):
        raise ReleasePreflightError(
            "native Windows upgrade certification is required after "
            f"{WINDOWS_FRESH_INSTALL_ONLY_THROUGH}; add the Windows upgrade lane before "
            f"releasing {target} (https://github.com/cisco-ai-defense/defenseclaw/issues/619)"
        )
    document["platform_published_baselines"]["windows"] = []
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ReleasePreflightError("this platform cannot safely persist the effective baseline policy")
    try:
        original = policy_path.lstat()
        if (
            not stat.S_ISREG(original.st_mode)
            or original.st_uid != os.geteuid()
            or original.st_nlink != 1
            or stat.S_IMODE(original.st_mode) & 0o022
        ):
            raise ReleasePreflightError("effective upgrade baseline policy is not in exclusive owner custody")
        descriptor = os.open(
            policy_path,
            os.O_WRONLY | no_follow | getattr(os, "O_CLOEXEC", 0),
        )
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (original.st_dev, original.st_ino)
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) & 0o022
            ):
                raise ReleasePreflightError("effective upgrade baseline policy custody changed while opening it")
            os.fchmod(stream.fileno(), 0o600)
            os.ftruncate(stream.fileno(), 0)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            persisted = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(persisted.st_mode)
                or (persisted.st_dev, persisted.st_ino) != (original.st_dev, original.st_ino)
                or persisted.st_uid != os.geteuid()
                or persisted.st_nlink != 1
                or stat.S_IMODE(persisted.st_mode) != 0o600
            ):
                raise ReleasePreflightError("effective upgrade baseline policy lost custody while persisting it")
        final = policy_path.lstat()
        if (
            not stat.S_ISREG(final.st_mode)
            or (final.st_dev, final.st_ino) != (original.st_dev, original.st_ino)
            or final.st_uid != os.geteuid()
            or final.st_nlink != 1
            or stat.S_IMODE(final.st_mode) != 0o600
        ):
            raise ReleasePreflightError("effective upgrade baseline policy path changed while persisting it")
    except OSError as exc:
        raise ReleasePreflightError(f"could not persist effective baseline policy: {exc}") from exc
    return selected


def _operator_git_state(*, runner: Runner = subprocess.run) -> tuple[str, str]:
    if _run(["git", "status", "--porcelain=v1", "--untracked-files=all"], runner=runner).strip():
        raise ReleasePreflightError("release preflight requires a clean worktree")
    branch = _run(["git", "symbolic-ref", "--quiet", "--short", "HEAD"], runner=runner).strip()
    if branch != "main":
        raise ReleasePreflightError(f"release preflight must run from local main, got {branch!r}")
    _run(["git", "fetch", "--no-tags", "origin", "main"], runner=runner)
    head = _run(["git", "rev-parse", "HEAD"], runner=runner).strip()
    remote = _run(["git", "rev-parse", "origin/main"], runner=runner).strip()
    if COMMIT_RE.fullmatch(head) is None or head != remote:
        raise ReleasePreflightError(
            f"local main must exactly match origin/main before dispatch (HEAD={head}, origin/main={remote})"
        )
    return head, branch


def _gh_authenticated_environment(*, runner: Runner = subprocess.run) -> dict[str, str]:
    environment = _sanitized_github_cli_environment(os.environ)
    token = _run(
        ["gh", "auth", "token", "--hostname", "github.com"],
        runner=runner,
        env=environment,
    ).strip()
    return _github_com_environment_with_token(token, environment=environment)


def _sanitized_github_cli_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """Remove ambient credential, interpreter, and trust selection."""

    sanitized = dict(environment)
    for variable in tuple(sanitized):
        folded = variable.casefold()
        if folded in GITHUB_CLI_UNTRUSTED_ENVIRONMENT_CASEFOLD or folded.startswith(
            GITHUB_CLI_UNTRUSTED_ENVIRONMENT_PREFIXES_CASEFOLD
        ):
            sanitized.pop(variable)
    # Proxy routing remains supported for proxy-only operator networks. Private
    # CA, TLS, GitHub-host, credential, and runtime overrides are removed, so
    # the proxy cannot replace the authenticated GitHub.com trust root.
    return sanitized


def _github_com_environment_with_token(
    token: str,
    *,
    environment: Mapping[str, str],
) -> dict[str, str]:
    """Bind an explicit credential to GitHub.com without ambient CLI routing."""

    sanitized = _sanitized_github_cli_environment(environment)
    if not token or len(token) > 4096 or any(character.isspace() for character in token):
        raise ReleasePreflightError("explicit GitHub.com token is missing or invalid")
    sanitized["GH_TOKEN"] = token
    return sanitized


def _environment_bound_runner(
    *,
    runner: Runner,
    environment: Mapping[str, str],
) -> Runner:
    """Bind every child invocation to one immutable, authenticated environment."""

    authenticated_environment = dict(environment)

    def bound_runner(
        command: Sequence[str],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str]:
        kwargs["env"] = dict(authenticated_environment)
        return runner(list(command), **kwargs)

    return bound_runner


def _dispatch_command(
    operation: str,
    version: str,
    *,
    repository: str,
    expected_commit: str,
) -> str:
    parts = [
        f"gh workflow run release.yaml --repo {repository} --ref main",
        f"  -f operation={operation}",
        f"  -f version={version}",
        f"  -f expected_commit={expected_commit}",
    ]
    if operation == "release":
        parts.append("  -f immutable_releases_confirmed=true")
    return " \\\n".join(parts)


def run_operator_preflight(
    *,
    operation: str,
    version: str,
    immutable_releases_confirmed: bool,
    repository: str = DEFAULT_REPOSITORY,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Run the non-mutating operator checks and return a dispatch plan."""

    _version_key(version)
    head, _branch = _operator_git_state(runner=runner)
    authenticated_environment = _gh_authenticated_environment(runner=runner)
    authenticated_runner = _environment_bound_runner(
        runner=runner,
        environment=authenticated_environment,
    )
    rulesets = fetch_release_channel_rulesets(repository, runner=authenticated_runner)
    effective_rules = fetch_effective_release_channel_rules(repository, runner=authenticated_runner)
    ruleset_id, ruleset_name = validate_request(
        operation=operation,
        version=version,
        repository=repository,
        ref="refs/heads/main",
        commit=head,
        expected_commit=head,
        immutable_releases_confirmed=immutable_releases_confirmed,
        rulesets=rulesets,
        effective_rules=effective_rules,
        require_publisher_bypass=False,
    )
    api = release_api_retry.GitHubReleaseAPI(repository=repository, runner=authenticated_runner)
    baselines: list[str] = []
    target_commit = head
    if operation == "release":
        release_api_retry.require_releasable_namespace(
            api,
            tag=version,
            expected_commit=head,
        )
        releases = api.release_rows()
        with tempfile.TemporaryDirectory(prefix="defenseclaw-release-preflight-") as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            inventory = root / "published-releases.json"
            inventory.write_text(json.dumps(releases), encoding="utf-8")
            os.chmod(inventory, 0o600)
            release_candidate.validate_release_progression(version, inventory)
            effective = root / "effective-upgrade-baselines.json"
            _run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "resolve_upgrade_baselines.py"),
                    "--target-version",
                    version,
                    "--output",
                    str(effective),
                    "--repository",
                    repository,
                ],
                runner=authenticated_runner,
            )
            baselines = select_upgrade_baselines(policy_path=effective, target=version)
    else:
        tag_payload = api.tag_ref(version)
        if tag_payload is None:
            raise ReleasePreflightError(f"repair target {version!r} has no tag ref")
        target_commit = api.resolve_tag_commit(tag_payload)
        release_api_retry.require_latest_immutable_release(
            api,
            tag=version,
            expected_commit=target_commit,
        )
    return {
        "schema_version": 1,
        "operation": operation,
        "version": version,
        "workflow_commit": head,
        "target_commit": target_commit,
        "release_channel_ruleset": {
            "id": ruleset_id,
            "name": ruleset_name,
        },
        "posix_upgrade_baselines": baselines,
        "dispatch_command": _dispatch_command(
            operation,
            version,
            repository=repository,
            expected_commit=head,
        ),
    }


def _common_request_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--operation", choices=("release", "repair-channel"), default="release")
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument(
        "--immutable-releases-confirmed",
        type=_boolean,
        choices=(True, False),
        default=False,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    request = commands.add_parser("request", help="validate workflow request and live channel rules")
    _common_request_arguments(request)
    request.add_argument("--ref", required=True)
    request.add_argument("--commit", required=True)
    request.add_argument("--expected-commit", required=True)
    operator = commands.add_parser("operator", help="run full local operator preflight")
    _common_request_arguments(operator)
    ruleset_admin = commands.add_parser(
        "ruleset-admin-audit",
        help="require the complete organization ruleset and sole publisher bypass",
    )
    ruleset_admin.add_argument("--repository", default=DEFAULT_REPOSITORY)
    select = commands.add_parser("select-baselines", help="select the authenticated POSIX matrix")
    select.add_argument("--policy", type=Path, required=True)
    select.add_argument("--version", required=True)
    select.add_argument("--github-output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "request":
            request_environment = _github_com_environment_with_token(
                os.environ.get("GH_TOKEN", ""),
                environment=os.environ,
            )
            request_runner = _environment_bound_runner(
                runner=subprocess.run,
                environment=request_environment,
            )
            rulesets = fetch_release_channel_rulesets(args.repository, runner=request_runner)
            effective_rules = fetch_effective_release_channel_rules(args.repository, runner=request_runner)
            identifier, name = validate_request(
                operation=args.operation,
                version=args.version,
                repository=args.repository,
                ref=args.ref,
                commit=args.commit,
                expected_commit=args.expected_commit,
                immutable_releases_confirmed=args.immutable_releases_confirmed,
                rulesets=rulesets,
                effective_rules=effective_rules,
                require_publisher_bypass=False,
            )
            print(f"release request and release-channel ruleset are valid: {name} ({identifier})")
            return 0
        if args.command == "select-baselines":
            selected = select_upgrade_baselines(policy_path=args.policy, target=args.version)
            compact = json.dumps(selected, separators=(",", ":"))
            if args.github_output is not None:
                with args.github_output.open("a", encoding="utf-8") as output:
                    output.write(f"upgrade_baselines={compact}\n")
            print(compact)
            return 0
        if args.command == "ruleset-admin-audit":
            admin_environment = _gh_authenticated_environment(runner=subprocess.run)
            admin_runner = _environment_bound_runner(
                runner=subprocess.run,
                environment=admin_environment,
            )
            rulesets = fetch_release_channel_rulesets(args.repository, runner=admin_runner)
            effective_rules = fetch_effective_release_channel_rules(args.repository, runner=admin_runner)
            identifier, name = validate_release_channel_rulesets(
                rulesets,
                effective_rules=effective_rules,
            )
            print(f"release-channel ruleset is fully valid: {name} ({identifier})")
            return 0
        plan = run_operator_preflight(
            operation=args.operation,
            version=args.version,
            immutable_releases_confirmed=args.immutable_releases_confirmed,
            repository=args.repository,
        )
        print(json.dumps(plan, indent=2, sort_keys=True))
        print("\nReady to dispatch manually:\n")
        print(plan["dispatch_command"])
        return 0
    except (
        OSError,
        release_api_retry.ReleaseAPIError,
        release_candidate.CandidateError,
        ReleasePreflightError,
        ValueError,
    ) as exc:
        print(f"release preflight failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
