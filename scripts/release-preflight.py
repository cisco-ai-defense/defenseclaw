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

"""Validate workflow requests and optionally preview DefenseClaw releases.

The release workflow remains the publication authority. A manual dispatch from
``main`` is automatically bound to GitHub's immutable ``github.sha``; operators
do not copy commit IDs or attest to repository settings. The optional operator
command previews the remote namespace and authenticated upgrade baselines, then
prints the same simple dispatch command. It never dispatches or mutates a
release.
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
WINDOWS_FRESH_INSTALL_ONLY_THROUGH = "0.8.8"
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
Runner = Callable[..., subprocess.CompletedProcess[str]]


class ReleasePreflightError(RuntimeError):
    """The release request is not ready for a production dispatch."""


def _version_key(value: object) -> tuple[int, int, int]:
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise ReleasePreflightError(f"version must be canonical X.Y.Z without a v prefix: {value!r}")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleasePreflightError(f"could not read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleasePreflightError(f"{label} must contain a JSON object")
    return value


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


def validate_request(
    *,
    operation: str,
    version: str,
    repository: str,
    ref: str,
    commit: str,
) -> None:
    """Validate the request GitHub bound to the selected ``main`` commit."""

    _version_key(version)
    if operation not in {"release", "repair-channel"}:
        raise ReleasePreflightError(f"unsupported release operation: {operation!r}")
    if repository != DEFAULT_REPOSITORY:
        raise ReleasePreflightError(f"release repository must be exactly {DEFAULT_REPOSITORY}, got {repository!r}")
    if ref != "refs/heads/main":
        raise ReleasePreflightError(f"release operations must run from refs/heads/main, got {ref!r}")
    if COMMIT_RE.fullmatch(commit) is None:
        raise ReleasePreflightError("release commit must be an exact lowercase 40-character SHA")


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
) -> str:
    parts = [
        f"gh workflow run release.yaml --repo {repository} --ref main",
        f"  -f operation={operation}",
        f"  -f version={version}",
    ]
    return " \\\n".join(parts)


def run_operator_preflight(
    *,
    operation: str,
    version: str,
    repository: str = DEFAULT_REPOSITORY,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Optionally preview the non-mutating remote checks and dispatch command."""

    _version_key(version)
    head, _branch = _operator_git_state(runner=runner)
    validate_request(
        operation=operation,
        version=version,
        repository=repository,
        ref="refs/heads/main",
        commit=head,
    )
    authenticated_environment = _gh_authenticated_environment(runner=runner)
    authenticated_runner = _environment_bound_runner(
        runner=runner,
        environment=authenticated_environment,
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
        "posix_upgrade_baselines": baselines,
        "dispatch_command": _dispatch_command(
            operation,
            version,
            repository=repository,
        ),
    }


def _common_request_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--operation", choices=("release", "repair-channel"), default="release")
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    request = commands.add_parser("request", help="validate the workflow request")
    _common_request_arguments(request)
    request.add_argument("--ref", required=True)
    request.add_argument("--commit", required=True)
    operator = commands.add_parser("operator", help="optionally preview a release dispatch")
    _common_request_arguments(operator)
    select = commands.add_parser("select-baselines", help="select the authenticated POSIX matrix")
    select.add_argument("--policy", type=Path, required=True)
    select.add_argument("--version", required=True)
    select.add_argument("--github-output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "request":
            validate_request(
                operation=args.operation,
                version=args.version,
                repository=args.repository,
                ref=args.ref,
                commit=args.commit,
            )
            print(f"release request is valid: {args.operation} {args.version} at {args.commit}")
            return 0
        if args.command == "select-baselines":
            selected = select_upgrade_baselines(policy_path=args.policy, target=args.version)
            compact = json.dumps(selected, separators=(",", ":"))
            if args.github_output is not None:
                with args.github_output.open("a", encoding="utf-8") as output:
                    output.write(f"upgrade_baselines={compact}\n")
            print(compact)
            return 0
        plan = run_operator_preflight(
            operation=args.operation,
            version=args.version,
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
