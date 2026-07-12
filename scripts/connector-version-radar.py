#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Discover untested stable connector releases without modifying installations.

The radar intentionally has a small scope: the three CLI connectors exercised by
the dedicated macOS connector lab.  It probes installed binaries, queries the
upstream stable release channels, and keeps attempted/passed history in a
caller-supplied machine-local state file.  It never changes an installed tool and
never edits ``validated_versions.json``.

``check`` writes one JSON document to stdout.  An optional fixture file makes the
whole discovery path hermetic for tests and local workflow development::

    {
      "codex": {
        "installed": "codex-cli 0.142.5",
        "latest": "0.144.1"
      },
      "claudecode": {
        "installed": {"stdout": "2.1.207 (Claude Code)", "returncode": 0},
        "latest": {"stdout": "\"2.1.208\"", "returncode": 0}
      },
      "antigravity": {
        "installed": "1.1.1",
        "latest": "{\"version\": \"1.1.2\"}"
      }
    }

When ``--fixture`` is present, a missing fixture is an infrastructure error; the
radar never falls through to a real command or network request.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
EXIT_OK = 0
EXIT_INFRASTRUCTURE_ERROR = 2
DEFAULT_TIMEOUT_SECONDS = 20.0
ANTIGRAVITY_MANIFEST_BASE = (
    "https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests"
)
CONNECTOR_ORDER = ("codex", "claudecode", "antigravity")
_VERSION_RE = re.compile(
    r"(?<![0-9A-Za-z])v?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?:-(?P<prerelease>[0-9A-Za-z.-]+))?"
    r"(?:\+(?P<build>[0-9A-Za-z.-]+))?(?![0-9A-Za-z])"
)
_PLATFORM_RE = re.compile(r"^[a-z0-9_]+$")


class RadarError(RuntimeError):
    """An infrastructure/configuration error that is not a connector regression."""


@dataclasses.dataclass(frozen=True)
class ConnectorSpec:
    name: str
    executable: str
    installed_command: tuple[str, ...]
    npm_package: str | None = None


SPECS: dict[str, ConnectorSpec] = {
    "codex": ConnectorSpec(
        name="codex",
        executable="codex",
        installed_command=("codex", "--version"),
        npm_package="@openai/codex",
    ),
    "claudecode": ConnectorSpec(
        name="claudecode",
        executable="claude",
        installed_command=("claude", "--version"),
        npm_package="@anthropic-ai/claude-code",
    ),
    "antigravity": ConnectorSpec(
        name="antigravity",
        executable="agy",
        installed_command=("agy", "--version"),
    ),
}


@dataclasses.dataclass(frozen=True)
class SemVersion:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()

    @property
    def stable(self) -> bool:
        return not self.prerelease

    @property
    def normalized(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            return f"{base}-{'.'.join(self.prerelease)}"
        return base

    def compare(self, other: SemVersion) -> int:
        own_core = (self.major, self.minor, self.patch)
        other_core = (other.major, other.minor, other.patch)
        if own_core != other_core:
            return 1 if own_core > other_core else -1
        if not self.prerelease and not other.prerelease:
            return 0
        if not self.prerelease:
            return 1
        if not other.prerelease:
            return -1
        for own, theirs in zip(self.prerelease, other.prerelease, strict=False):
            if own == theirs:
                continue
            own_numeric = own.isdigit()
            theirs_numeric = theirs.isdigit()
            if own_numeric and theirs_numeric:
                return 1 if int(own) > int(theirs) else -1
            if own_numeric != theirs_numeric:
                return -1 if own_numeric else 1
            return 1 if own > theirs else -1
        if len(self.prerelease) == len(other.prerelease):
            return 0
        return 1 if len(self.prerelease) > len(other.prerelease) else -1


@dataclasses.dataclass(frozen=True)
class ExternalResult:
    ok: bool
    stdout: str = ""
    error: str = ""


CommandRunner = Callable[[Sequence[str], float], ExternalResult]
URLFetcher = Callable[[str, float], ExternalResult]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_version(value: str, *, require_stable: bool = False) -> SemVersion:
    """Extract and normalize the first semantic version in command/JSON output."""

    match = _VERSION_RE.search(value.strip())
    if not match:
        raise ValueError("no semantic x.y.z version found")
    prerelease = tuple(filter(None, (match.group("prerelease") or "").split(".")))
    parsed = SemVersion(
        major=int(match.group("major")),
        minor=int(match.group("minor")),
        patch=int(match.group("patch")),
        prerelease=prerelease,
    )
    if require_stable and not parsed.stable:
        raise ValueError(f"stable channel returned prerelease {parsed.normalized}")
    return parsed


def run_command(command: Sequence[str], timeout: float) -> ExternalResult:
    """Run a read-only version query and convert execution failures to data."""

    try:
        proc = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError:
        return ExternalResult(False, error=f"executable not found: {command[0]}")
    except subprocess.TimeoutExpired:
        return ExternalResult(False, error=f"command timed out after {timeout:g}s: {command[0]}")
    except OSError as exc:
        return ExternalResult(False, error=f"could not execute {command[0]}: {exc}")

    if proc.returncode != 0:
        detail = _short_error(proc.stderr or proc.stdout or "no diagnostic output")
        return ExternalResult(False, error=f"{command[0]} exited {proc.returncode}: {detail}")
    return ExternalResult(True, stdout=proc.stdout.strip())


def fetch_url(url: str, timeout: float) -> ExternalResult:
    """Fetch release metadata only; downloaded agent payloads are never requested."""

    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "DefenseClaw-Connector-Radar/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed HTTPS origin
            return ExternalResult(True, stdout=response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, UnicodeError, OSError) as exc:
        return ExternalResult(False, error=f"release metadata request failed: {_short_error(str(exc))}")


def _short_error(value: str, limit: int = 400) -> str:
    flattened = " ".join(value.split())
    return flattened[:limit] + ("..." if len(flattened) > limit else "")


def antigravity_platform() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch_aliases = {
        "arm64": "arm64",
        "aarch64": "arm64",
        "x86_64": "amd64",
        "amd64": "amd64",
    }
    arch = arch_aliases.get(machine)
    if not arch:
        raise RadarError(f"unsupported Antigravity architecture: {machine or 'unknown'}")
    if system == "darwin":
        return f"darwin_{arch}"
    if system == "linux":
        libc_name = platform.libc_ver()[0].lower()
        musl = libc_name == "musl" or any(
            Path(path).exists()
            for path in ("/lib/libc.musl-x86_64.so.1", "/lib/libc.musl-aarch64.so.1")
        )
        return f"linux_{arch}{'_musl' if musl else ''}"
    if system == "windows":
        return f"windows_{arch}"
    raise RadarError(f"unsupported Antigravity operating system: {system or 'unknown'}")


def load_fixture(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RadarError(f"could not read fixture {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RadarError(f"fixture {path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise RadarError("fixture root must be a JSON object")
    connectors = payload.get("connectors", payload)
    if not isinstance(connectors, dict):
        raise RadarError("fixture connectors must be a JSON object")
    return connectors


def fixture_result(fixtures: Mapping[str, Any], connector: str, stage: str) -> ExternalResult:
    connector_fixture = fixtures.get(connector)
    if not isinstance(connector_fixture, Mapping) or stage not in connector_fixture:
        return ExternalResult(False, error=f"fixture missing {connector}.{stage}")
    value = connector_fixture[stage]
    if isinstance(value, str):
        return ExternalResult(True, stdout=value)
    if not isinstance(value, Mapping):
        return ExternalResult(False, error=f"fixture {connector}.{stage} must be a string or object")
    if value.get("error"):
        return ExternalResult(False, error=_short_error(str(value["error"])))
    try:
        returncode = int(value.get("returncode", 0))
    except (TypeError, ValueError):
        return ExternalResult(False, error=f"fixture {connector}.{stage}.returncode must be an integer")
    stdout = str(value.get("stdout", ""))
    if returncode:
        detail = _short_error(str(value.get("stderr", stdout or "fixture failure")))
        return ExternalResult(False, error=f"fixture returned {returncode}: {detail}")
    return ExternalResult(True, stdout=stdout)


def query_installed(
    spec: ConnectorSpec,
    *,
    timeout: float,
    command_runner: CommandRunner,
    fixtures: Mapping[str, Any] | None,
) -> ExternalResult:
    if fixtures is not None:
        return fixture_result(fixtures, spec.name, "installed")
    return command_runner(spec.installed_command, timeout)


def query_latest(
    spec: ConnectorSpec,
    *,
    timeout: float,
    command_runner: CommandRunner,
    url_fetcher: URLFetcher,
    fixtures: Mapping[str, Any] | None,
    antigravity_platform_name: str,
) -> tuple[ExternalResult, str]:
    if fixtures is not None:
        result = fixture_result(fixtures, spec.name, "latest")
        return result, "fixture"
    if spec.npm_package:
        command = ("npm", "view", spec.npm_package, "dist-tags.latest", "--json")
        return command_runner(command, timeout), f"npm:{spec.npm_package}:dist-tags.latest"
    manifest_url = f"{ANTIGRAVITY_MANIFEST_BASE}/{antigravity_platform_name}.json"
    return url_fetcher(manifest_url, timeout), manifest_url


def _latest_version_from_output(spec: ConnectorSpec, output: str) -> SemVersion:
    value: Any = output
    try:
        parsed_json = json.loads(output)
    except json.JSONDecodeError:
        parsed_json = None
    if spec.name == "antigravity":
        if isinstance(parsed_json, dict):
            value = parsed_json.get("version", "")
        elif isinstance(parsed_json, str):
            value = parsed_json
        elif parsed_json is not None:
            raise ValueError("Antigravity release metadata did not contain an object or string")
    elif isinstance(parsed_json, str):
        value = parsed_json
    elif parsed_json is not None:
        raise ValueError("npm dist-tags.latest did not return a JSON string")
    if not isinstance(value, str):
        raise ValueError("release metadata did not contain a string version")
    return parse_version(value, require_stable=True)


def empty_state() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "connectors": {}}


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return empty_state()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RadarError(f"could not read state {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RadarError(f"state {path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise RadarError("state root must be a JSON object")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise RadarError(
            f"unsupported state schema_version {payload.get('schema_version')!r}; expected {SCHEMA_VERSION}"
        )
    if not isinstance(payload.get("connectors"), dict):
        raise RadarError("state connectors must be a JSON object")
    version_fields = (
        "installed_seed_version",
        "last_seen_installed_version",
        "last_attempted_version",
        "last_passed_version",
    )
    for connector, entry in payload["connectors"].items():
        if not isinstance(connector, str) or not isinstance(entry, dict):
            raise RadarError("each state connector must map a string name to a JSON object")
        for field in version_fields:
            if field not in entry:
                continue
            value = entry[field]
            if not isinstance(value, str):
                raise RadarError(f"state {connector}.{field} must be a semantic-version string")
            try:
                parse_version(value)
            except ValueError as exc:
                raise RadarError(f"state {connector}.{field} is invalid: {exc}") from exc
    return payload


def atomic_write_json(path: Path, payload: Any, *, mode: int = 0o600) -> None:
    """Atomically replace a JSON file and keep machine-local state private."""

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _state_version(entry: Mapping[str, Any], key: str) -> str:
    value = entry.get(key, "")
    if not value:
        return ""
    if not isinstance(value, str):
        raise RadarError(f"state field {key} must be a semantic-version string")
    try:
        return parse_version(value).normalized
    except ValueError as exc:
        raise RadarError(f"state field {key} is invalid: {exc}") from exc


def check_radar(
    *,
    state_path: Path,
    connector_names: Sequence[str] = CONNECTOR_ORDER,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    command_runner: CommandRunner = run_command,
    url_fetcher: URLFetcher = fetch_url,
    fixtures: Mapping[str, Any] | None = None,
    antigravity_platform_name: str | None = None,
    force: bool = False,
    now: str | None = None,
) -> dict[str, Any]:
    """Collect version data, persist last-seen state, and return the radar document."""

    state = load_state(state_path)
    state_connectors = state["connectors"]
    generated_at = now or utc_now()
    platform_name = antigravity_platform_name
    if "antigravity" in connector_names and platform_name is None:
        try:
            platform_name = antigravity_platform()
        except RadarError as exc:
            platform_name = ""
            platform_error = str(exc)
        else:
            platform_error = ""
    else:
        platform_error = ""
    if platform_name and not _PLATFORM_RE.fullmatch(platform_name):
        raise RadarError("Antigravity platform may contain only lowercase letters, digits, and underscores")

    connector_results: dict[str, Any] = {}
    candidates: list[dict[str, str]] = []
    infrastructure_errors: list[dict[str, str]] = []

    for connector in connector_names:
        spec = SPECS[connector]
        entry = state_connectors.setdefault(connector, {})
        if not isinstance(entry, dict):
            entry = {}
            state_connectors[connector] = entry

        installed_result = query_installed(
            spec,
            timeout=timeout,
            command_runner=command_runner,
            fixtures=fixtures,
        )
        installed_version = ""
        installed_error = installed_result.error
        if installed_result.ok:
            try:
                installed_version = parse_version(installed_result.stdout).normalized
            except ValueError as exc:
                installed_error = f"could not parse `{spec.executable} --version`: {exc}"

        if installed_version:
            if not entry.get("installed_seed_version"):
                entry["installed_seed_version"] = installed_version
                entry["installed_seeded_at"] = generated_at
            entry["last_seen_installed_version"] = installed_version
            entry["last_seen_installed_at"] = generated_at

        if connector == "antigravity" and platform_error:
            latest_result = ExternalResult(False, error=platform_error)
            latest_source = "official Antigravity release manifest"
        else:
            latest_result, latest_source = query_latest(
                spec,
                timeout=timeout,
                command_runner=command_runner,
                url_fetcher=url_fetcher,
                fixtures=fixtures,
                antigravity_platform_name=platform_name or "",
            )
        latest_version = ""
        latest_error = latest_result.error
        if latest_result.ok:
            try:
                latest_version = _latest_version_from_output(spec, latest_result.stdout).normalized
            except ValueError as exc:
                latest_error = f"could not parse latest stable version: {exc}"

        previous_attempted = _state_version(entry, "last_attempted_version")
        previous_passed = _state_version(entry, "last_passed_version")
        baseline_version = previous_passed or installed_version
        needs_test = False
        status = "current"

        if installed_error:
            status = "infrastructure_error"
            infrastructure_errors.append(
                {"connector": connector, "stage": "installed_probe", "error": installed_error}
            )
        if latest_error:
            status = "infrastructure_error"
            infrastructure_errors.append(
                {"connector": connector, "stage": "latest_query", "error": latest_error}
            )

        if not installed_error and not latest_error:
            installed_semver = parse_version(installed_version)
            latest_semver = parse_version(latest_version)
            if force:
                needs_test = True
                status = "forced_test_required"
                candidates.append(
                    {
                        "connector": connector,
                        "baseline_version": baseline_version,
                        "installed_version": installed_version,
                        "candidate_version": latest_version,
                    }
                )
            elif latest_semver.compare(installed_semver) < 0:
                status = "installed_ahead"
            elif previous_attempted == latest_version:
                status = "tested_passed" if previous_passed == latest_version else "already_attempted"
            else:
                attempted_semver = parse_version(previous_attempted) if previous_attempted else None
                if attempted_semver is not None and latest_semver.compare(attempted_semver) < 0:
                    status = "latest_older_than_attempted"
                else:
                    needs_test = True
                    status = (
                        "update_available"
                        if latest_semver.compare(installed_semver) > 0
                        else "initial_test_required"
                    )
                    candidates.append(
                        {
                            "connector": connector,
                            "baseline_version": baseline_version,
                            "installed_version": installed_version,
                            "candidate_version": latest_version,
                        }
                    )

        connector_results[connector] = {
            "status": status,
            "needs_test": needs_test,
            "baseline_version": baseline_version or None,
            "installed": {
                "status": "ok" if installed_version else "error",
                "version": installed_version or None,
                "source": " ".join(spec.installed_command),
                "error": installed_error or None,
            },
            "latest": {
                "status": "ok" if latest_version else "error",
                "version": latest_version or None,
                "stable": bool(latest_version),
                "source": latest_source,
                "error": latest_error or None,
            },
            "state": {
                "installed_seed_version": entry.get("installed_seed_version"),
                "last_attempted_version": previous_attempted or None,
                "last_passed_version": previous_passed or None,
            },
        }

    state["updated_at"] = generated_at
    try:
        atomic_write_json(state_path, state)
    except OSError as exc:
        raise RadarError(f"could not persist state {state_path}: {exc}") from exc

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "status": "infrastructure_error" if infrastructure_errors else "ok",
        "forced": force,
        "any_new": bool(candidates),
        "has_candidates": bool(candidates),
        "candidates": candidates,
        "infrastructure_errors": infrastructure_errors,
        "connectors": connector_results,
    }


def mark_state(
    *,
    state_path: Path,
    connector: str,
    version: str,
    result: str,
    now: str | None = None,
) -> dict[str, Any]:
    """Persist a candidate attempt or a successful live certification run."""

    normalized = parse_version(version).normalized
    timestamp = now or utc_now()
    state = load_state(state_path)
    entry = state["connectors"].setdefault(connector, {})
    if not isinstance(entry, dict):
        entry = {}
        state["connectors"][connector] = entry
    entry["last_attempted_version"] = normalized
    entry["last_attempted_at"] = timestamp
    if result == "passed":
        entry["last_passed_version"] = normalized
        entry["last_passed_at"] = timestamp
    state["updated_at"] = timestamp
    try:
        atomic_write_json(state_path, state)
    except OSError as exc:
        raise RadarError(f"could not persist state {state_path}: {exc}") from exc
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "ok",
        "connector": connector,
        "version": normalized,
        "result": result,
        "recorded_at": timestamp,
    }


def write_github_outputs(path: Path, payload: Mapping[str, Any]) -> None:
    candidates = payload.get("candidates", [])
    errors = payload.get("infrastructure_errors", [])
    matrix = {"include": candidates}
    outputs = {
        "status": payload.get("status", "infrastructure_error"),
        "any_new": str(bool(candidates)).lower(),
        "has_candidates": str(bool(candidates)).lower(),
        "candidate_connectors": json.dumps(
            [item["connector"] for item in candidates], separators=(",", ":")
        ),
        "candidate_matrix": json.dumps(matrix, separators=(",", ":")),
        "matrix": json.dumps(matrix, separators=(",", ":")),
        "has_infrastructure_errors": str(bool(errors)).lower(),
        "infrastructure_error_connectors": json.dumps(
            sorted({item.get("connector", "radar") for item in errors}), separators=(",", ":")
        ),
        "radar_json": json.dumps(payload, sort_keys=True, separators=(",", ":")),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for key, value in outputs.items():
            handle.write(f"{key}={value}\n")


def infrastructure_payload(message: str, *, now: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now or utc_now(),
        "status": "infrastructure_error",
        "forced": False,
        "any_new": False,
        "has_candidates": False,
        "candidates": [],
        "infrastructure_errors": [{"connector": "radar", "stage": "configuration", "error": message}],
        "connectors": {},
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="Query installed and latest stable connector versions.")
    check.add_argument("--state", required=True, type=Path, help="Machine-local attempted/passed state JSON path.")
    check.add_argument("--output", type=Path, help="Also atomically write the full radar JSON to this path.")
    check.add_argument(
        "--github-output",
        type=Path,
        default=Path(os.environ["GITHUB_OUTPUT"]) if os.environ.get("GITHUB_OUTPUT") else None,
        help="Append compact outputs to this GitHub Actions output file (default: $GITHUB_OUTPUT).",
    )
    check.add_argument("--fixture", type=Path, help="Hermetic installed/latest responses; disables real queries.")
    check.add_argument(
        "--connector",
        action="append",
        choices=CONNECTOR_ORDER,
        dest="connectors",
        help="Limit discovery to a connector (repeatable; default: all three).",
    )
    check.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    check.add_argument(
        "--force",
        action="store_true",
        help="Schedule all successfully queried selected connectors, even if already attempted.",
    )
    check.add_argument(
        "--antigravity-platform",
        help="Override the official manifest platform name (for example darwin_arm64).",
    )

    mark = subparsers.add_parser("mark", help="Record that a candidate was attempted or passed live tests.")
    mark.add_argument("--state", required=True, type=Path)
    mark.add_argument("--connector", required=True, choices=CONNECTOR_ORDER)
    mark.add_argument("--version", required=True)
    mark.add_argument("--result", required=True, choices=("attempted", "passed"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "mark":
        try:
            payload = mark_state(
                state_path=args.state,
                connector=args.connector,
                version=args.version,
                result=args.result,
            )
        except (RadarError, ValueError) as exc:
            payload = infrastructure_payload(str(exc))
            print(json.dumps(payload, sort_keys=True))
            return EXIT_INFRASTRUCTURE_ERROR
        print(json.dumps(payload, sort_keys=True))
        return EXIT_OK

    if args.timeout <= 0:
        payload = infrastructure_payload("--timeout must be greater than zero")
        print(json.dumps(payload, sort_keys=True))
        return EXIT_INFRASTRUCTURE_ERROR

    try:
        fixtures = load_fixture(args.fixture)
        payload = check_radar(
            state_path=args.state,
            connector_names=args.connectors or CONNECTOR_ORDER,
            timeout=args.timeout,
            fixtures=fixtures,
            antigravity_platform_name=args.antigravity_platform,
            force=args.force,
        )
    except RadarError as exc:
        payload = infrastructure_payload(str(exc))

    if args.output:
        try:
            atomic_write_json(args.output, payload, mode=0o644)
        except OSError as exc:
            payload = infrastructure_payload(f"could not write radar output {args.output}: {exc}")
    if args.github_output:
        try:
            write_github_outputs(args.github_output, payload)
        except OSError as exc:
            payload = infrastructure_payload(f"could not write GitHub outputs {args.github_output}: {exc}")

    print(json.dumps(payload, sort_keys=True))
    return EXIT_OK if payload["status"] == "ok" else EXIT_INFRASTRUCTURE_ERROR


if __name__ == "__main__":
    sys.exit(main())
