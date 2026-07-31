#!/usr/bin/env python3
"""Fail closed unless a durable macOS Codex release-evidence manifest is complete."""

from __future__ import annotations

import argparse
import json
import platform
import re
import sys
from pathlib import Path

SHA256 = re.compile(r"^[0-9a-f]{64}$")
FILE_MODE = re.compile(r"^0[0-7]{3}$")
REQUIRED_RESULTS = {
    "packaged_setup",
    "authenticated_live",
    "action_block_visible",
    "doctor_clean",
    "teardown_exact_restore",
    "hook_events",
    "notify_event",
    "native_otlp",
    "audit_correlation",
}
REQUIRED_ARTIFACTS = {
    "results.jsonl",
    "audit.db",
    "setup.log",
    "status.log",
    "doctor.log",
    "restoration.json",
    "provenance.json",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate(payload: object, expected_version: str) -> None:
    require(isinstance(payload, dict), "manifest root must be an object")
    assert isinstance(payload, dict)
    require(payload.get("schema_version") == 1, "schema_version must be 1")
    require(payload.get("connector") == "codex", "connector must be codex")
    require(payload.get("os") == "macos", "os must be macos")
    require(payload.get("requested_version") == "latest", "run must request latest")
    require(payload.get("resolved_version") == expected_version, "resolved version is not current")
    require(payload.get("authenticated") is True, "official-client run was not authenticated")

    package = payload.get("package")
    require(isinstance(package, dict), "package evidence is missing")
    assert isinstance(package, dict)
    require(package.get("name") == "@openai/codex", "unexpected package name")
    require(package.get("version") == expected_version, "package version mismatch")
    require(bool(package.get("integrity")), "package registry integrity is missing")

    native = payload.get("native")
    require(isinstance(native, dict), "native executable evidence is missing")
    assert isinstance(native, dict)
    require(native.get("macho") is True, "selected executable is not proven Mach-O")
    host_arch = platform.machine().lower()
    expected_arch = "arm64" if host_arch in {"arm64", "aarch64"} else "x86_64"
    require(native.get("architecture") == expected_arch, "native architecture does not match the host")
    require(native.get("codesign_valid") is True, "strict code signature check did not pass")
    require(native.get("identifier") == "codex", "unexpected code-signing identifier")
    require(native.get("team_identifier") == "2DC432GLL2", "unexpected signing team")
    require(native.get("quarantined") is False, "selected executable is quarantined")
    require(
        isinstance(native.get("sha256"), str) and bool(SHA256.fullmatch(native["sha256"])),
        "native executable SHA-256 is missing or invalid",
    )

    results = payload.get("results")
    require(isinstance(results, dict), "results object is missing")
    assert isinstance(results, dict)
    missing = sorted(REQUIRED_RESULTS - results.keys())
    require(not missing, f"required results are missing: {', '.join(missing)}")
    failed = sorted(name for name in REQUIRED_RESULTS if results.get(name) != "pass")
    require(not failed, f"required results did not pass: {', '.join(failed)}")

    restoration = payload.get("restoration")
    require(isinstance(restoration, dict), "restoration evidence is missing")
    assert isinstance(restoration, dict)
    require(
        restoration.get("before_sha256") == restoration.get("after_sha256")
        and isinstance(restoration.get("before_sha256"), str)
        and bool(SHA256.fullmatch(restoration["before_sha256"])),
        "Codex config was not restored byte-for-byte",
    )
    before_mode = restoration.get("before_mode")
    after_mode = restoration.get("after_mode")
    require(
        isinstance(before_mode, str)
        and bool(FILE_MODE.fullmatch(before_mode))
        and before_mode == after_mode,
        "Codex config mode was not restored exactly",
    )

    artifacts = payload.get("artifacts")
    require(isinstance(artifacts, dict) and bool(artifacts), "durable artifact hashes are missing")
    assert isinstance(artifacts, dict)
    missing_artifacts = sorted(REQUIRED_ARTIFACTS - artifacts.keys())
    require(not missing_artifacts, f"required artifacts are missing: {', '.join(missing_artifacts)}")
    for name, digest in artifacts.items():
        require(
            isinstance(name, str)
            and bool(name)
            and isinstance(digest, str)
            and bool(SHA256.fullmatch(digest)),
            "every artifact must have a name and SHA-256",
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    validate(json.loads(args.manifest.read_text(encoding="utf-8")), args.expected_version)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"macOS Codex evidence assertion failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
