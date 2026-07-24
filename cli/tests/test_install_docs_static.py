# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from defenseclaw import install_publish

ROOT = Path(__file__).resolve().parents[2]
CURRENT_RELEASE = "0.8.6"
STALE_RELEASES = ("0.8.0", "0.8.1", "0.8.2", "0.8.3", "0.8.4", "0.8.5")

BASH_INSTALL_LINES = (
    f"VERSION={CURRENT_RELEASE}",
    'INSTALL_URL="https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${VERSION}/scripts/install.sh"',
    'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash',
)
DOC_INSTALL_COMMANDS = {
    "README.md": BASH_INSTALL_LINES,
    "docs/QUICKSTART.md": BASH_INSTALL_LINES,
    "docs/INSTALL.md": BASH_INSTALL_LINES
    + (
        'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector codex',
        'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector claudecode',
        'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector zeptoclaw',
        'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector none',
        'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --no-openclaw',
    ),
    "docs-site/content/docs/get-started/install.mdx": BASH_INSTALL_LINES
    + (
        ".\\DefenseClawSetup-x64.exe",
        ".\\DefenseClawSetup-x64.exe /quiet /norestart INSTALLSCOPE=user CONNECTOR=codex MODE=observe STARTGATEWAY=1",
        "after download it does not require Python, `uv`, Go, Node.js, Git, or a",
        "PowerShell installation command.",
    ),
    "docs-site/content/docs/get-started/first-guardrail.mdx": (
        f"VERSION={CURRENT_RELEASE}",
        'INSTALL_URL="https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${VERSION}/scripts/install.sh"',
        'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector claudecode',
    ),
    "docs-site/components/terminal-demo.tsx": (
        f"const INSTALL_VERSION = '{CURRENT_RELEASE}';",
        "text: `curl -LsSf https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${INSTALL_VERSION}/scripts/install.sh | VERSION=${INSTALL_VERSION} bash`,",
    ),
}
RELEASE_INSTALL_COMMANDS = {
    **DOC_INSTALL_COMMANDS,
    "scripts/install.sh": BASH_INSTALL_LINES,
}

INSTALLER_FILES = (
    "scripts/install.sh",
    "scripts/install.ps1",
)

OBSERVABILITY_V8_CURRENT_AUTHORITY_FILES = (
    "docs-site/components/command-generator.tsx",
    "docs-site/content/docs/command-generator.mdx",
    "docs-site/content/docs/setup/guardrail/index.mdx",
    "docs-site/content/docs/connectors/openclaw.mdx",
    "docs-site/content/docs/connectors/zeptoclaw.mdx",
    "docs-site/content/docs/connectors/claudecode.mdx",
    "docs-site/content/docs/connectors/codex.mdx",
    "docs-site/content/docs/connectors/geminicli.mdx",
    "docs-site/content/docs/setup/index.mdx",
    "bundles/local_observability_stack/prometheus/rules/alerts.yml",
    "scripts/install-dev.sh",
    "docs-site/content/docs/reference/configuration.mdx",
)

OBSERVABILITY_V8_WORKFLOW_GUIDES = (
    "docs-site/components/command-generator.tsx",
    "docs-site/content/docs/command-generator.mdx",
    "docs-site/content/docs/setup/guardrail/index.mdx",
    "docs-site/content/docs/setup/index.mdx",
    "bundles/local_observability_stack/prometheus/rules/alerts.yml",
)

OBSERVABILITY_V8_CONNECTOR_GUIDES = (
    "docs-site/content/docs/connectors/openclaw.mdx",
    "docs-site/content/docs/connectors/zeptoclaw.mdx",
    "docs-site/content/docs/connectors/claudecode.mdx",
    "docs-site/content/docs/connectors/codex.mdx",
    "docs-site/content/docs/connectors/geminicli.mdx",
)

OBSERVABILITY_V8_JSONL_GUIDES = {
    "docs-site/content/docs/setup/index.mdx": "kind: jsonl",
    "docs-site/content/docs/reference/configuration.mdx": "kind: jsonl",
}


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _write_python_selector_shims(root: Path, body: str) -> None:
    """Make installer Python selection independent of host-installed minors."""

    for name in ("python3.12", "python3.11", "python3.13", "python3.10", "python3"):
        _write_executable(root / name, body)


def test_posix_installer_rejects_python_314_before_creating_policy_venv() -> None:
    source = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    assert 'readonly MIN_PYTHON_VERSION="3.10"' in source
    assert 'readonly MAX_PYTHON_VERSION_EXCLUSIVE="3.14"' in source
    selector = source[source.index("ensure_python() {") : source.index("# ── Resolve dist artifacts")]
    assert 'version_gte "$ver" "${MIN_PYTHON_VERSION}"' in selector
    assert '! version_gte "$ver" "${MAX_PYTHON_VERSION_EXCLUSIVE}"' in selector

    developer_installer = (ROOT / "scripts/install-dev.sh").read_text(encoding="utf-8")
    assert 'readonly MAX_PYTHON_VERSION_EXCLUSIVE="3.14"' in developer_installer
    assert 'version_in_range "${ver}" "${MIN_PYTHON_VERSION}" "${MAX_PYTHON_VERSION_EXCLUSIVE}"' in developer_installer


def _write_minimal_schema2_install_dist(root: Path, version: str = CURRENT_RELEASE) -> None:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "amd64"
    gateways = {
        os_name: {
            platform_arch: f"defenseclaw_{version}_protocol2_{os_name}_{platform_arch}.dcgateway"
            for platform_arch in ("amd64", "arm64")
        }
        for os_name in ("darwin", "linux", "windows")
    }
    wheel_name = f"defenseclaw-{version}-2-py3-none-any.dcwheel"
    gateway_name = str(gateways[system][arch])
    manifest = {
        "schema_version": 2,
        "release_version": version,
        "release_artifacts": {"wheel": wheel_name, "gateways": gateways},
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
    (root / "upgrade-manifest.json").write_bytes(manifest_bytes)

    envelope_magic = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n"
    gateway_body = b"#!/bin/sh\nexit 0\n"
    tar_info = tarfile.TarInfo("defenseclaw")
    tar_info.mode = 0o755
    tar_info.size = len(gateway_body)
    gateway_payload = io.BytesIO()
    with tarfile.open(fileobj=gateway_payload, mode="w:gz") as archive:
        archive.addfile(tar_info, io.BytesIO(gateway_body))
    (root / gateway_name).write_bytes(envelope_magic + bytes(value ^ 0xA5 for value in gateway_payload.getvalue()))

    wheel_payload = io.BytesIO()
    with zipfile.ZipFile(wheel_payload, "w") as archive:
        archive.writestr(
            f"defenseclaw-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: defenseclaw\nVersion: {version}\n",
        )
        archive.writestr(
            "defenseclaw/install_publish.py",
            (ROOT / "cli/defenseclaw/install_publish.py").read_bytes(),
        )
    (root / wheel_name).write_bytes(envelope_magic + bytes(value ^ 0xA5 for value in wheel_payload.getvalue()))

    names = ("upgrade-manifest.json", gateway_name, wheel_name)
    (root / "checksums.txt").write_text(
        "".join(f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n" for name in names),
        encoding="utf-8",
    )
    (root / "checksums.txt.sig").write_text("test signature\n", encoding="utf-8")
    (root / "checksums.txt.pem").write_text("test certificate\n", encoding="utf-8")


def test_schema2_protected_envelopes_are_not_renamed_wheels_or_archives(tmp_path: Path) -> None:
    release = tmp_path / "release"
    release.mkdir()
    _write_minimal_schema2_install_dist(release)

    wheel = next(release.glob("*.dcwheel"))
    gateway = next(release.glob("*.dcgateway"))
    magic = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n"
    for protected in (wheel, gateway):
        encoded = protected.read_bytes()
        assert encoded.startswith(magic)
        payload = bytes(value ^ 0xA5 for value in encoded[len(magic) :])
        assert payload
        assert not zipfile.is_zipfile(protected)
        with pytest.raises(tarfile.ReadError):
            tarfile.open(protected, "r:*").close()

    decoded_wheel = tmp_path / "decoded.whl"
    decoded_wheel.write_bytes(bytes(value ^ 0xA5 for value in wheel.read_bytes()[len(magic) :]))
    assert zipfile.is_zipfile(decoded_wheel)
    decoded_gateway = tmp_path / "decoded.tar.gz"
    decoded_gateway.write_bytes(bytes(value ^ 0xA5 for value in gateway.read_bytes()[len(magic) :]))
    with tarfile.open(decoded_gateway, "r:gz") as archive:
        assert archive.getnames() == ["defenseclaw"]


def test_protocol2_plugin_is_exact_versioned_signed_input_before_extraction() -> None:
    installer = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    plugin = installer[
        installer.index("release_has_plugin() {") : installer.index(
            "# ── OpenClaw",
        )
    ]

    assert 'tarball_name="defenseclaw-plugin-${RELEASE_VERSION}.tar.gz"' in plugin
    assert 'if [[ "${MODERN_RELEASE:-false}" == true ]]; then' in plugin
    assert "return 0" in plugin
    fetch = plugin.index('fetch_artifact "$(artifact_path "${tarball_name}")" "${tarball}"')
    verify = plugin.index('verify_checksum "${tarball}" "${tarball_name}"')
    extract = plugin.index('tar -xzf "${tarball}" -C "${dest}"')
    assert fetch < verify < extract
    assert "No plugin artifact in this release" in plugin


def test_posix_envelope_failure_preserves_private_destination_for_tree_retirement() -> None:
    installer = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    materializer = installer[
        installer.index('MAGIC = b"DEFENSECLAW-PROTECTED-ARTIFACT-V1') : installer.index(
            "materialized_digest = hashlib.sha256()"
        )
    ]

    assert "destination.unlink" not in materializer
    assert "os.unlink" not in materializer
    assert "retires this residue under deterministic private custody" in materializer


@pytest.mark.skipif(os.name == "nt", reason="installer identity helper is POSIX-only")
def test_posix_installer_identity_is_per_inode_not_per_filesystem(tmp_path: Path) -> None:
    source = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    assert " -ef " not in source
    assert 'rm -f "${activation}"' not in source
    assert '--custody-root "${INSTALL_CUSTODY_ROOT}"' in source
    assert '"${CONNECTOR_MARKER_ID}"' in source
    start = source.index("path_identity() {")
    end = source.index("\n}\n\npath_has_identity()", start) + len("\n}")
    function = source[start:end]
    assert 'getattr(os, "O_SYMLINK", 0x00200000)' in function
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.write_bytes(b"first\n")
    second.write_bytes(b"second\n")
    os_name = "darwin" if platform.system() == "Darwin" else "linux"

    def identities() -> list[str]:
        completed = subprocess.run(
            [
                "/bin/bash",
                "-c",
                f'set -euo pipefail\nOS={os_name}\n{function}\npath_identity "$1"\npath_identity "$2"',
                "bash",
                str(first),
                str(second),
            ],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        return completed.stdout.splitlines()

    before = identities()
    assert len(before) == 2 and before[0] != before[1]
    assert all(len(identity.split(":")) == 4 for identity in before)
    first.unlink()
    first.write_bytes(b"replacement\n")
    after = identities()
    assert all(len(identity.split(":")) == 4 for identity in after)
    assert before[0] != after[0]


def test_posix_installer_routes_retirement_custody_by_managed_filesystem() -> None:
    source = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    assert ('readonly STATE_CUSTODY_ROOT="$(dirname "${DEFENSECLAW_HOME}")/.defenseclaw-install-custody"') in source

    cleanup = source[
        source.index("cleanup_install_attempt() {") : source.index(
            "\n}\n\nclaim_fresh_install_home()",
            source.index("cleanup_install_attempt() {"),
        )
    ]
    for managed in (
        '"${DEFENSECLAW_VENV}"',
        '"${DEFENSECLAW_HOME}/picked_connector"',
        '"${DEFENSECLAW_HOME}/extensions/defenseclaw"',
        '"${DEFENSECLAW_HOME}/extensions"',
        '"${DEFENSECLAW_HOME}"',
    ):
        command = cleanup[cleanup.index(managed) :]
        command = command[: command.index("|| true")]
        assert '--custody-root "${STATE_CUSTODY_ROOT}"' in command

    for managed in ('"${INSTALL_DIR}/defenseclaw"', '"${INSTALL_DIR}"', '"${bin_parent}"'):
        command = cleanup[cleanup.index(managed) :]
        command = command[: command.index("|| true")]
        assert '--custody-root "${INSTALL_CUSTODY_ROOT}"' in command

    connector = source[
        source.index("record_picked_connector() {") : source.index(
            "\n}\n\n# ── Interrupt handler",
            source.index("record_picked_connector() {"),
        )
    ]
    assert '--custody-root "${STATE_CUSTODY_ROOT}"' in connector
    assert 'recover-custody "${STATE_CUSTODY_ROOT}"' in source
    entrypoint = source[source.index("load_release_policy\n") :]
    prepublication = entrypoint[: entrypoint.index("claim_fresh_install_home")]
    assert prepublication.count("prepare-custody") == 2
    assert '"${STATE_CUSTODY_ROOT}" "${state_parent}"' in prepublication
    assert '"${INSTALL_CUSTODY_ROOT}" "${install_anchor}"' in prepublication


def test_posix_install_attempt_marker_bounds_the_publication_lifecycle() -> None:
    source = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    marker_lifecycle = source[
        source.index("update_install_attempt_marker() {") : source.index(
            "\n# Return device, inode",
            source.index("update_install_attempt_marker() {"),
        )
    ]
    assert "os.unlink(" not in marker_lifecycle
    assert '"${PUBLISH_HELPER}" unlink-exact' in marker_lifecycle
    early_guard = source.index("if existing_install_detected && ! interrupted_install_attempt_detected; then")
    assert early_guard < source.index("detect_platform\n", early_guard)

    recovered_guard = source.index("if existing_install_detected; then", early_guard + 1)
    begin = source.index("begin_install_attempt\n", recovered_guard)
    first_publication = source.index("claim_fresh_install_home\n", begin)
    assert recovered_guard < begin < first_publication

    completion = source[
        source.index("complete_install_attempt() {") : source.index(
            "\n}\n\nversion_gte()",
            source.index("complete_install_attempt() {"),
        )
    ]
    retire = completion.index("finish_install_attempt")
    succeeded = completion.index("INSTALL_SUCCEEDED=true")
    assert retire < succeeded


@pytest.mark.skipif(os.name == "nt", reason="POSIX installer custody uses POSIX modes")
@pytest.mark.parametrize("split_roots", (False, True))
def test_posix_install_attempt_marker_is_durable_private_and_recoverable(
    tmp_path: Path,
    split_roots: bool,
) -> None:
    source = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    start = source.index("custody_stat() {")
    end = source.index("\n# Return device, inode", start)
    functions = source[start:end]

    install_custody = tmp_path / "home/.defenseclaw-install-custody"
    state_custody = tmp_path / "state/.defenseclaw-install-custody" if split_roots else install_custody
    for custody in {install_custody, state_custody}:
        custody.parent.mkdir(parents=True, mode=0o700)
        prepared = subprocess.run(
            [
                sys.executable,
                str(ROOT / "cli/defenseclaw/install_publish.py"),
                "prepare-custody",
                str(custody),
                str(custody.parent),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        assert prepared.returncode == 0, prepared.stdout + prepared.stderr

    program = f"""
set -euo pipefail
die() {{ printf '%s\n' "$1" >&2; exit 71; }}
{functions}
INSTALL_ATTEMPT_MARKER=.defenseclaw-install-in-progress-v1
INSTALL_ATTEMPT_MARKER_CONTENT='DefenseClaw authenticated fresh install in progress v1'
INSTALL_CUSTODY_ROOT=$1
STATE_CUSTODY_ROOT=$2
POLICY_PYTHON=$3
PUBLISH_HELPER=$4
begin_install_attempt
interrupted_install_attempt_detected
if [[ "${{ACTION}}" == complete ]]; then
    finish_install_attempt
    ! interrupted_install_attempt_detected
fi
"""
    environment = {**os.environ, "ACTION": "interrupt"}
    interrupted = subprocess.run(
        [
            "/bin/bash",
            "-c",
            program,
            "bash",
            str(install_custody),
            str(state_custody),
            sys.executable,
            str(ROOT / "cli/defenseclaw/install_publish.py"),
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert interrupted.returncode == 0, interrupted.stdout + interrupted.stderr

    marker_name = ".defenseclaw-install-in-progress-v1"
    roots = {install_custody, state_custody}
    for custody in roots:
        marker = custody / marker_name
        assert stat.S_IMODE(custody.stat().st_mode) == 0o700
        assert stat.S_IMODE(marker.stat().st_mode) == 0o600
        assert marker.stat().st_nlink == 1
        assert marker.read_text(encoding="ascii") == ("DefenseClaw authenticated fresh install in progress v1\n")

    environment["ACTION"] = "complete"
    recovered = subprocess.run(
        [
            "/bin/bash",
            "-c",
            program,
            "bash",
            str(install_custody),
            str(state_custody),
            sys.executable,
            str(ROOT / "cli/defenseclaw/install_publish.py"),
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert recovered.returncode == 0, recovered.stdout + recovered.stderr
    assert all(not (custody / marker_name).exists() for custody in roots)
    assert all(custody.is_dir() for custody in roots)
    expected = b"DefenseClaw authenticated fresh install in progress v1\n"
    for custody in roots:
        retired = [path for path in custody.glob("retired-*") if path.is_file() and path.read_bytes() == expected]
        assert len(retired) == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX marker retirement is rename-only")
def test_posix_install_attempt_marker_substitution_is_preserved(tmp_path: Path) -> None:
    source = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    start = source.index("custody_stat() {")
    end = source.index("\n# Return device, inode", start)
    functions = source[start:end]
    custody = tmp_path / ".defenseclaw-install-custody"
    prepared = subprocess.run(
        [
            sys.executable,
            str(ROOT / "cli/defenseclaw/install_publish.py"),
            "prepare-custody",
            str(custody),
            str(tmp_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert prepared.returncode == 0, prepared.stdout + prepared.stderr

    wrapper = tmp_path / "publisher-wrapper.py"
    wrapper.write_text(
        """#!/usr/bin/env python3
import os
from pathlib import Path
import sys

arguments = sys.argv[1:]
if arguments and arguments[0] == "unlink-exact":
    marker = Path(arguments[1])
    marker.rename(marker.with_name("attempt-marker-moved-away"))
    marker.write_bytes(b"foreign replacement\\n")
    marker.chmod(0o600)
os.execv(
    sys.executable,
    [sys.executable, os.environ["REAL_PUBLISHER"], *arguments],
)
""",
        encoding="utf-8",
    )
    program = f"""
set -euo pipefail
die() {{ printf '%s\n' "$1" >&2; exit 71; }}
{functions}
INSTALL_ATTEMPT_MARKER=.defenseclaw-install-in-progress-v1
INSTALL_ATTEMPT_MARKER_CONTENT='DefenseClaw authenticated fresh install in progress v1'
INSTALL_CUSTODY_ROOT=$1
STATE_CUSTODY_ROOT=$1
POLICY_PYTHON=$2
PUBLISH_HELPER=$3
begin_install_attempt
finish_install_attempt
"""
    completed = subprocess.run(
        [
            "/bin/bash",
            "-c",
            program,
            "bash",
            str(custody),
            sys.executable,
            str(wrapper),
        ],
        cwd=ROOT,
        env={
            **os.environ,
            "REAL_PUBLISHER": str(ROOT / "cli/defenseclaw/install_publish.py"),
        },
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )

    output = completed.stdout + completed.stderr
    assert completed.returncode == 71, output
    assert "Could not durably retire" in output
    marker = custody / ".defenseclaw-install-in-progress-v1"
    assert marker.read_bytes() == b"foreign replacement\n"
    assert (custody / "attempt-marker-moved-away").read_bytes() == (
        b"DefenseClaw authenticated fresh install in progress v1\n"
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX interrupted retirement is rename-only")
def test_posix_install_attempt_marker_allows_authenticated_interrupted_recovery(
    tmp_path: Path,
) -> None:
    source = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    start = source.index("custody_stat() {")
    end = source.index("\n# Return device, inode", start)
    functions = source[start:end]
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    custody = home / ".defenseclaw-install-custody"
    install_publish.prepare_custody(custody, home)

    program = f"""
set -euo pipefail
die() {{ printf '%s\n' "$1" >&2; exit 71; }}
{functions}
INSTALL_ATTEMPT_MARKER=.defenseclaw-install-in-progress-v1
INSTALL_ATTEMPT_MARKER_CONTENT='DefenseClaw authenticated fresh install in progress v1'
INSTALL_CUSTODY_ROOT=$1
STATE_CUSTODY_ROOT=$1
POLICY_PYTHON=$2
PUBLISH_HELPER=$3
begin_install_attempt
interrupted_install_attempt_detected
"""
    marked = subprocess.run(
        [
            "/bin/bash",
            "-c",
            program,
            "bash",
            str(custody),
            sys.executable,
            str(ROOT / "cli/defenseclaw/install_publish.py"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert marked.returncode == 0, marked.stdout + marked.stderr

    partial_home = home / ".defenseclaw"
    partial_home.mkdir(mode=0o700)
    identity = install_publish.path_identity(partial_home)
    custody_fd = install_publish._open_custody_root(custody, create=False)
    try:
        intent, _retired = install_publish._retirement_names(
            str(partial_home),
            identity,
            "directory",
        )
        document = install_publish._retirement_document(
            str(partial_home),
            identity,
            "directory",
        )
        assert install_publish._ensure_retirement_intent(
            custody_fd,
            intent,
            document,
            allow_create=True,
        )
    finally:
        os.close(custody_fd)

    recovered = subprocess.run(
        [
            sys.executable,
            str(ROOT / "cli/defenseclaw/install_publish.py"),
            "recover-custody",
            str(custody),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert recovered.returncode == 0, recovered.stdout + recovered.stderr
    assert not partial_home.exists()
    assert (custody / ".defenseclaw-install-in-progress-v1").is_file()
    retired_directories = [path for path in custody.glob("retired-*") if path.is_dir()]
    assert len(retired_directories) == 1

    retry = subprocess.run(
        [
            "/bin/bash",
            "-c",
            program,
            "bash",
            str(custody),
            sys.executable,
            str(ROOT / "cli/defenseclaw/install_publish.py"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert retry.returncode == 0, retry.stdout + retry.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX installer custody uses POSIX file types")
@pytest.mark.parametrize("invalid_kind", ("content", "mode", "symlink", "directory"))
def test_posix_install_attempt_marker_invalid_state_fails_closed(
    tmp_path: Path,
    invalid_kind: str,
) -> None:
    source = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    start = source.index("custody_stat() {")
    end = source.index("\nupdate_install_attempt_marker()", start)
    functions = source[start:end]
    custody = tmp_path / ".defenseclaw-install-custody"
    custody.mkdir(mode=0o700)
    marker = custody / ".defenseclaw-install-in-progress-v1"
    if invalid_kind == "content":
        marker.write_text("invalid\n", encoding="ascii")
        marker.chmod(0o600)
    elif invalid_kind == "mode":
        marker.write_text(
            "DefenseClaw authenticated fresh install in progress v1\n",
            encoding="ascii",
        )
        marker.chmod(0o644)
    elif invalid_kind == "symlink":
        target = tmp_path / "marker-target"
        target.write_text(
            "DefenseClaw authenticated fresh install in progress v1\n",
            encoding="ascii",
        )
        target.chmod(0o600)
        marker.symlink_to(target)
    else:
        marker.mkdir(mode=0o700)

    program = f"""
set -euo pipefail
{functions}
INSTALL_ATTEMPT_MARKER=.defenseclaw-install-in-progress-v1
INSTALL_ATTEMPT_MARKER_CONTENT='DefenseClaw authenticated fresh install in progress v1'
INSTALL_CUSTODY_ROOT=$1
STATE_CUSTODY_ROOT=$1
if interrupted_install_attempt_detected; then
    exit 72
fi
"""
    completed = subprocess.run(
        ["/bin/bash", "-c", program, "bash", str(custody)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="legacy rollback is POSIX-only")
def test_legacy_failure_preserves_residue_without_exact_retirement(
    tmp_path: Path,
) -> None:
    source = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    start = source.index("path_identity() {")
    end = source.index("\nclaim_fresh_install_home()", start)
    functions = source[start:end]
    os_name = "darwin" if platform.system() == "Darwin" else "linux"
    script = f"""
set -euo pipefail
OS={os_name}
{functions}
warn() {{ :; }}
root=$1
DEFENSECLAW_HOME=$root/.defenseclaw
DEFENSECLAW_VENV=$DEFENSECLAW_HOME/.venv
INSTALL_DIR=$root/.local/bin
mkdir -p "$DEFENSECLAW_VENV" "$DEFENSECLAW_HOME/extensions/defenseclaw" "$INSTALL_DIR"
printf 'plugin\n' > "$DEFENSECLAW_HOME/extensions/defenseclaw/index.js"
GATEWAY_ACTIVATION="$INSTALL_DIR/.defenseclaw-gateway.install.test"
printf 'gateway\n' > "$GATEWAY_ACTIVATION"
GATEWAY_ACTIVATION_ID=$(path_identity "$GATEWAY_ACTIVATION")
ln "$GATEWAY_ACTIVATION" "$INSTALL_DIR/defenseclaw-gateway"
GATEWAY_PUBLISHED_ID=$(path_identity "$INSTALL_DIR/defenseclaw-gateway")
PICKED_CONNECTOR_ACTIVATION="$DEFENSECLAW_HOME/.picked-connector.install.test"
printf 'openclaw\n' > "$PICKED_CONNECTOR_ACTIVATION"
PICKED_CONNECTOR_ACTIVATION_ID=$(path_identity "$PICKED_CONNECTOR_ACTIVATION")
ln "$PICKED_CONNECTOR_ACTIVATION" "$DEFENSECLAW_HOME/picked_connector"
CONNECTOR_MARKER_ID=$(path_identity "$DEFENSECLAW_HOME/picked_connector")
VENV_CLAIM_ID=$(path_identity "$DEFENSECLAW_VENV")
PLUGIN_CLAIM_ID=$(path_identity "$DEFENSECLAW_HOME/extensions/defenseclaw")
EXTENSIONS_CLAIM_ID=$(path_identity "$DEFENSECLAW_HOME/extensions")
HOME_CLAIM_ID=$(path_identity "$DEFENSECLAW_HOME")
INSTALL_DIR_CLAIM_ID=$(path_identity "$INSTALL_DIR")
LOCAL_BIN_PARENT_CLAIM_ID=$(path_identity "$root/.local")
INSTALL_SUCCEEDED=false
MODERN_RELEASE=false
PUBLISH_HELPER=
POLICY_PYTHON=
GATEWAY_ROLLBACK_TOKEN=
CONNECTOR_MARKER_ROLLBACK_TOKEN=
CLI_PUBLISHED_ID=
POLICY_DIR=
POLICY_DIR_ID=
cleanup_install_attempt
test -e "$DEFENSECLAW_HOME/picked_connector"
test -e "$INSTALL_DIR/defenseclaw-gateway"
test -e "$DEFENSECLAW_HOME/extensions/defenseclaw/index.js"
"""
    completed = subprocess.run(
        ["/bin/bash", "-c", script, "bash", str(tmp_path / "home")],
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.skipif(platform.system() != "Darwin", reason="real codesign regression is macOS-only")
def test_legacy_macos_installer_claims_gateway_after_copy_and_codesign(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    fake_bin = tmp_path / "fake-bin"
    release = tmp_path / "release"
    home.mkdir()
    fake_bin.mkdir()
    release.mkdir()

    version = "0.8.3"
    manifest = {"schema_version": 1, "release_version": version}
    manifest_path = release / "upgrade-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    (release / "checksums.txt").write_text(
        f"{hashlib.sha256(manifest_path.read_bytes()).hexdigest()}  upgrade-manifest.json\n",
        encoding="utf-8",
    )
    machine = platform.machine().lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "amd64"
    gateway = release / f"defenseclaw-gateway-darwin-{arch}"
    shutil.copyfile("/usr/bin/true", gateway)
    gateway.chmod(0o755)
    (release / f"defenseclaw-{version}-py3-none-any.whl").write_bytes(b"legacy wheel fixture\n")

    _write_python_selector_shims(
        fake_bin,
        f"#!{sys.executable}\n"
        "import os\n"
        "import sys\n"
        f"os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n",
    )
    _write_executable(
        fake_bin / "uv",
        "#!/bin/sh\n"
        "set -eu\n"
        'if [ "${1:-}" = "--version" ]; then echo \'uv 0.8.0\'; exit 0; fi\n'
        'if [ "${1:-}" = "venv" ]; then\n'
        "  venv=$2\n"
        '  mkdir -p "$venv/bin"\n'
        "  printf '#!/bin/sh\\nexit 0\\n' > \"$venv/bin/python\"\n"
        '  chmod +x "$venv/bin/python"\n'
        "  exit 0\n"
        "fi\n"
        'if [ "${1:-}" = "pip" ] && [ "${2:-}" = "install" ]; then\n'
        "  python=''\n"
        "  previous=''\n"
        '  for argument in "$@"; do\n'
        '    if [ "$previous" = "--python" ]; then python=$argument; break; fi\n'
        "    previous=$argument\n"
        "  done\n"
        "  cli=${python%/python}/defenseclaw\n"
        "  printf '#!/bin/sh\\nexit 0\\n' > \"$cli\"\n"
        '  chmod +x "$cli"\n'
        "  exit 0\n"
        "fi\n"
        "exit 90\n",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "DEFENSECLAW_HOME": str(home / ".defenseclaw"),
            "PATH": f"{fake_bin}:/usr/bin:/bin",
        }
    )
    completed = subprocess.run(
        [
            "/bin/bash",
            str(ROOT / "scripts/install.sh"),
            "--local",
            str(release),
            "--yes",
            "--connector",
            "none",
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=45,
        check=False,
    )

    output = completed.stdout + completed.stderr
    assert completed.returncode == 0, output
    installed_gateway = home / ".local/bin/defenseclaw-gateway"
    assert installed_gateway.is_file() and not installed_gateway.is_symlink()
    activation_residue = list((home / ".local/bin").glob(".defenseclaw-gateway.install.*"))
    assert len(activation_residue) == 1
    assert activation_residue[0].stat().st_ino == installed_gateway.stat().st_ino
    assert "Legacy gateway activation residue was preserved" in output
    verified = subprocess.run(
        ["/usr/bin/codesign", "--verify", str(installed_gateway)],
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert verified.returncode == 0, verified.stdout + verified.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX installer requires /bin/bash")
def test_posix_installer_refuses_partial_home_and_dangling_entrypoints(tmp_path: Path) -> None:
    installer = ROOT / "scripts/install.sh"
    for case in ("partial-home", "dangling-cli"):
        home = tmp_path / case / "home"
        data_home = home / ".defenseclaw"
        home.mkdir(parents=True)
        if case == "partial-home":
            data_home.mkdir()
            marker = data_home / "partial-state"
            marker.write_bytes(b"preserve\n")
        else:
            install_dir = home / ".local/bin"
            install_dir.mkdir(parents=True)
            marker = install_dir / "defenseclaw"
            marker.symlink_to(home / "missing-cli")

        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(home),
                "DEFENSECLAW_HOME": str(data_home),
                "PATH": "/usr/bin:/bin",
            }
        )
        completed = subprocess.run(
            ["/bin/bash", str(installer), "--yes", "--connector", "none"],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

        output = completed.stdout + completed.stderr
        assert completed.returncode == 1, output
        assert "An existing DefenseClaw installation was detected" in output
        assert "No changes were made" in output
        assert "Installing Gateway" not in output
        if case == "partial-home":
            assert marker.read_bytes() == b"preserve\n"
        else:
            assert marker.is_symlink()
            assert not marker.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX installer requires /bin/bash")
def test_posix_local_installer_refuses_existing_state_before_artifact_checks(tmp_path: Path) -> None:
    home = tmp_path / "home"
    data_home = home / ".defenseclaw"
    local_dist = tmp_path / "local-dist"
    data_home.mkdir(parents=True)
    local_dist.mkdir()
    marker = data_home / "partial-state"
    marker.write_bytes(b"preserve\n")
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "DEFENSECLAW_HOME": str(data_home),
            "PATH": "/usr/bin:/bin",
        }
    )

    completed = subprocess.run(
        [
            "/bin/bash",
            str(ROOT / "scripts/install.sh"),
            "--yes",
            "--connector",
            "none",
            "--local",
            str(local_dist),
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )

    output = completed.stdout + completed.stderr
    assert completed.returncode == 1, output
    assert "An existing DefenseClaw installation was detected" in output
    assert "No changes were made" in output
    assert "Detecting platform" not in output
    assert marker.read_bytes() == b"preserve\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX installer requires /bin/bash")
def test_posix_installer_refuses_path_only_gateway_before_platform_or_network(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    path_bin = tmp_path / "path-bin"
    home.mkdir()
    path_bin.mkdir()
    gateway = path_bin / "defenseclaw-gateway"
    gateway.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    gateway.chmod(0o755)
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "DEFENSECLAW_HOME": str(home / ".defenseclaw"),
            "PATH": f"{path_bin}:/usr/bin:/bin",
        }
    )

    completed = subprocess.run(
        [
            "/bin/bash",
            str(ROOT / "scripts/install.sh"),
            "--yes",
            "--connector",
            "none",
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )

    output = completed.stdout + completed.stderr
    assert completed.returncode == 1, output
    assert "An existing DefenseClaw installation was detected" in output
    assert "No changes were made" in output
    assert "Detecting platform" not in output
    assert "Authenticating release policy" not in output
    assert gateway.read_text(encoding="utf-8") == "#!/bin/sh\nexit 0\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX installer publication uses hard links and symlinks")
@pytest.mark.parametrize("arrival", ("gateway", "cli", "venv", "success"))
def test_posix_installer_never_replaces_entrypoint_that_appears_after_preflight(
    tmp_path: Path,
    arrival: str,
) -> None:
    home = tmp_path / "home"
    fake_bin = tmp_path / "fake-bin"
    release = tmp_path / "release"
    home.mkdir()
    fake_bin.mkdir()
    release.mkdir()
    _write_minimal_schema2_install_dist(release)

    real_ln = shutil.which("ln", path="/usr/bin:/bin")
    assert real_ln is not None
    sentinel = f"concurrent-{arrival}-installation\n"
    if arrival == "venv":
        destination = home / ".defenseclaw/.venv/concurrent-install"
    elif arrival == "success":
        destination = tmp_path / "never-created"
    else:
        destination = home / ".local/bin" / ("defenseclaw-gateway" if arrival == "gateway" else "defenseclaw")
    _write_executable(
        fake_bin / "ln",
        "#!/bin/sh\n"
        "set -eu\n"
        'eval last=\\"\\${$#}\\"\n'
        'if [ "$last" = "$RACE_DESTINATION" ]; then\n'
        '  printf \'%s\' "$RACE_SENTINEL" > "$last"\n'
        "fi\n"
        f'exec "{real_ln}" "$@"\n',
    )
    real_mkdir = shutil.which("mkdir", path="/usr/bin:/bin")
    assert real_mkdir is not None
    _write_executable(
        fake_bin / "mkdir",
        "#!/bin/sh\n"
        "set -eu\n"
        'eval last=\\"\\${$#}\\"\n'
        f'"{real_mkdir}" "$@"\n'
        'if [ "${RACE_KIND:-}" = venv ] && [ "$last" = "$RACE_HOME" ]; then\n'
        f'  "{real_mkdir}" -p "${{RACE_DESTINATION%/*}}"\n'
        '  printf \'%s\' "$RACE_SENTINEL" > "$RACE_DESTINATION"\n'
        "fi\n",
    )
    _write_executable(fake_bin / "cosign", "#!/bin/sh\nexit 0\n")
    _write_python_selector_shims(
        fake_bin,
        f"#!{sys.executable}\n"
        "import os\n"
        "from pathlib import Path\n"
        "import sys\n"
        "arguments = sys.argv[1:]\n"
        "kind = os.environ.get('RACE_KIND', '')\n"
        "operation = arguments[1] if len(arguments) > 1 and arguments[0].endswith('install_publish.py') else ''\n"
        "inject = (kind == 'gateway' and operation == 'fresh-regular') or (kind == 'cli' and operation == 'fresh-symlink')\n"
        "if kind == 'venv' and operation == 'fresh-directory':\n"
        "    inject = Path(arguments[-1]) == Path(os.environ['RACE_DESTINATION']).parent\n"
        "if inject:\n"
        "    destination = Path(os.environ['RACE_DESTINATION'])\n"
        "    destination.parent.mkdir(parents=True, exist_ok=True)\n"
        "    destination.write_text(os.environ['RACE_SENTINEL'], encoding='utf-8')\n"
        f"os.execv({sys.executable!r}, [{sys.executable!r}, *arguments])\n",
    )
    _write_executable(
        fake_bin / "uv",
        "#!/bin/sh\n"
        "set -eu\n"
        'if [ "${1:-}" = "--version" ]; then echo \'uv 0.8.0\'; exit 0; fi\n'
        'if [ "${1:-}" = "venv" ]; then\n'
        "  venv=$2\n"
        '  mkdir -p "$venv/bin"\n'
        "  printf '#!/bin/sh\\nexit 0\\n' > \"$venv/bin/python\"\n"
        '  chmod +x "$venv/bin/python"\n'
        "  exit 0\n"
        "fi\n"
        'if [ "${1:-}" = "pip" ] && [ "${2:-}" = "install" ]; then\n'
        "  python=''\n"
        "  previous=''\n"
        '  for argument in "$@"; do\n'
        '    if [ "$previous" = "--python" ]; then python=$argument; break; fi\n'
        "    previous=$argument\n"
        "  done\n"
        '  [ -n "$python" ]\n'
        "  cli=${python%/python}/defenseclaw\n"
        "  printf '#!/bin/sh\\nexit 0\\n' > \"$cli\"\n"
        '  chmod +x "$cli"\n'
        "  exit 0\n"
        "fi\n"
        "exit 90\n",
    )

    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "DEFENSECLAW_HOME": str(home / ".defenseclaw"),
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "RACE_DESTINATION": str(destination),
            "RACE_HOME": str(home / ".defenseclaw"),
            "RACE_KIND": arrival,
            "RACE_SENTINEL": sentinel,
        }
    )
    completed = subprocess.run(
        [
            "/bin/bash",
            str(ROOT / "scripts/install.sh"),
            "--local",
            str(release),
            "--yes",
            "--connector",
            "none",
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    output = completed.stdout + completed.stderr
    if arrival == "success":
        assert completed.returncode == 0, output
        assert (home / ".defenseclaw/.venv/bin/defenseclaw").is_file()
        assert (home / ".local/bin/defenseclaw").is_symlink()
        assert (home / ".local/bin/defenseclaw-gateway").is_file()
        custody = home / ".defenseclaw-install-custody"
        attempt_marker = custody / ".defenseclaw-install-in-progress-v1"
        assert custody.is_dir()
        assert stat.S_IMODE(custody.stat().st_mode) == 0o700
        assert not attempt_marker.exists()

        uv_called = tmp_path / "second-uv-called"
        python_called = tmp_path / "second-python-called"
        _write_executable(
            fake_bin / "uv",
            "#!/bin/sh\nprintf 'called\\n' > \"$SECOND_UV_CALLED\"\nexit 97\n",
        )
        _write_python_selector_shims(
            fake_bin,
            "#!/bin/sh\nprintf 'called\\n' > \"$SECOND_PYTHON_CALLED\"\nexit 98\n",
        )
        environment.update(
            {
                "SECOND_UV_CALLED": str(uv_called),
                "SECOND_PYTHON_CALLED": str(python_called),
            }
        )
        refused = subprocess.run(
            [
                "/bin/bash",
                str(ROOT / "scripts/install.sh"),
                "--local",
                str(release),
                "--yes",
                "--connector",
                "none",
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        refusal_output = refused.stdout + refused.stderr
        assert refused.returncode == 1, refusal_output
        assert "An existing DefenseClaw installation was detected" in refusal_output
        assert "No changes were made" in refusal_output
        assert "Detecting platform" not in refusal_output
        assert not uv_called.exists()
        assert not python_called.exists()
        assert not attempt_marker.exists()
        return
    assert completed.returncode != 0, output
    assert "appeared during installation" in output
    assert destination.is_file() and not destination.is_symlink()
    assert destination.read_text(encoding="utf-8") == sentinel
    if arrival == "venv":
        assert not (home / ".local/bin/defenseclaw-gateway").exists()
        assert not (home / ".local/bin/defenseclaw").exists()
    else:
        assert not (home / ".defenseclaw").exists()
    if arrival == "cli":
        assert not (home / ".local/bin/defenseclaw-gateway").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX installer uses Bash glob expansion")
def test_posix_connector_marker_requires_one_real_retained_stage(tmp_path: Path) -> None:
    installer = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    function_start = installer.index("record_picked_connector() {")
    function_end = installer.index("\n}\n\n# ── Interrupt handler", function_start) + len("\n}")
    function = installer[function_start:function_end]

    home = tmp_path / "home/.defenseclaw"
    policy = tmp_path / "policy"
    publisher = tmp_path / "publisher.sh"
    identity_called = tmp_path / "path-identity-called"
    home.mkdir(parents=True)
    policy.mkdir()
    _write_executable(publisher, "#!/bin/sh\nprintf '%s\\n' retained-token\n")

    program = (
        "set -euo pipefail\n"
        "die() { printf '%s\\n' \"$1\" >&2; exit 71; }\n"
        'path_identity() { : > "${PATH_IDENTITY_CALLED}"; return 1; }\n'
        f"{function}\n"
        "CONNECTOR=codex\n"
        "MODERN_RELEASE=true\n"
        f"DEFENSECLAW_HOME={home!s}\n"
        f"INSTALL_CUSTODY_ROOT={tmp_path / 'custody'!s}\n"
        f"STATE_CUSTODY_ROOT={tmp_path / 'state-custody'!s}\n"
        f"POLICY_DIR={policy!s}\n"
        "POLICY_PYTHON=/bin/sh\n"
        f"PUBLISH_HELPER={publisher!s}\n"
        f"PATH_IDENTITY_CALLED={identity_called!s}\n"
        "record_picked_connector\n"
    )
    completed = subprocess.run(
        ["/bin/bash", "-c", program],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )

    output = completed.stdout + completed.stderr
    assert completed.returncode == 71, output
    assert "Connector marker rollback custody could not be bound" in output
    assert "Could not bind retained connector marker custody" not in output
    assert not identity_called.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX rollback uses descriptor-bound publisher")
def test_posix_failed_install_removes_attempt_owned_plugin_marker_and_bin_dirs(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    fake_bin = tmp_path / "fake-bin"
    release = tmp_path / "release"
    commit_called = tmp_path / "commit-called"
    home.mkdir()
    fake_bin.mkdir()
    release.mkdir()
    _write_minimal_schema2_install_dist(release)

    plugin_body = b"export const installed = true;\n"
    plugin_info = tarfile.TarInfo("index.js")
    plugin_info.mode = 0o600
    plugin_info.size = len(plugin_body)
    plugin_archive = release / f"defenseclaw-plugin-{CURRENT_RELEASE}.tar.gz"
    with tarfile.open(plugin_archive, "w:gz") as archive:
        archive.addfile(plugin_info, io.BytesIO(plugin_body))
    with (release / "checksums.txt").open("a", encoding="utf-8") as checksums:
        checksums.write(f"{hashlib.sha256(plugin_archive.read_bytes()).hexdigest()}  {plugin_archive.name}\n")

    _write_executable(fake_bin / "cosign", "#!/bin/sh\nexit 0\n")
    _write_python_selector_shims(
        fake_bin,
        f"#!{sys.executable}\n"
        "import os\n"
        "from pathlib import Path\n"
        "import sys\n"
        "arguments = sys.argv[1:]\n"
        "if (\n"
        "    len(arguments) > 1\n"
        "    and arguments[0].endswith('install_publish.py')\n"
        "    and arguments[1] == 'commit-token'\n"
        "):\n"
        "    home = Path(os.environ['HOME'])\n"
        "    marker = home / '.defenseclaw/picked_connector'\n"
        "    plugin = home / '.defenseclaw/extensions/defenseclaw/index.js'\n"
        "    if marker.read_text(encoding='utf-8').strip() != 'openclaw':\n"
        "        raise SystemExit(74)\n"
        "    if plugin.read_bytes() != b'export const installed = true;\\n':\n"
        "        raise SystemExit(74)\n"
        "    Path(os.environ['COMMIT_CALLED']).write_text('called\\n', encoding='utf-8')\n"
        "    raise SystemExit(73)\n"
        f"os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n",
    )
    _write_executable(
        fake_bin / "uv",
        "#!/bin/sh\n"
        "set -eu\n"
        'if [ "${1:-}" = "--version" ]; then echo \'uv 0.8.0\'; exit 0; fi\n'
        'if [ "${1:-}" = "venv" ]; then\n'
        "  venv=$2\n"
        '  mkdir -p "$venv/bin"\n'
        "  printf '#!/bin/sh\\nexit 0\\n' > \"$venv/bin/python\"\n"
        '  chmod +x "$venv/bin/python"\n'
        "  exit 0\n"
        "fi\n"
        'if [ "${1:-}" = "pip" ] && [ "${2:-}" = "install" ]; then\n'
        "  python=''\n"
        "  previous=''\n"
        '  for argument in "$@"; do\n'
        '    if [ "$previous" = "--python" ]; then python=$argument; break; fi\n'
        "    previous=$argument\n"
        "  done\n"
        '  [ -n "$python" ]\n'
        "  cli=${python%/python}/defenseclaw\n"
        "  printf '#!/bin/sh\\nexit 0\\n' > \"$cli\"\n"
        '  chmod +x "$cli"\n'
        "  exit 0\n"
        "fi\n"
        "exit 90\n",
    )
    _write_executable(
        fake_bin / "openclaw",
        '#!/bin/sh\nif [ "${1:-}" = "--version" ]; then echo \'openclaw 2026.3.24\'; exit 0; fi\nexit 0\n',
    )
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "DEFENSECLAW_HOME": str(home / ".defenseclaw"),
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "COMMIT_CALLED": str(commit_called),
        }
    )
    completed = subprocess.run(
        [
            "/bin/bash",
            str(ROOT / "scripts/install.sh"),
            "--local",
            str(release),
            "--yes",
            "--connector",
            "openclaw",
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    output = completed.stdout + completed.stderr
    assert completed.returncode != 0, output
    assert commit_called.exists(), output
    assert commit_called.read_text(encoding="utf-8") == "called\n"
    assert not (home / ".defenseclaw").exists()
    assert not (home / ".local").exists()
    assert not (home / ".local/bin/defenseclaw").exists()
    assert not (home / ".local/bin/defenseclaw-gateway").exists()


@pytest.mark.skipif(os.name == "nt", reason="source-install Makefile preflight uses POSIX symlinks")
def test_source_install_preflight_refuses_release_and_other_checkout_but_allows_owner(
    tmp_path: Path,
) -> None:
    make = shutil.which("make")
    if make is None:
        pytest.skip("make is unavailable")
    tool_dirs = {str(Path(tool).parent) for name in ("go", "python3") if (tool := shutil.which(name)) is not None}
    test_path = os.pathsep.join(sorted(tool_dirs) + ["/usr/bin", "/bin"])

    def run(
        home: Path,
        install_dir: Path,
        target: str = "_source-install-preflight",
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(home),
                "DEFENSECLAW_HOME": str(home / ".defenseclaw"),
                "PATH": test_path,
            }
        )
        return subprocess.run(
            [
                make,
                "--no-print-directory",
                target,
                f"INSTALL_DIR={install_dir}",
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    release_home = tmp_path / "release/home"
    release_bin = release_home / ".local/bin"
    release_venv = release_home / ".defenseclaw/.venv/bin"
    release_bin.mkdir(parents=True)
    release_venv.mkdir(parents=True)
    release_cli = release_venv / "defenseclaw"
    release_cli.write_bytes(b"release cli\n")
    release_link = release_bin / "defenseclaw"
    release_link.symlink_to(release_cli)
    release_gateway = release_bin / "defenseclaw-gateway"
    release_gateway.write_bytes(b"release gateway\n")

    refused = run(release_home, release_bin)
    refused_output = refused.stdout + refused.stderr
    assert refused.returncode != 0
    assert "source install refused" in refused_output
    assert "release-owned resolver" in refused_output
    assert "No installed files or services were changed" in refused_output
    assert release_link.readlink() == release_cli
    assert release_gateway.read_bytes() == b"release gateway\n"
    assert not (release_bin / ".defenseclaw-source-root").exists()

    other_home = tmp_path / "other/home"
    other_bin = other_home / ".local/bin"
    other_bin.mkdir(parents=True)
    other_cli = tmp_path / "different-checkout/.venv/bin/defenseclaw"
    (other_bin / "defenseclaw").symlink_to(other_cli)

    refused = run(other_home, other_bin)
    refused_output = refused.stdout + refused.stderr
    assert refused.returncode != 0
    assert "another installation" in refused_output
    assert "release-owned resolver" in refused_output
    assert (other_bin / "defenseclaw").readlink() == other_cli

    refused = run(other_home, other_bin, "_source-install-dev-preflight")
    assert refused.returncode != 0
    assert "another installation" in (refused.stdout + refused.stderr)

    owner_home = tmp_path / "owner/home"
    owner_bin = owner_home / ".local/bin"
    owner_bin.mkdir(parents=True)
    expected_cli = ROOT.resolve() / ".venv/bin/defenseclaw"
    (owner_bin / "defenseclaw").symlink_to(expected_cli)
    (owner_home / ".defenseclaw").mkdir()

    refused = run(owner_home, owner_bin)
    assert refused.returncode != 0
    assert "managed state exists beside a markerless source CLI" in (refused.stdout + refused.stderr)

    allowed = run(owner_home, owner_bin, "_source-install-dev-preflight")
    assert allowed.returncode == 0, allowed.stdout + allowed.stderr
    assert not (owner_bin / ".defenseclaw-source-root").exists()

    owner_gateway = owner_bin / "defenseclaw-gateway"
    owner_gateway.write_bytes(b"owned gateway\n")
    owner_gateway.chmod(0o755)
    gateway_digest = hashlib.sha256(owner_gateway.read_bytes()).hexdigest()
    (owner_bin / ".defenseclaw-source-root").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "checkout_root": str(ROOT.resolve()),
                "source_release": CURRENT_RELEASE,
                "source_install_compatibility_epoch": 2,
                "runtime_config_version": 8,
                "gateway_sha256": gateway_digest,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (owner_bin / "defenseclaw").unlink()
    allowed = run(owner_home, owner_bin)
    assert allowed.returncode == 0, allowed.stdout + allowed.stderr


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX executables")
def test_source_gateway_claim_allows_rebuild_but_rejects_installed_tampering(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "checkout"
    install_dir = tmp_path / "home/.local/bin"
    venv_bin = repo / ".venv/bin"
    repo.mkdir()
    (repo / "scripts").mkdir()
    (repo / "cli/defenseclaw").mkdir(parents=True)
    shutil.copy2(
        ROOT / "scripts/source-install-publish.py",
        repo / "scripts/source-install-publish.py",
    )
    shutil.copy2(
        ROOT / "scripts/source_release_identity.py",
        repo / "scripts/source_release_identity.py",
    )
    shutil.copy2(
        ROOT / "cli/defenseclaw/install_publish.py",
        repo / "cli/defenseclaw/install_publish.py",
    )
    for relative in (
        "pyproject.toml",
        "Makefile",
        "uv.lock",
        "cli/defenseclaw/__init__.py",
        "extensions/defenseclaw/package.json",
        "extensions/defenseclaw/package-lock.json",
        "macos/DefenseClawMac/DefenseClawMac.xcodeproj/project.pbxproj",
        "internal/config/config.go",
        "internal/config/observability_v8_types.go",
        "release/source-install-identity.json",
    ):
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    install_dir.mkdir(parents=True)
    venv_bin.mkdir(parents=True)
    cli = venv_bin / "defenseclaw"
    cli.write_bytes(b"cli\n")
    cli.chmod(0o755)
    (install_dir / "defenseclaw").symlink_to(cli)
    source_gateway = repo / "defenseclaw-gateway"
    installed_gateway = install_dir / "defenseclaw-gateway"

    def write_gateway(path: Path, payload: bytes) -> None:
        path.write_bytes(payload)
        path.chmod(0o755)

    def guard(mode: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "/bin/bash",
                str(ROOT / "scripts/source-install-preflight.sh"),
                mode,
                str(repo),
                str(install_dir),
                ".venv/bin",
                "defenseclaw",
                "defenseclaw-gateway",
            ],
            env={
                **os.environ,
                "HOME": str(tmp_path / "home"),
                "DEFENSECLAW_HOME": str(tmp_path / "home/.defenseclaw"),
                "PATH": "/usr/bin:/bin",
            },
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )

    write_gateway(source_gateway, b"gateway-v1\n")
    write_gateway(installed_gateway, b"gateway-v1\n")
    assert guard("check").returncode == 0
    assert guard("claim").returncode == 0

    write_gateway(source_gateway, b"gateway-v2\n")
    assert guard("check").returncode == 0
    assert guard("publish-gateway").returncode == 0
    assert installed_gateway.read_bytes() == b"gateway-v2\n"
    # A crash after gateway activation but before the final marker claim must
    # be rerunnable when the new installed bytes exactly equal this checkout.
    assert guard("check").returncode == 0
    assert guard("claim").returncode == 0

    marker = (install_dir / ".defenseclaw-source-root").read_text(encoding="utf-8")
    assert hashlib.sha256(b"gateway-v2\n").hexdigest() in marker
    write_gateway(installed_gateway, b"tampered\n")
    refused = guard("check")
    assert refused.returncode != 0
    assert "changed since the last successful source claim" in (refused.stdout + refused.stderr)


@pytest.mark.skipif(os.name == "nt", reason="development installer uses Bash and POSIX symlinks")
def test_direct_dev_installer_refuses_release_install_before_dependency_or_file_changes(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    install_dir = home / ".local/bin"
    release_venv = home / ".defenseclaw/.venv/bin"
    plugin_dir = home / ".defenseclaw/extensions/defenseclaw"
    install_dir.mkdir(parents=True)
    release_venv.mkdir(parents=True)
    plugin_dir.mkdir(parents=True)
    release_cli = release_venv / "defenseclaw"
    release_cli.write_bytes(b"release cli\n")
    cli_link = install_dir / "defenseclaw"
    cli_link.symlink_to(release_cli)
    gateway = install_dir / "defenseclaw-gateway"
    gateway.write_bytes(b"release gateway\n")
    plugin = plugin_dir / "index.js"
    plugin.write_bytes(b"release plugin\n")
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "DEFENSECLAW_HOME": str(home / ".defenseclaw"),
            "PATH": "/usr/bin:/bin",
        }
    )

    completed = subprocess.run(
        ["/bin/bash", str(ROOT / "scripts/install-dev.sh"), "--yes"],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )

    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "source install refused" in output
    assert "release-owned resolver" in output
    assert "Detecting Operating System" not in output
    assert cli_link.readlink() == release_cli
    assert gateway.read_bytes() == b"release gateway\n"
    assert plugin.read_bytes() == b"release plugin\n"
    assert not (install_dir / ".defenseclaw-source-root").exists()


@pytest.mark.skipif(os.name == "nt", reason="parallel source install uses POSIX Make targets")
@pytest.mark.parametrize("target", ("install", "all"))
def test_parallel_make_install_cannot_mutate_managed_files_before_preflight(
    tmp_path: Path,
    target: str,
) -> None:
    make = shutil.which("make")
    if make is None:
        pytest.skip("make is unavailable")

    home = tmp_path / "home"
    install_dir = home / ".local/bin"
    release_venv = home / ".defenseclaw/.venv/bin"
    plugin_dir = home / ".defenseclaw/extensions/defenseclaw"
    install_dir.mkdir(parents=True)
    release_venv.mkdir(parents=True)
    plugin_dir.mkdir(parents=True)
    release_cli = release_venv / "defenseclaw"
    release_cli.write_bytes(b"release cli\n")
    cli_link = install_dir / "defenseclaw"
    cli_link.symlink_to(release_cli)
    gateway = install_dir / "defenseclaw-gateway"
    gateway.write_bytes(b"release gateway\n")
    plugin = plugin_dir / "index.js"
    plugin.write_bytes(b"release plugin\n")
    shell_rc = home / ".zshrc"
    shell_rc.write_bytes(b"preserve shell rc\n")
    config = home / ".defenseclaw/config.yaml"
    config.write_bytes(b"config_version: 7\npreserve: true\n")
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "DEFENSECLAW_HOME": str(home / ".defenseclaw"),
            "PATH": "/usr/bin:/bin",
        }
    )

    completed = subprocess.run(
        [
            make,
            "--no-print-directory",
            "-j4",
            "-o",
            "pycli",
            "-o",
            "gateway",
            "-o",
            "plugin",
            target,
            "CONNECTOR=openclaw",
            f"INSTALL_DIR={install_dir}",
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )

    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "source install refused" in output
    assert cli_link.readlink() == release_cli
    assert gateway.read_bytes() == b"release gateway\n"
    assert plugin.read_bytes() == b"release plugin\n"
    assert shell_rc.read_bytes() == b"preserve shell rc\n"
    assert config.read_bytes() == b"config_version: 7\npreserve: true\n"
    assert not (install_dir / ".defenseclaw-source-root").exists()


@pytest.mark.skipif(os.name == "nt", reason="source install ownership uses POSIX symlinks")
def test_failed_gateway_install_does_not_claim_source_ownership(tmp_path: Path) -> None:
    make = shutil.which("make")
    if make is None or not (ROOT / ".venv/bin/defenseclaw").is_file():
        pytest.skip("make or the checkout CLI is unavailable")

    home = tmp_path / "home"
    install_dir = home / ".local/bin"
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    _write_executable(fake_bin / "uv", "#!/bin/sh\nexit 0\n")
    recursive_make = fake_bin / "recursive-make"
    _write_executable(
        recursive_make,
        '#!/bin/sh\ncase " $* " in\n  *" pycli "*) exit 0 ;;\n  *" gateway "*) exit 42 ;;\n  *) exit 43 ;;\nesac\n',
    )
    _write_executable(
        fake_bin / "go",
        "#!/bin/sh\n"
        'if [ "${1:-}" = "env" ] && [ "${2:-}" = "GOPATH" ]; then\n'
        f"  printf '%s\\n' '{tmp_path}'\n"
        "  exit 0\n"
        "fi\n"
        "exit 42\n",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "DEFENSECLAW_HOME": str(home / ".defenseclaw"),
            "PATH": f"{fake_bin}:/usr/bin:/bin",
        }
    )
    completed = subprocess.run(
        [
            make,
            "--no-print-directory",
            "-j4",
            "-o",
            "pycli",
            "-o",
            "gateway",
            "install",
            "CONNECTOR=none",
            "GATEWAY=missing-source-gateway",
            f"INSTALL_DIR={install_dir}",
            f"MAKE={recursive_make}",
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )

    assert completed.returncode != 0
    assert (install_dir / "defenseclaw").is_symlink()
    assert not (install_dir / "missing-source-gateway").exists()
    assert not (install_dir / ".defenseclaw-source-root").exists()


def test_source_install_docs_are_developer_only_and_point_existing_hosts_to_resolver() -> None:
    for rel in ("README.md", "docs/INSTALL.md"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        normalized = " ".join(text.split())
        assert "development tooling" in text or "developer builds" in text
        assert "not an alternate upgrade mechanism" in normalized or "not an upgrade path" in normalized
        assert "release-owned" in text
        assert "`scripts/upgrade.sh`" in text
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "`scripts/upgrade.ps1`" in readme
    install = (ROOT / "docs/INSTALL.md").read_text(encoding="utf-8")
    assert "does not claim an upgrade" in install


def test_public_operator_docs_never_advertise_direct_defenseclaw_package_install() -> None:
    paths = (
        "README.md",
        "docs/CLI.md",
        "docs/INSTALL.md",
        "docs/OBSERVABILITY.md",
        "docs-site/content/docs/get-started/install.mdx",
        "docs-site/content/docs/get-started/upgrade.mdx",
        "docs-site/content/docs/reference/cli.mdx",
    )
    package_install = re.compile(
        r"\b(?:pipx|pip|uv\s+pip|uv\s+tool)\s+install\b[^\n`]*"
        r"\bdefenseclaw(?:\[|==|@|\s|['\"]|$)",
        re.IGNORECASE,
    )
    for rel in paths:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "uv pip install -e ." not in text
        assert package_install.search(text) is None, rel

    cli = (ROOT / "docs/CLI.md").read_text(encoding="utf-8")
    assert "only in an isolated contributor checkout" in cli
    assert "Do not point raw `pip`, `uv`, editable-install" in cli


def test_quickstart_docs_do_not_pipe_main_installer() -> None:
    for rel, expected_lines in DOC_INSTALL_COMMANDS.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.sh" not in text
        assert "raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.ps1" not in text
        for expected in expected_lines:
            assert expected in text, f"{rel} is missing install snippet line: {expected}"


def test_release_docs_use_one_dispatch_and_never_precreate_tag() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    install = (ROOT / "docs/INSTALL.md").read_text(encoding="utf-8")

    for text in (makefile, install):
        assert "gh workflow run release.yaml --ref main" in text
        assert "-f version=" in text
        assert "-f immutable_releases_confirmed=true" in text
        assert "-f operation=certify" not in text
        assert "-f operation=release" not in text
        assert "git tag 0.4.0" not in text
        assert "git push origin" not in text
    assert "Do not create or push the tag yourself" in install
    normalized = " ".join(install.split())
    assert "One dispatch from a reviewed `main` commit" in normalized
    assert "tests those exact candidate bytes, and publishes them" in normalized
    assert "A merge to `main` is the review-and-CI boundary" in normalized
    assert "certification receipt" not in normalized


def test_upgrade_docs_fail_closed_for_unsupported_sources_without_inferred_hops() -> None:
    install = (ROOT / "docs/INSTALL.md").read_text(encoding="utf-8")
    cli = (ROOT / "docs/CLI.md").read_text(encoding="utf-8")
    guardrail = (ROOT / "docs/GUARDRAIL.md").read_text(encoding="utf-8")

    for text in (install, cli, guardrail):
        assert "remain on the current version" in text.lower()
        assert "contact support" in text.lower()
    assert "newest authenticated `0.7.x`, `0.6.x`, and `0.5.x`" in install
    assert "Sources outside the signed published-baseline policy" in install
    assert "first native Windows release" in install
    assert "does not claim an upgrade" in install
    assert "no Windows hard-cut path is published" in cli
    assert "Explicitly upgrade to `0.8.4`" not in cli
    assert "reach tested baseline `0.4.0`" not in cli
    assert "Upgrading from 0.2.0 to an artifact-backed release" not in install
    assert "--version 0.4.0" not in install


def test_upgrade_docs_use_resolver_only_crash_recovery_without_manual_rollback() -> None:
    install = (ROOT / "docs/INSTALL.md").read_text(encoding="utf-8")
    upgrade_start = install.index("## Upgrading")
    troubleshooting_start = install.index("## Troubleshooting")
    section = install[upgrade_start:troubleshooting_start]

    assert "Re-run that same resolver in latest mode, without a version override" in section
    assert "do not manually copy a backup over live state" in section
    assert "./scripts/upgrade.sh --yes" in section
    assert "first native Windows release is qualified as" in section
    assert "does not claim an upgrade" in section
    assert "upgrade.sh --version" not in section
    assert "VERSION=0.3.0" not in section
    assert "curl -sSfL" not in section


def test_installed_user_upgrade_docs_require_authenticated_resolver_assets() -> None:
    from defenseclaw.resolver_hint import authenticated_resolver_instructions

    cli = (ROOT / "docs/CLI.md").read_text(encoding="utf-8")
    quickstart = (ROOT / "docs/GUARDRAIL_QUICKSTART.md").read_text(encoding="utf-8")
    site = (ROOT / "docs-site/content/docs/get-started/upgrade.mdx").read_text(encoding="utf-8")

    assert "defenseclaw-upgrade.sh" in cli
    assert "verify-blob" in cli
    assert "unset VERSION" in cli
    latest_assets = "releases/latest/download/"
    assert cli.count(latest_assets) == 1
    assert re.search(r"releases/download/\d+\.\d+\.\d+/", cli) is None
    assert f"releases/download/v{CURRENT_RELEASE}/" not in cli
    assert "That URL is only a locator" in " ".join(cli.split())
    generated = authenticated_resolver_instructions(CURRENT_RELEASE)
    assert "Preflight refusal only" in generated
    assert "unset VERSION" in generated
    assert "does not require a source checkout" in quickstart
    assert "does not require a source checkout" in site
    expected_reference = "https://github.com/cisco-ai-defense/defenseclaw/blob/main/docs/CLI.md#upgrade"
    assert expected_reference in site
    assert f"/blob/{CURRENT_RELEASE}/docs/CLI.md#upgrade" not in site
    assert "/blob/v0.8.4/docs/CLI.md#upgrade" not in site


def test_public_docs_never_direct_pre_bridge_clients_to_their_immutable_cli() -> None:
    paths = (
        "docs/INSTALL.md",
        "docs-site/content/docs/get-started/install.mdx",
        "docs-site/content/docs/get-started/upgrade.mdx",
        "docs-site/content/docs/reference/cli.mdx",
    )
    rendered = "\n".join((ROOT / path).read_text(encoding="utf-8") for path in paths)

    assert "upgrade them directly to the latest fixed release" not in rendered
    assert "Signed releases still upgrade without local `cosign`" not in rendered
    assert "0.8.3`-or-older" in rendered
    assert "current release-owned resolver" in rendered
    assert "cannot perform" in rendered or "cannot learn" in rendered


def test_hard_cut_docs_require_target_resolver_for_frozen_controllers() -> None:
    cli = (ROOT / "docs/CLI.md").read_text(encoding="utf-8")
    install = (ROOT / "docs/INSTALL.md").read_text(encoding="utf-8")
    site = (ROOT / "docs-site/content/docs/get-started/upgrade.mdx").read_text(encoding="utf-8")
    guardrail = (ROOT / "docs/GUARDRAIL.md").read_text(encoding="utf-8")
    rendered = "\n".join((cli, install, site, guardrail))

    assert "release-owned POSIX shell resolver performs the supported one-command path" in cli
    assert "Every supported POSIX source uses the authenticated target-release resolver" in install
    assert "immutable `0.8.4` command cannot parse the truthful" in site
    assert "platform_tested_source_versions.windows: []" in site
    assert "bash defenseclaw-upgrade.sh --yes" in install
    assert "bash defenseclaw-upgrade.sh --yes" in site
    assert "PowerShell resolver" in site and "refusal" in site
    assert "first native Windows release" in install
    assert "does not claim an upgrade" in install
    assert "without `--version`" in cli
    assert "Do not add `--version` to the resolver command" in install
    assert "without a target version" in site
    assert "0.8.3` or older" in install
    assert "`0.8.3` or older" in site
    assert rendered.count("obsolete raw") >= 3
    assert "frozen built-in command remains usable" not in rendered
    assert "supports `0.8.4 → 0.8.5`" not in rendered
    assert "curl -fsSL https://raw.githubusercontent.com" not in rendered
    assert "upgrade.sh | bash" not in rendered


def test_windows_bootstrap_binds_native_setup_to_authenticated_signed_outer_bytes() -> None:
    installer = (ROOT / "scripts/install.ps1").read_text(encoding="utf-8")

    assert "function Get-AuthenticatedChecksum" in installer
    assert "$setupSha = Get-AuthenticatedChecksum" in installer
    assert "-ChecksumsContent $ChecksumsContent -FileName $SetupAsset" in installer
    assert "Assert-Sha256 -Path $setup -Expected $setupSha -Label $SetupAsset" in installer
    assert "Authenticated Setup provenance does not match the exact authenticated checksum" in installer
    assert "Assert-SetupAuthenticode -Path $setup" in installer
    assert "function New-PrivateStageRoot" in installer
    assert "Set-PrivateDirectoryProtection -Path $root" in installer
    assert "[IO.FileMode]::CreateNew" in installer
    assert "function Remove-PrivateStageRoot" in installer

    native_setup = installer[installer.index("function Invoke-NativeSetup {") : installer.index("function Main {")]
    checksum = native_setup.index("Assert-Sha256")
    authenticode = native_setup.index("Assert-SetupAuthenticode")
    execute = native_setup.index("Invoke-BoundedNativeProcess")
    assert checksum < authenticode < execute

    main = installer[installer.index("function Main {") :]
    execute = main.index("Invoke-NativeSetup")
    cleanup = main.index("Remove-PrivateStageRoot")
    assert execute < main.index("} finally {") < cleanup


def test_cli_docs_describe_authenticated_same_version_upgrade_as_noop() -> None:
    cli = (ROOT / "docs/CLI.md").read_text(encoding="utf-8")
    normalized = " ".join(cli.split())

    assert "An authenticated same-version request is a no-op" in normalized
    assert "it does not reinstall artifacts or run migrations" in normalized
    assert "run automatically even during same-version upgrades" not in normalized


def test_installer_help_does_not_pipe_main_installer() -> None:
    for rel in INSTALLER_FILES:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "defenseclaw/main" not in text


def test_install_docs_track_current_release() -> None:
    for rel, expected_lines in RELEASE_INSTALL_COMMANDS.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        versioned_lines = tuple(line for line in expected_lines if CURRENT_RELEASE in line)
        assert versioned_lines, f"{rel} must pin at least one installer version"
        for expected in versioned_lines:
            assert expected in text, f"{rel} is missing current install example: {expected}"
            for stale in STALE_RELEASES:
                stale_example = expected.replace(CURRENT_RELEASE, stale)
                assert stale_example not in text, f"{rel} still contains stale install example: {stale_example}"


def test_current_observability_docs_do_not_advertise_retired_redaction_controls() -> None:
    retired_guidance = (
        "--disable-redaction",
        "--enable-redaction",
        "setup redaction",
        "privacy.disable_redaction",
        "disableRedaction",
    )
    for rel in OBSERVABILITY_V8_CURRENT_AUTHORITY_FILES:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for retired in retired_guidance:
            assert retired not in text, f"{rel} still advertises retired control: {retired}"

    guardrail_reference = (ROOT / "docs-site/content/docs/setup/guardrail/index.mdx").read_text()
    assert "Legacy v7 JSONL export" in guardrail_reference


def test_current_observability_guidance_explains_v8_redaction_workflow() -> None:
    required_workflow = (
        "observability.destinations[].routes[].selector.buckets",
        "observability.redaction_profiles",
        "defenseclaw config validate",
        "defenseclaw config show --effective --section observability",
        "defenseclaw observability plan",
        "defenseclaw-gateway restart",
    )
    for rel in OBSERVABILITY_V8_WORKFLOW_GUIDES:
        text = (ROOT / rel).read_text()
        for expected in required_workflow:
            assert expected in text, f"{rel} is missing v8 redaction guidance: {expected}"

    for rel in OBSERVABILITY_V8_CONNECTOR_GUIDES:
        text = (ROOT / rel).read_text()
        assert "observability.destinations[].routes[].selector.buckets" in text
        assert "observability.redaction_profiles" in text


def test_current_observability_docs_describe_jsonl_as_explicit_optional_destination() -> None:
    for rel, expected_wording in OBSERVABILITY_V8_JSONL_GUIDES.items():
        lines = [line for line in (ROOT / rel).read_text().splitlines() if "gateway.jsonl" in line]
        assert lines, f"{rel} must retain its scoped gateway.jsonl guidance"
        for line in lines:
            normalized = line.lower()
            assert "optional" in normalized, f"{rel} treats gateway.jsonl as implicit: {line}"
            assert expected_wording.lower() in normalized, f"{rel} omits the expected JSONL destination wording: {line}"


def test_dev_installer_only_offers_jsonl_tail_when_the_destination_exists() -> None:
    text = (ROOT / "scripts/install-dev.sh").read_text(encoding="utf-8")
    existence_check = 'if [[ -f "${HOME}/.defenseclaw/gateway.jsonl" ]]'
    tail_command = "tail -f ~/.defenseclaw/gateway.jsonl"
    enablement = "add an explicit kind: jsonl destination to create it"
    assert existence_check in text
    assert tail_command in text
    assert enablement in text
    assert text.index(existence_check) < text.index(tail_command) < text.index(enablement)


def test_setup_index_separates_commands_from_policy_reference_cards() -> None:
    text = (ROOT / "docs-site/content/docs/setup/index.mdx").read_text()
    command_start = text.index("## Auxiliary configuration commands")
    reference_start = text.index("## Deployment and policy references")
    matrix_start = text.index("## Interactive vs non-interactive")
    command_cards = text[command_start:reference_start]
    reference_cards = text[reference_start:matrix_start]
    assert 'title="Redaction profiles"' not in command_cards
    assert 'title="Redaction profiles"' in reference_cards
    assert "not\nadditional `defenseclaw setup` verbs" in reference_cards


def test_zeptoclaw_calls_out_local_history_retention_and_trust_boundary() -> None:
    text = (ROOT / "docs-site/content/docs/connectors/zeptoclaw.mdx").read_text()
    for expected in (
        'title="Treat local event history as sensitive data"',
        "observability.local.retention_days",
        "retains 90 days",
        "observability.defaults.redaction_profile",
        "also governs SQLite",
        "only that export trust boundary",
    ):
        assert expected in text


def test_enterprise_example_uses_secure_managed_redaction_default() -> None:
    text = (ROOT / "docs-site/content/docs/setup/enterprise-deployment.mdx").read_text()
    assert "  defaults:\n    redaction_profile: sensitive" in text


def test_readme_observability_edit_workflow_is_fail_fast() -> None:
    text = (ROOT / "README.md").read_text()
    expected = "\n".join(
        (
            "defenseclaw config validate && \\",
            "defenseclaw config show --effective --section observability && \\",
            "defenseclaw observability plan && \\",
            "defenseclaw-gateway restart && \\",
            "defenseclaw doctor",
        )
    )
    assert expected in text
