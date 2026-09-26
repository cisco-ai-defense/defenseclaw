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
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
# Checked-in source fixtures and published documentation share one release
# identity so native repair/upgrade comparisons remain monotonic.
CURRENT_RELEASE = "0.8.10"
CURRENT_PUBLISHED_RELEASE = "0.8.10"
LATEST_POSIX_INSTALL_URL = (
    "https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/install.sh"
)
LATEST_POSIX_INSTALL_COMMAND = f"curl -LsSf {LATEST_POSIX_INSTALL_URL} | bash"
LATEST_WINDOWS_INSTALL_COMMAND = (
    "irm https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/install.ps1 | iex"
)
DOC_INSTALL_COMMANDS = {
    "docs-site/content/docs/get-started/install.mdx": (
        LATEST_POSIX_INSTALL_COMMAND,
        LATEST_WINDOWS_INSTALL_COMMAND,
    ),
    "docs-site/content/docs/get-started/first-guardrail.mdx": (
        f"{LATEST_POSIX_INSTALL_COMMAND} -s -- --connector claudecode",
    ),
    "docs-site/components/terminal-demo.tsx": (
        f"text: '{LATEST_POSIX_INSTALL_COMMAND}',",
    ),
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
    "docs-site/content/docs/setup/index.mdx",
    "docs-site/content/docs/reference/redaction.mdx",
    "docs-site/content/docs/reference/cli.mdx",
    "docs-site/content/docs/observability/index.mdx",
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
    assert "defenseclaw upgrade" in refused_output
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
    assert "defenseclaw upgrade" in refused_output
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
    assert "defenseclaw upgrade" in output
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
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    install = (ROOT / "docs/INSTALL.md").read_text(encoding="utf-8")

    for text in (readme, install):
        normalized = " ".join(text.split())
        assert "development tooling" in normalized or "contributor tooling" in normalized
        assert "not an alternate upgrade mechanism" in normalized or "not an installation or upgrade path" in normalized
        assert "`defenseclaw upgrade`" in text

    assert "source of truth for installation" in readme
    assert "https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/upgrade/" in readme
    assert "do not claim an upgrade" in " ".join(install.split())


def test_public_operator_docs_never_advertise_direct_defenseclaw_package_install() -> None:
    paths = {
        "README.md",
        "docs/CLI.md",
        "docs/INSTALL.md",
        "docs/OBSERVABILITY.md",
        *(
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "docs-site/content/docs").rglob("*.mdx")
        ),
    }
    package_install = re.compile(
        r"\b(?:pipx|pip|uv\s+pip|uv\s+tool)\s+install\b[^\n`]*"
        r"\bdefenseclaw(?:\[|==|@|\s|['\"]|$)",
        re.IGNORECASE,
    )
    scanner_install = re.compile(
        r"\b(?:pipx|pip|uv\s+pip|uv\s+tool)\s+install\b[^\n`]*"
        r"\b(?:cisco-ai-(?:skill|mcp)-scanner|skill-scanner|mcp-scanner)"
        r"(?:==|@|\s|['\"]|$)",
        re.IGNORECASE,
    )
    for rel in sorted(paths):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "uv pip install -e ." not in text
        assert package_install.search(text) is None, rel
        assert scanner_install.search(text) is None, rel

    cli = (ROOT / "docs/CLI.md").read_text(encoding="utf-8")
    assert "published CLI reference" in cli
    assert "https://cisco-ai-defense.github.io/defenseclaw/docs/reference/cli/" in cli


def test_repository_operator_pointers_delegate_to_the_canonical_website() -> None:
    expected = {
        "docs/API.md": "https://cisco-ai-defense.github.io/defenseclaw/docs/reference/gateway-api/",
        "docs/CLI.md": "https://cisco-ai-defense.github.io/defenseclaw/docs/reference/cli/",
        "docs/CONFIG_FILES.md": "https://cisco-ai-defense.github.io/defenseclaw/docs/reference/configuration/",
        "docs/CONNECTOR-MATRIX.md": "https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/compatibility/",
        "docs/ENV-VARS.md": "https://cisco-ai-defense.github.io/defenseclaw/docs/reference/env-vars/",
        "docs/INSTALL.md": "https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/install/",
        "docs/QUICKSTART.md": "https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/quickstart/",
        "docs/REGISTRIES.md": "https://cisco-ai-defense.github.io/defenseclaw/docs/setup/registries/",
        "docs/SPLUNK_APP.md": "https://cisco-ai-defense.github.io/defenseclaw/docs/observability/splunk/",
    }
    for rel, canonical_url in expected.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        normalized = " ".join(text.split()).lower()
        assert canonical_url in text, rel
        assert "website" in normalized or "published" in normalized, rel
        assert len(text.splitlines()) <= 40, f"{rel} grew beyond a stable pointer page"


def test_scanner_recovery_docs_match_dependency_and_registry_contracts() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    mcp_docs = (ROOT / "docs-site/content/docs/setup/mcp-scanner.mdx").read_text(
        encoding="utf-8"
    )
    registry_docs = (
        ROOT / "docs-site/content/docs/setup/registries.mdx"
    ).read_text(encoding="utf-8")
    llm_source = (ROOT / "cli/defenseclaw/llm.py").read_text(encoding="utf-8")
    mcp_source = (ROOT / "cli/defenseclaw/scanner/mcp.py").read_text(
        encoding="utf-8"
    )

    assert "python_version>='3.11'" in pyproject
    assert "including a POSIX release install" in mcp_docs
    assert "Use Python 3.11 or newer" in mcp_docs
    assert "affected skill scans fail" in registry_docs
    assert "marked `error`" in registry_docs
    assert "MCP entries" in registry_docs and "remain `pending`" in registry_docs
    assert "cli extra" not in llm_source
    assert "mcp-scan extra" not in mcp_source


def test_quickstart_docs_do_not_pipe_main_installer() -> None:
    for rel, expected_lines in DOC_INSTALL_COMMANDS.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.sh" not in text
        assert "raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.ps1" not in text
        for expected in expected_lines:
            assert expected in text, f"{rel} is missing install snippet line: {expected}"


def test_release_docs_use_one_dispatch_and_never_precreate_tag() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    runbook = (ROOT / "docs/RELEASE_RUNBOOK.md").read_text(encoding="utf-8")

    for text in (makefile, runbook):
        assert "gh workflow run release.yaml" in text
        assert "--repo cisco-ai-defense/defenseclaw" in text
        assert "--ref main" in text
        assert "-f version=" in text
        assert "git tag" not in text
        assert "git push origin" not in text
















def test_installer_help_does_not_pipe_main_installer() -> None:
    for rel in INSTALLER_FILES:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "defenseclaw/main" not in text


def test_published_posix_install_examples_default_to_latest_release() -> None:
    for rel, expected_lines in DOC_INSTALL_COMMANDS.items():
        text = (ROOT / rel).read_text(encoding="utf-8")
        stripped_lines = {line.strip() for line in text.splitlines()}
        latest_lines = tuple(line for line in expected_lines if LATEST_POSIX_INSTALL_URL in line)
        assert latest_lines, f"{rel} must install from the latest release asset"
        for expected in latest_lines:
            assert expected in stripped_lines, f"{rel} is missing latest install example: {expected}"
        assert text.count(LATEST_POSIX_INSTALL_URL) == 1
        assert "raw.githubusercontent.com/cisco-ai-defense/defenseclaw/" not in text
        assert "INSTALL_URL=" not in text
        assert "INSTALL_VERSION" not in text

    install_page = (
        ROOT / "docs-site/content/docs/get-started/install.mdx"
    ).read_text(encoding="utf-8")
    assert install_page.index(LATEST_POSIX_INSTALL_COMMAND) < install_page.index(
        "## Prerequisites"
    )


def test_current_observability_docs_do_not_advertise_retired_redaction_controls() -> None:
    retired_guidance = (
        "--disable-redaction",
        "--enable-redaction",
        "setup redaction on",
        "setup redaction off",
        "privacy.disable_redaction",
        "disableRedaction",
    )
    for rel in OBSERVABILITY_V8_CURRENT_AUTHORITY_FILES:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for retired in retired_guidance:
            assert retired not in text, f"{rel} still advertises retired control: {retired}"

    guardrail_reference = (ROOT / "docs-site/content/docs/setup/guardrail/index.mdx").read_text(encoding="utf-8")
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
        text = (ROOT / rel).read_text(encoding="utf-8")
        for expected in required_workflow:
            assert expected in text, f"{rel} is missing v8 redaction guidance: {expected}"

    for rel in OBSERVABILITY_V8_CONNECTOR_GUIDES:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "observability.destinations[].routes[].selector.buckets" in text
        assert "observability.redaction_profiles" in text


def test_current_observability_docs_describe_jsonl_as_explicit_optional_destination() -> None:
    for rel, expected_wording in OBSERVABILITY_V8_JSONL_GUIDES.items():
        lines = [line for line in (ROOT / rel).read_text(encoding="utf-8").splitlines() if "gateway.jsonl" in line]
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
    text = (ROOT / "docs-site/content/docs/setup/index.mdx").read_text(encoding="utf-8")
    command_start = text.index("## Auxiliary configuration commands")
    reference_start = text.index("## Deployment and policy references")
    matrix_start = text.index("## Interactive vs non-interactive")
    command_cards = text[command_start:reference_start]
    reference_cards = text[reference_start:matrix_start]
    assert 'title="setup redaction"' in command_cards
    assert 'title="Redaction profiles"' in reference_cards
    assert "more depth\nthan the command cards above" in reference_cards


def test_redaction_cli_docs_cover_simple_advanced_and_scripted_workflows() -> None:
    redaction = (ROOT / "docs-site/content/docs/reference/redaction.mdx").read_text(encoding="utf-8")
    setup = (ROOT / "docs-site/content/docs/setup/index.mdx").read_text(encoding="utf-8")
    cli = (ROOT / "docs-site/content/docs/reference/cli.mdx").read_text(encoding="utf-8")

    for text in (redaction, setup, cli):
        assert "defenseclaw setup redaction" in text
        normalized = " ".join(text.replace("**", "").split())
        assert "Show advanced settings?" in normalized
        assert "remove-all" in text
    for expected in (
        "bucket set",
        "profile set",
        "destination send",
        "route add",
        "--dry-run",
        "managed enterprise destination",
        "config.yaml.before-redaction",
    ):
        assert expected in redaction


def test_redaction_workflow_documents_linux_windows_macos_and_tui_surfaces() -> None:
    redaction = (ROOT / "docs-site/content/docs/reference/redaction.mdx").read_text(encoding="utf-8")
    setup = (ROOT / "docs-site/content/docs/setup/index.mdx").read_text(encoding="utf-8")
    cli = (ROOT / "docs-site/content/docs/reference/cli.mdx").read_text(encoding="utf-8")
    windows_paths = (
        ROOT / "docs-site/content/docs/get-started/windows/paths-troubleshooting.mdx"
    ).read_text(encoding="utf-8")

    for expected in (
        "macOS, Linux, and native Windows",
        "Setup → Redaction Policy",
        "%USERPROFILE%\\.defenseclaw\\backups\\config.yaml.before-redaction",
        "protected current-user/SYSTEM DACL",
        "0700`/`0600",
    ):
        assert expected in redaction
    assert "TUI → Setup → Redaction Policy" in setup
    assert "Logs → Redaction policy…" in setup
    assert "config.yaml.before-redaction-*" in windows_paths
    assert (
        "`defenseclaw setup redaction "
        "[status\\|remove-all\\|apply\\|defaults\\|bucket\\|profile\\|destination\\|route]`"
        in cli
    )
    for command_surface in (
        "status --json",
        "remove-all --dry-run",
        "apply --scope",
        "defaults set",
        "bucket set",
        "profile set",
        "destination send",
        "route add",
    ):
        assert f"defenseclaw setup redaction {command_surface}" in redaction


def test_macos_redaction_sheet_exposes_the_complete_advanced_cli_surface() -> None:
    source = (
        ROOT / "macos/DefenseClawMac/DefenseClawMac/Features/LogsView.swift"
    ).read_text(encoding="utf-8")

    assert 'DisclosureGroup("Show advanced settings"' in source
    for action in (
        "case bucketList",
        "case bucketSet",
        "case bucketReset",
        "case profileList",
        "case profileShow",
        "case profileSet",
        "case profileRemove",
        "case destinationShow",
        "case destinationSend",
        "case destinationInherit",
        "case routeList",
        "case routeAdd",
        "case routeSet",
        "case routeMove",
        "case routeRemove",
    ):
        assert action in source
    for expected in (
        '"compliance.activity"',
        '"diagnostic"',
        '"--producer-action"',
        '"--event-name"',
        '"--min-severity"',
        '"--dry-run"',
        "if result.succeeded",
        "resetActionFields()",
    ):
        assert expected in source
    assert '"setup", "redaction", "apply"' in source
    assert '"--profile", profile' in source
    assert 'routeBuckets = action == .destinationSend ? "*" : ""' in source
    assert (
        "if result.succeeded, action.isMutation, !dryRun {\n                resetActionFields()\n            }"
        in source
    )


def test_zeptoclaw_calls_out_local_history_retention_and_trust_boundary() -> None:
    text = (ROOT / "docs-site/content/docs/connectors/zeptoclaw.mdx").read_text()
    for expected in (
        'title="Treat local event history as sensitive data"',
        "observability.local.retention_days",
        "retains seven days",
        "observability.defaults.redaction_profile",
        "also governs SQLite",
        "only that export trust boundary",
    ):
        assert expected in text


def test_enterprise_example_uses_secure_managed_redaction_default() -> None:
    text = (ROOT / "docs-site/content/docs/setup/enterprise-deployment.mdx").read_text()
    assert "  defaults:\n    redaction_profile: sensitive" in text


def test_readme_delegates_observability_operations_to_the_website() -> None:
    readme = (ROOT / "README.md").read_text()
    implementation = (ROOT / "docs/OBSERVABILITY.md").read_text()

    assert "https://cisco-ai-defense.github.io/defenseclaw/docs/observability/" in readme
    assert "schemas/telemetry/v8/registry.yaml" in implementation
    assert "make telemetry-generate" in implementation
    assert "make telemetry-check" in implementation
    assert "defenseclaw-gateway restart" not in readme


def test_policy_overview_matches_atomic_invalid_regex_rejection() -> None:
    overview = (ROOT / "docs-site/content/docs/policies/index.mdx").read_text()
    validation = (ROOT / "docs-site/content/docs/policies/rulepack-validation.mdx").read_text()

    assert "logged and dropped" not in overview
    assert "rejects the complete candidate" in overview
    assert "Regexes compile during [rule-pack validation]" in overview
    assert "/docs/policies/rulepack-validation" in overview
    assert "invalid Go regular expression" in validation
    assert "does not silently discard the bad file" in " ".join(validation.split())
