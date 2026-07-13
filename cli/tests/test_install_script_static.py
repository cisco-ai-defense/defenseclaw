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

import re
from pathlib import Path

from defenseclaw.platform_support import supported_connectors
from defenseclaw.tui.panels.first_run import CONNECTOR_CHOICES

ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = ROOT / "scripts" / "install.sh"
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"


def test_installers_require_portable_litellm_wheels() -> None:
    install_sh = INSTALL_SH.read_text(encoding="utf-8")
    install_ps1 = INSTALL_PS1.read_text(encoding="utf-8")
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert install_sh.count("--only-binary litellm") == 3
    assert "--only-binary litellm" in install_ps1
    assert project.count('"litellm>=1.84.0,<1.92.0"') == 1


CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = ROOT / "Makefile"
INSTALL_DOC = ROOT / "docs" / "INSTALL.md"


def test_unsigned_local_dist_is_never_advertised_as_schema2_installer_input() -> None:
    posix = INSTALL_SH.read_text(encoding="utf-8")
    windows = INSTALL_PS1.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")
    docs = INSTALL_DOC.read_text(encoding="utf-8")

    assert "unsigned directory produced by `make dist` is intentionally rejected" in posix
    assert "unsigned directory produced by `make dist` is rejected" in windows
    assert "$(DIST_DIR)/ is not authenticated installer input for 0.8.4+" in makefile
    assert "Do not pass the unsigned output of `make dist`" in docs
    assert "signed checksums and certificate" in docs
    assert "./scripts/install.sh --local dist/" not in docs


def test_existing_install_refusal_names_authenticated_latest_mode_resolver() -> None:
    posix = INSTALL_SH.read_text(encoding="utf-8")
    windows = INSTALL_PS1.read_text(encoding="utf-8")

    assert posix.count(
        "authenticated release-owned upgrade resolver from the target release in latest mode"
    ) == 2
    assert "bash defenseclaw-upgrade.sh --yes" in posix
    assert "Do not pass --version" in posix
    assert "blob/main/docs/CLI.md#upgrade" in posix

    assert (
        "authenticated release-owned upgrade resolver from the target release in latest mode"
    ) in windows
    assert "& .\\defenseclaw-upgrade.ps1 -Yes" in windows
    assert "Do not pass -Version" in windows
    assert "blob/main/docs/CLI.md#upgrade" in windows
    assert "defenseclaw upgrade where supported" not in windows


def test_windows_installer_smoke_never_stubs_schema2_provenance() -> None:
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^  windows-installer-smoke:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    assert match is not None
    job = match.group(0)

    assert "must never stub provenance verification" in job
    legacy_epoch = job.index('payload["source_install_compatibility_epoch"] = 1')
    legacy_runtime = job.index('payload["runtime_config_version"] = 7')
    stamp = job.index("scripts/stamp-version.sh 0.8.3")
    assert legacy_epoch < stamp
    assert legacy_runtime < stamp
    assert 'payload.get("schema_version") != 1' in job
    assert "scripts/stamp-version.sh 0.8.3" in job
    assert "scripts/source_release_identity.py check --expected-release 0.8.3" in job
    assert "main.version=0.8.3" in job
    assert "make dist-upgrade-manifest" in job
    assert "make dist-upgrade-manifest dist-checksums" not in job
    assert "hashlib.sha256(path.read_bytes()).hexdigest()" in job
    assert 'path.relative_to(root).as_posix()' in job
    assert 'manifest.get("schema_version") != 1' in job
    assert 'manifest.get("release_version") != "0.8.3"' in job
    assert '"release_artifacts" in manifest' in job
    assert "cosign.cmd" not in job
    assert "installer smoke stub" not in job
    assert "DEFENSECLAW-PROTECTED-ARTIFACT-V1" not in job
    assert "did not report exact 0.8.3" in job
    assert "Native installer rollback self-test (PowerShell 5.1 + 7)" in job
    assert '@("powershell.exe", "pwsh")' in job
    assert "-TestMode" in job
    assert "-NativePrivateDirectorySelfTestRoot $root" in job
    assert "native installer self-test failed" in job
    assert "native installer self-test left residue" in job

    native = job.index("Native installer rollback self-test (PowerShell 5.1 + 7)")
    policy = job.index("Build and verify legacy installer policy fixture")
    install = job.index("Run install.ps1 against local artifacts")
    assert native < job.index("actions/setup-go")
    assert native < job.index("astral-sh/setup-uv")
    assert native < job.index("Stamp legacy schema-1 installer fixture")
    assert native < job.index("Build gateway binary + CLI wheel")
    assert native < policy < install
    assert policy < job.index("upgrade-manifest.json", policy) < install
    assert policy < job.index("make dist-upgrade-manifest", policy) < install
    assert policy < job.index('root / "checksums.txt"', policy) < install


def test_sandbox_installer_fallback_uses_selected_release() -> None:
    text = INSTALL_SH.read_text()
    assert "raw.githubusercontent.com/${REPO}/main/scripts/install-openshell-sandbox.sh" not in text
    assert (
        "raw.githubusercontent.com/${REPO}/${RELEASE_VERSION}/scripts/install-openshell-sandbox.sh"
        in text
    )


def test_release_installers_track_known_connector_choices() -> None:
    sh_text = INSTALL_SH.read_text()
    sh_match = re.search(r"readonly CONNECTOR_CHOICES=\(([^)]*)\)", sh_text)
    assert sh_match is not None
    shell_choices = tuple(sh_match.group(1).split())

    ps_text = INSTALL_PS1.read_text()
    ps_match = re.search(r"\$ConnectorChoices = @\((.*?)\)", ps_text, re.DOTALL)
    assert ps_match is not None
    ps_choices = tuple(re.findall(r'"([^"]+)"', ps_match.group(1)))
    hook_match = re.search(
        r"\$HookConnectors = \$ConnectorChoices \| Where-Object "
        r'\{ \$_ -notin @\((.*?)\) \}',
        ps_text,
        re.DOTALL,
    )
    assert hook_match is not None
    hook_exclusions = tuple(re.findall(r'"([^"]+)"', hook_match.group(1)))

    assert shell_choices == (*CONNECTOR_CHOICES, "none")

    windows_choices = tuple(supported_connectors(CONNECTOR_CHOICES, "windows"))
    assert ps_choices == (*windows_choices, "none")
    assert hook_exclusions == ("codex", "claudecode", "none")
    assert tuple(c for c in ps_choices if c not in hook_exclusions) == tuple(
        c for c in windows_choices if c not in hook_exclusions
    )
