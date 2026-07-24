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

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

from defenseclaw.platform_support import supported_connectors
from defenseclaw.tui.panels.first_run import CONNECTOR_CHOICES
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = ROOT / "scripts" / "install.sh"
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
UPGRADE_SH = ROOT / "scripts" / "upgrade.sh"


def test_posix_requires_portable_litellm_and_windows_delegates_to_native_setup() -> None:
    install_sh = INSTALL_SH.read_text(encoding="utf-8")
    install_ps1 = INSTALL_PS1.read_text(encoding="utf-8")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert install_sh.count("--only-binary litellm") == 3
    assert "--only-binary litellm" not in install_ps1
    assert "It does not install Python, uv, wheels" in install_ps1
    assert '$SetupAsset = "DefenseClawSetup-x64.exe"' in install_ps1
    expected = SpecifierSet(">=1.84.0,<1.92.0")
    direct = {requirement.name: requirement for requirement in map(Requirement, project["project"]["dependencies"])}
    overrides = {
        requirement.name: requirement
        for requirement in map(Requirement, project["tool"]["uv"]["override-dependencies"])
    }
    assert direct["litellm"].specifier == expected
    assert overrides["litellm"].specifier == expected


WINDOWS_NATIVE_WORKFLOW = ROOT / ".github" / "workflows" / "windows-native.yml"
MAKEFILE = ROOT / "Makefile"
INSTALL_DOC = ROOT / "docs" / "INSTALL.md"


def test_local_dist_is_never_advertised_as_authenticated_release_input() -> None:
    posix = INSTALL_SH.read_text(encoding="utf-8")
    windows = INSTALL_PS1.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")
    docs = INSTALL_DOC.read_text(encoding="utf-8")

    assert "unsigned directory produced by `make dist` is intentionally rejected" in posix
    assert "Authenticated Setup provenance does not declare its signing state" in windows
    assert "Setup signing state conflicts with authenticated provenance" in windows
    assert "Invoke-StagedChecksumVerification" in windows
    assert "$(DIST_DIR)/ is not authenticated installer input for 0.8.4+" in makefile
    assert "Do not pass the unsigned output of `make dist`" in docs
    assert "signed checksums and certificate" in docs
    assert "./scripts/install.sh --local dist/" not in docs


def test_existing_install_refusal_names_authenticated_latest_mode_resolver() -> None:
    posix = INSTALL_SH.read_text(encoding="utf-8")
    windows = INSTALL_PS1.read_text(encoding="utf-8")

    assert posix.count("authenticated release-owned upgrade resolver from the target release in latest mode") == 2
    assert "bash defenseclaw-upgrade.sh --yes" in posix
    assert "Do not pass --version" in posix
    assert "blob/main/docs/CLI.md#upgrade" in posix

    # Windows servicing is owned by the authenticated native Setup executable;
    # the compatibility bootstrap must not route existing installs through the
    # legacy PowerShell upgrade resolver.
    assert '$SetupAsset = "DefenseClawSetup-x64.exe"' in windows
    assert "$arguments = New-SetupArgumentList" in windows
    assert "return Invoke-BoundedNativeProcess -FilePath $SetupPath" in windows
    assert "defenseclaw-upgrade.ps1" not in windows


def test_windows_native_workflow_builds_exact_setup_before_lifecycle_acceptance() -> None:
    workflow = WINDOWS_NATIVE_WORKFLOW.read_text(encoding="utf-8")
    package_match = re.search(r"(?ms)^  package-artifact:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)", workflow)
    acceptance_match = re.search(r"(?ms)^  packaged-acceptance:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)", workflow)
    assert package_match is not None
    assert acceptance_match is not None
    package = package_match.group(0)
    acceptance = acceptance_match.group(0)

    artifacts = package.index("-Operation build-artifacts")
    installer = package.index("-Operation build-installer")
    wizard = package.index("-Mode wizard-smoke")
    upload = package.index("name: windows-native-package")
    assert artifacts < installer < wizard < upload
    assert "installer smoke stub" not in package
    assert "needs: package-artifact" in acceptance
    assert "name: windows-native-package" in acceptance
    assert "-Mode setup-acceptance" in acceptance


def test_sandbox_installer_fallback_uses_selected_release() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "raw.githubusercontent.com/${REPO}/main/scripts/install-openshell-sandbox.sh" not in text
    assert "raw.githubusercontent.com/${REPO}/${RELEASE_VERSION}/scripts/install-openshell-sandbox.sh" in text


def test_release_installers_track_known_connector_choices() -> None:
    sh_text = INSTALL_SH.read_text(encoding="utf-8")
    sh_match = re.search(r"readonly CONNECTOR_CHOICES=\(([^)]*)\)", sh_text)
    assert sh_match is not None
    shell_choices = tuple(sh_match.group(1).split())

    ps_text = INSTALL_PS1.read_text(encoding="utf-8")
    ps_match = re.search(r"\$ConnectorChoices = @\((.*?)\)", ps_text, re.DOTALL)
    assert ps_match is not None
    ps_choices = tuple(re.findall(r'"([^"]+)"', ps_match.group(1)))
    hook_literal_match = re.search(
        r"\$HookConnectors = @\((.*?)\)",
        ps_text,
        re.DOTALL,
    )
    if hook_literal_match is not None:
        hook_choices = tuple(re.findall(r'"([^"]+)"', hook_literal_match.group(1)))
    else:
        hook_filter_match = re.search(
            r"\$HookConnectors = \$ConnectorChoices \| Where-Object "
            r"\{ \$_ -notin @\((.*?)\) \}",
            ps_text,
            re.DOTALL,
        )
        assert hook_filter_match is not None
        hook_exclusions = tuple(re.findall(r'"([^"]+)"', hook_filter_match.group(1)))
        hook_choices = tuple(choice for choice in ps_choices if choice not in hook_exclusions)

    assert shell_choices == (*CONNECTOR_CHOICES, "none")

    windows_choices = tuple(supported_connectors(CONNECTOR_CHOICES, "windows"))
    assert ps_choices == (*windows_choices, "none")
    assert hook_choices == ()


def test_posix_install_and_upgrade_validate_cli_before_launcher_publication() -> None:
    install_text = INSTALL_SH.read_text(encoding="utf-8")
    install_cli = install_text.split("install_python_cli()", 1)[1].split("# ── Install: OpenClaw Plugin", 1)[0]
    validation = '"${DEFENSECLAW_VENV}/bin/defenseclaw" --help'
    assert install_cli.index("uv pip install") < install_cli.index(validation)
    assert install_cli.index(validation) < install_cli.index("fresh-symlink")

    upgrade_text = UPGRADE_SH.read_text(encoding="utf-8")
    install_start = upgrade_text.index('VENV_PYTHON="${DEFENSECLAW_VENV}/bin/python"')
    launcher = upgrade_text.index('ln -sf "${DEFENSECLAW_VENV}/bin/defenseclaw"', install_start)
    upgrade_install = upgrade_text[install_start:launcher]
    assert upgrade_install.index("pip install") < upgrade_install.index(validation)


def test_posix_upgrade_binds_sigstore_to_exact_release_workflow() -> None:
    text = UPGRADE_SH.read_text(encoding="utf-8")

    identity = "https://github.com/${REPO}/.github/workflows/release.yaml@refs/heads/main"
    assert f'--certificate-identity "{identity}"' in text
    assert f"--certificate-identity '{identity}'" in text
    assert "--certificate-identity-regexp" not in text
