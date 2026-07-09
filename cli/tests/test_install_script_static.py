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
UPGRADE_SH = ROOT / "scripts" / "upgrade.sh"


def test_sandbox_installer_fallback_uses_selected_release() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "raw.githubusercontent.com/${REPO}/main/scripts/install-openshell-sandbox.sh" not in text
    assert (
        "raw.githubusercontent.com/${REPO}/${RELEASE_VERSION}/scripts/install-openshell-sandbox.sh"
        in text
    )


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
            r'\{ \$_ -notin @\((.*?)\) \}',
            ps_text,
            re.DOTALL,
        )
        assert hook_filter_match is not None
        hook_exclusions = tuple(
            re.findall(r'"([^"]+)"', hook_filter_match.group(1))
        )
        hook_choices = tuple(
            choice for choice in ps_choices if choice not in hook_exclusions
        )

    assert shell_choices == (*CONNECTOR_CHOICES, "none")

    windows_choices = tuple(supported_connectors(CONNECTOR_CHOICES, "windows"))
    assert ps_choices == (*windows_choices, "none")
    assert hook_choices == ()


def test_posix_install_and_upgrade_validate_tui_before_launcher_publication() -> None:
    install_text = INSTALL_SH.read_text(encoding="utf-8")
    install_cli = install_text.split("install_python_cli()", 1)[1].split(
        "# ── Install: OpenClaw Plugin", 1
    )[0]
    assert install_cli.index("pip check") < install_cli.index("app.run_test(size=(80, 24))")
    assert install_cli.index("app.run_test(size=(80, 24))") < install_cli.index("ln -sf")

    upgrade_text = UPGRADE_SH.read_text(encoding="utf-8")
    install_start = upgrade_text.index('VENV_PYTHON="${DEFENSECLAW_VENV}/bin/python"')
    launcher = upgrade_text.index('ln -sf "${DEFENSECLAW_VENV}/bin/defenseclaw"', install_start)
    upgrade_install = upgrade_text[install_start:launcher]
    assert upgrade_install.index("pip check") < upgrade_install.index("app.run_test(size=(80, 24))")
