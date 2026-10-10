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

"""The release runbook's rules must match the code they protect."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs" / "RELEASE_RUNBOOK.md"


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_runbook_documents_release_draft_and_yank() -> None:
    runbook = _text("docs/RELEASE_RUNBOOK.md")

    assert "gh workflow run release.yaml --repo cisco-ai-defense/defenseclaw --ref main -f version=X.Y.Z" in runbook
    assert "gh release edit X.Y.Z --draft=false --latest" in runbook
    assert "gh release edit X.Y.Z --prerelease" in runbook
    assert "never delete" in runbook.lower()
    assert "operation: legacy-channel" in runbook


def test_permanent_asset_names_are_what_the_release_publishes_and_clients_fetch() -> None:
    runbook = _text("docs/RELEASE_RUNBOOK.md")
    workflow = _text(".github/workflows/release.yaml")
    shim = _text("cli/defenseclaw/upgrade_shim.py")

    for asset in ("install.sh", "install.ps1", "defenseclaw-upgrade.sh"):
        assert f"`{asset}`" in runbook
        assert f"  {asset.replace('.', chr(92) + '.')}$" in workflow
    assert '"install.ps1" if os.name == "nt" else "install.sh"' in shim
    assert "releases/download/{version}" in shim


def test_permanent_installer_flags_are_documented_and_accepted() -> None:
    runbook = _text("docs/RELEASE_RUNBOOK.md")
    install_sh = _text("scripts/install.sh")

    for flag in ("--yes", "--version", "--local", "--rollback"):
        assert f"`{flag}`" in runbook
        assert re.search(rf"^\s+{re.escape(flag)}[)|]", install_sh, re.MULTILINE), flag
    # Only the copy defenseclaw upgrade runs ignores an unknown flag.
    assert '[[ -n "${RUN_BY_UPGRADE}" ]] || usage_error "Unknown option: $1"\n            warn "Ignoring unknown option: $1" ;;' in install_sh


def test_handoff_marker_in_runbook_matches_the_script() -> None:
    runbook = _text("docs/RELEASE_RUNBOOK.md")
    handoff_last_line = _text("scripts/defenseclaw-upgrade.sh").splitlines()[-1]

    assert f"`{handoff_last_line}`" in runbook


def test_config_schema_rule_names_real_code() -> None:
    runbook = _text("docs/RELEASE_RUNBOOK.md")

    assert "CONFIG_MIGRATIONS" in runbook and "CONFIG_MIGRATIONS:" in _text("cli/defenseclaw/migrations.py")
    assert "CURRENT_CONFIG_VERSION" in runbook and "CURRENT_CONFIG_VERSION = " in _text("cli/defenseclaw/config.py")
    go_config = "".join(path.read_text(encoding="utf-8") for path in (ROOT / "internal/config").glob("*.go"))
    assert "MaxSupportedConfigVersion" in runbook and "MaxSupportedConfigVersion" in go_config


def test_dry_run_cannot_sign_publish_or_read_release_secrets() -> None:
    import yaml

    workflow = yaml.safe_load(_text(".github/workflows/release.yaml"))
    dry_run = workflow[True]["workflow_dispatch"]["inputs"]["dry_run"]
    assert dry_run["type"] == "boolean" and dry_run["default"] is False
    jobs = workflow["jobs"]
    # Each job that signs, releases or pushes is skipped by its own condition.
    for name in ("sign", "publish", "legacy-channel"):
        assert "!inputs.dry_run" in jobs[name]["if"], name
    for name, job in jobs.items():
        # `inputs.dry_run && '' || 'release'` would always pick 'release'.
        if name != "legacy-channel" and "environment" in job:
            assert job["environment"] == "${{ !inputs.dry_run && 'release' || '' }}", name
        for step in job.get("steps", []):
            run = step.get("run", "")
            publishing = ("gh release create", "gh release edit", "publish-release-channel", "cosign sign-blob")
            if any(cmd in run for cmd in publishing):
                assert '[[ "$DRY_RUN" != true ]] ||' in run, (name, step.get("name"))
            for key, value in step.get("env", {}).items():
                if "secrets." in str(value):
                    guarded = str(value).startswith("${{ !inputs.dry_run && secrets.")
                    assert name == "legacy-channel" or guarded, (name, key)
