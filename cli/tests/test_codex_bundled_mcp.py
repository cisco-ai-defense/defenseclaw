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

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw import connector_paths
from defenseclaw.commands.cmd_mcp import mcp
from defenseclaw.config import MCPServerEntry
from defenseclaw.enforce import PolicyEngine
from defenseclaw.models import ScanResult

from tests.helpers import cleanup_app, make_app_context

_DOCS_NAME = "openaiDeveloperDocs"
_DOCS_URL = "https://developers.openai.com/mcp"


def test_codex_marks_only_exact_user_docs_entry_bundled(tmp_path, monkeypatch) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    (codex_home / "config.toml").write_text(
        f'[mcp_servers.{_DOCS_NAME}]\nurl = "{_DOCS_URL}"\n\n'
        "[mcp_servers.node_repl]\ncommand = \"node_repl\"\nargs = []\n",
        encoding="utf-8",
    )

    by_name = {
        entry.name: entry for entry in connector_paths.mcp_servers("codex")
    }

    assert by_name[_DOCS_NAME].bundled is True
    assert by_name[_DOCS_NAME].source_scope == "user"
    assert by_name["node_repl"].bundled is False


def test_codex_docs_entry_with_extra_fields_is_not_exempt(tmp_path, monkeypatch) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    (codex_home / "config.toml").write_text(
        f'[mcp_servers.{_DOCS_NAME}]\nurl = "{_DOCS_URL}"\n'
        'http_headers = { Authorization = "operator-controlled" }\n',
        encoding="utf-8",
    )

    entries = connector_paths.mcp_servers("codex")

    assert len(entries) == 1
    assert entries[0].bundled is False


def test_same_docs_identity_in_project_config_is_not_exempt(tmp_path, monkeypatch) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    workspace = tmp_path / "repo"
    project_config = workspace / ".codex" / "config.toml"
    project_config.parent.mkdir(parents=True)
    project_config.write_text(
        f'[mcp_servers.{_DOCS_NAME}]\nurl = "{_DOCS_URL}"\n',
        encoding="utf-8",
    )

    entries = connector_paths.mcp_servers("codex", workspace_dir=str(workspace))

    assert len(entries) == 1
    assert entries[0].source_scope == "project"
    assert entries[0].bundled is False


def test_amp_skill_mcp_never_inherits_codex_bundled_identity(
    tmp_path, monkeypatch
) -> None:
    skill_root = tmp_path / "amp-skills"
    skill = skill_root / "docs"
    skill.mkdir(parents=True)
    (skill / "mcp.json").write_text(
        json.dumps({_DOCS_NAME: {"url": _DOCS_URL}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(connector_paths, "_amp_settings_documents", lambda _workspace: [])
    monkeypatch.setattr(connector_paths, "_amp_skill_dirs", lambda _workspace: [str(skill_root)])

    entries = connector_paths._amp_mcp_servers()

    assert len(entries) == 1
    assert entries[0].name == _DOCS_NAME
    assert entries[0].bundled is False


def _clean_result(target: str) -> ScanResult:
    return ScanResult(
        scanner="mcp-scanner",
        target=target,
        timestamp=datetime.now(timezone.utc),
        findings=[],
    )


def test_scan_all_skips_bundled_entry_but_scans_user_entry() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.mcp_servers = lambda connector=None: [  # type: ignore[method-assign]
            MCPServerEntry(name=_DOCS_NAME, url=_DOCS_URL, bundled=True),
            MCPServerEntry(name="operator", url="https://example.test/mcp"),
        ]
        with patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan") as scan:
            scan.side_effect = lambda target, **_kwargs: _clean_result(target)
            result = CliRunner().invoke(
                mcp, ["scan", "--all"], obj=app, catch_exceptions=False
            )

        assert result.exit_code == 0, result.output
        scan.assert_called_once()
        assert scan.call_args.args[0] == "https://example.test/mcp"
        assert f"BUNDLED: {_DOCS_NAME}" in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_named_bundled_entry_is_discovery_only() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.mcp_servers = lambda connector=None: [  # type: ignore[method-assign]
            MCPServerEntry(name=_DOCS_NAME, url=_DOCS_URL, bundled=True)
        ]
        with patch("defenseclaw.scanner.mcp.MCPScannerWrapper.scan") as scan:
            result = CliRunner().invoke(
                mcp, ["scan", _DOCS_NAME, "--json"], obj=app,
                catch_exceptions=False,
            )

        assert result.exit_code == 0, result.output
        scan.assert_not_called()
        assert json.loads(result.output) == {
            "connector": "openclaw",
            "target": _DOCS_NAME,
            "status": "skipped",
            "reason": "vendor_bundled",
        }
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_mcp_list_json_exposes_bundled_provenance() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.mcp_servers = lambda connector=None: [  # type: ignore[method-assign]
            MCPServerEntry(name=_DOCS_NAME, url=_DOCS_URL, bundled=True)
        ]
        result = CliRunner().invoke(
            mcp, ["list", "--json"], obj=app, catch_exceptions=False
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload[0]["name"] == _DOCS_NAME
        assert payload[0]["bundled"] is True
    finally:
        cleanup_app(app, db_path, tmp_dir)


@pytest.mark.parametrize("verb", ["block", "allow", "unblock"])
@pytest.mark.parametrize(
    ("target", "scoped"),
    [(_DOCS_NAME, False), (_DOCS_NAME, True), (_DOCS_URL, False)],
)
def test_policy_mutations_refuse_resolved_bundled_entry(
    verb: str,
    target: str,
    scoped: bool,
) -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.mcp_servers = lambda connector=None: [  # type: ignore[method-assign]
            MCPServerEntry(name=_DOCS_NAME, url=_DOCS_URL, bundled=True)
        ]
        policy = PolicyEngine(app.store)
        connector = "openclaw" if scoped else ""
        if verb == "unblock":
            if scoped:
                policy.block_for_connector("mcp", target, connector, "pre-existing")
            else:
                policy.block("mcp", target, "pre-existing")

        args = [verb, target]
        if scoped:
            args += ["--connector", connector]
        result = CliRunner().invoke(mcp, args, obj=app)

        assert result.exit_code == 1, result.output
        assert "bundled entries are discovery-only" in result.output
        if verb == "unblock":
            if scoped:
                assert app.store.has_action(
                    "mcp", target, "install", "block", connector
                )
            else:
                assert policy.is_blocked("mcp", target)
        elif scoped:
            assert not app.store.has_action(
                "mcp", target, "install", verb, connector
            )
        else:
            assert policy.get_action("mcp", target) is None
    finally:
        cleanup_app(app, db_path, tmp_dir)
