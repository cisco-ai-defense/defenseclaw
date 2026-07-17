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

"""Tests for the connector-aware MCP set/unset writers (S4.2).

Pins three contracts:

1. The dispatch matrix — OpenClaw delegates to its CLI shim,
   Claude Code patches ~/.claude/settings.json, Codex patches
   ~/.codex/config.toml by default, ZeptoClaw refuses with a clear error.
2. Atomicity + 0o600 perms on the JSON-rewriting branches.
3. Round-trip — what we set is what we read back via mcp_servers().
"""

from __future__ import annotations

import base64
import json
import os
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest
from defenseclaw import connector_paths, file_permissions, windows_acl
from defenseclaw.connector_paths import (
    KNOWN_CONNECTORS,
    MCPWriteUnsupportedError,
    lookup_managed_mcp_backup,
    restore_managed_mcp_backup,
    set_mcp_server,
    unset_mcp_server,
)

from tests.permissions import assert_owner_only_directory, assert_owner_only_file


def _claude_ownership_files(data_home: Path) -> list[Path]:
    metadata_dir = data_home / "connector_backups" / "mcp"
    return list(metadata_dir.glob("c-*.json"))


def _claude_released_names(data_home: Path) -> set[str]:
    metadata = _claude_ownership_files(data_home)
    assert len(metadata) == 1
    return set(json.loads(metadata[0].read_text(encoding="utf-8"))["released"])


# ---------------------------------------------------------------------------
# OpenClaw — delegation to injected setter/unsetter
# ---------------------------------------------------------------------------


class TestOpenClawDelegation:
    def test_set_calls_setter_with_dotted_path_and_json(self):
        calls: list[tuple[str, str]] = []

        def fake_setter(path: str, value: str) -> None:
            calls.append((path, value))

        set_mcp_server(
            "openclaw",
            "demo",
            {"command": "uvx", "args": ["demo-mcp"]},
            openclaw_config_setter=fake_setter,
        )
        assert calls == [
            ("mcp.servers.demo", json.dumps({"command": "uvx", "args": ["demo-mcp"]})),
        ]

    def test_unset_calls_unsetter_with_dotted_path(self):
        calls: list[str] = []

        def fake_unsetter(path: str) -> None:
            calls.append(path)

        unset_mcp_server(
            "openclaw",
            "demo",
            openclaw_config_unsetter=fake_unsetter,
        )
        assert calls == ["mcp.servers.demo"]

    def test_set_without_setter_raises(self):
        with pytest.raises(RuntimeError, match="openclaw_config_setter"):
            set_mcp_server("openclaw", "demo", {"command": "x"})

    def test_unset_without_unsetter_raises(self):
        with pytest.raises(RuntimeError, match="openclaw_config_unsetter"):
            unset_mcp_server("openclaw", "demo")


# ---------------------------------------------------------------------------
# ZeptoClaw — programmatic writes are explicitly unsupported
# ---------------------------------------------------------------------------


class TestZeptoClawUnsupported:
    def test_set_raises(self):
        with pytest.raises(MCPWriteUnsupportedError, match="zeptoclaw"):
            set_mcp_server("zeptoclaw", "demo", {"command": "x"})

    def test_unset_raises(self):
        with pytest.raises(MCPWriteUnsupportedError, match="zeptoclaw"):
            unset_mcp_server("zeptoclaw", "demo")

    def test_unknown_connector_raises_unsupported(self):
        with pytest.raises(MCPWriteUnsupportedError, match="unknown connector"):
            set_mcp_server("future-frame", "demo", {"command": "x"})


# ---------------------------------------------------------------------------
# Claude Code — patches ~/.claude/settings.json
# ---------------------------------------------------------------------------


class TestClaudeCodeWrites:
    @pytest.fixture(autouse=True)
    def _isolate_defenseclaw_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "DEFENSECLAW_HOME",
            str(tmp_path / "d"),
        )

    def test_set_creates_settings_when_absent(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("claudecode", "demo", {"command": "uvx"})

        settings = tmp_path / ".claude" / "settings.json"
        assert settings.is_file()
        data = json.loads(settings.read_text())
        assert data["mcpServers"]["demo"] == {"command": "uvx"}

    def test_set_preserves_unrelated_keys(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(
            json.dumps(
                {
                    "mcpServers": {"existing": {"command": "old"}},
                    "theme": "dark",
                    "permissions": {"allow": ["edit"]},
                }
            )
        )

        set_mcp_server(
            "claudecode",
            "demo",
            {"command": "uvx", "args": ["demo-mcp"]},
        )

        data = json.loads(settings.read_text())
        assert data["theme"] == "dark"
        assert data["permissions"] == {"allow": ["edit"]}
        assert data["mcpServers"]["existing"] == {"command": "old"}
        assert data["mcpServers"]["demo"]["command"] == "uvx"

    def test_set_uses_0o600_permissions(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "defenseclaw-home"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        set_mcp_server(
            "claudecode",
            "demo",
            {"command": "uvx", "env": {"API_KEY": "secret"}},
        )
        settings = tmp_path / ".claude" / "settings.json"
        assert_owner_only_file(settings)
        metadata_dir = data_home / "connector_backups" / "mcp"
        metadata_files = _claude_ownership_files(data_home)
        assert len(metadata_files) == 1
        assert_owner_only_directory(metadata_dir)
        assert_owner_only_file(metadata_files[0])
        assert_owner_only_file(Path(f"{metadata_files[0]}.lock"))

    def test_set_and_unset_refuse_symlinked_settings(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        target = tmp_path / "operator-settings.json"
        target.write_text('{"theme":"unchanged"}', encoding="utf-8")
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        try:
            settings.symlink_to(target)
        except OSError:
            pytest.skip("symlink creation is unavailable")

        with pytest.raises(ValueError, match="symlink"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        with pytest.raises(ValueError, match="symlink"):
            unset_mcp_server("claudecode", "demo")

        assert target.read_text(encoding="utf-8") == '{"theme":"unchanged"}'

    def test_public_set_and_unset_normalize_unsafe_path_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(connector_paths, "claude_config_dir", lambda: str(tmp_path / ".claude"))

        def refuse_unsafe_path(*_args):
            raise file_permissions.UnsafePathError("refusing sensitive write through symlink")

        monkeypatch.setattr(connector_paths, "_set_claudecode_mcp_server", refuse_unsafe_path)
        with pytest.raises(ValueError, match="symlink") as set_error:
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        assert isinstance(set_error.value.__cause__, file_permissions.UnsafePathError)

        monkeypatch.setattr(connector_paths, "_unset_claudecode_mcp_server", refuse_unsafe_path)
        with pytest.raises(ValueError, match="symlink") as unset_error:
            unset_mcp_server("claudecode", "demo")
        assert isinstance(unset_error.value.__cause__, file_permissions.UnsafePathError)

    def test_unset_removes_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "demo": {"command": "uvx"},
                        "keep": {"command": "stay"},
                    },
                }
            )
        )

        unset_mcp_server("claudecode", "demo")

        data = json.loads(settings.read_text())
        assert "demo" not in data["mcpServers"]
        assert data["mcpServers"]["keep"] == {"command": "stay"}

    def test_unset_missing_is_noop(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        # No file present.
        unset_mcp_server("claudecode", "demo")  # must not raise

    @pytest.mark.parametrize(
        "original",
        [
            b'{\r\n  "theme": "dark"\r\n}',
            b'{ "mcpServers" : { }, "theme" : "dark" }\n',
            b'{"mcpServers":{"existing":{"command":"keep"}},"theme":"dark"}',
            b"",
            b" \r\n\t",
        ],
        ids=[
            "absent-property",
            "preexisting-empty-property",
            "unrelated-mcp",
            "empty-file",
            "whitespace-file",
        ],
    )
    def test_set_unset_restores_exact_preexisting_bytes(
        self,
        tmp_path,
        monkeypatch,
        original,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "defenseclaw-home"))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_bytes(original)

        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        unset_mcp_server("claudecode", "demo")

        assert settings.read_bytes() == original

    def test_set_unset_removes_file_created_by_defenseclaw(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "defenseclaw-home"))
        settings = tmp_path / ".claude" / "settings.json"

        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        assert settings.is_file()

        unset_mcp_server("claudecode", "demo")

        assert not settings.exists()
        metadata_dir = tmp_path / "defenseclaw-home" / "connector_backups" / "mcp"
        assert list(metadata_dir.glob("c-*.json")) == []

    def test_unset_preserves_external_root_and_unrelated_mcp_edits(
        self,
        tmp_path,
        monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "defenseclaw-home"))
        settings = tmp_path / ".claude" / "settings.json"

        set_mcp_server("claudecode", "managed", {"command": "inert-managed"})
        external = json.loads(settings.read_text(encoding="utf-8"))
        external["theme"] = "operator-edit"
        external["mcpServers"]["external"] = {"command": "inert-external"}
        settings.write_text(json.dumps(external, separators=(",", ":")), encoding="utf-8")

        unset_mcp_server("claudecode", "managed")

        result = json.loads(settings.read_text(encoding="utf-8"))
        assert result["theme"] == "operator-edit"
        assert result["mcpServers"] == {"external": {"command": "inert-external"}}

    def test_unset_does_not_remove_externally_changed_managed_server(
        self,
        tmp_path,
        monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "defenseclaw-home"))
        settings = tmp_path / ".claude" / "settings.json"

        set_mcp_server("claudecode", "managed", {"command": "inert-managed"})
        external = json.loads(settings.read_text(encoding="utf-8"))
        external["mcpServers"]["managed"] = {"command": "operator-replacement"}
        settings.write_text(json.dumps(external), encoding="utf-8")

        unset_mcp_server("claudecode", "managed")

        result = json.loads(settings.read_text(encoding="utf-8"))
        assert result["mcpServers"]["managed"] == {"command": "operator-replacement"}

    @pytest.mark.parametrize("first_unset", ["first", "second"])
    def test_multiple_managed_servers_restore_only_after_last_unset(
        self,
        tmp_path,
        monkeypatch,
        first_unset,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "defenseclaw-home"))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        original = b'{\n "theme": "dark"\n}\n'
        settings.write_bytes(original)

        set_mcp_server("claudecode", "first", {"command": "inert-first"})
        set_mcp_server("claudecode", "second", {"command": "inert-second"})
        unset_mcp_server("claudecode", first_unset)

        intermediate = json.loads(settings.read_text(encoding="utf-8"))
        remaining = "second" if first_unset == "first" else "first"
        assert first_unset not in intermediate["mcpServers"]
        assert intermediate["mcpServers"][remaining] == {"command": f"inert-{remaining}"}

        unset_mcp_server("claudecode", remaining)
        assert settings.read_bytes() == original

    @pytest.mark.parametrize(
        "original",
        [b"\xff\xfe", b"{ malformed", b"[]\n", b'"scalar"\n', b"null\n"],
        ids=["invalid-utf8", "malformed-json", "array", "scalar", "null"],
    )
    @pytest.mark.parametrize("operation", ["set", "unset"])
    def test_invalid_settings_fail_closed(
        self,
        tmp_path,
        monkeypatch,
        original,
        operation,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_bytes(original)

        with pytest.raises(MCPWriteUnsupportedError, match="JSON object"):
            if operation == "set":
                set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
            else:
                unset_mcp_server("claudecode", "demo")

        assert settings.read_bytes() == original
        assert _claude_ownership_files(data_home) == []
        assert not Path(connector_paths._managed_mcp_backup_path(str(settings))).exists()

    def test_recovers_crash_before_config_publication(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{\r\n "theme": "operator"\r\n}\r\n'
        settings.write_bytes(original)
        publish = connector_paths._publish_claude_config_if_unchanged

        def crash_before_publish(*_args, **_kwargs):
            raise RuntimeError("simulated crash before config publication")

        monkeypatch.setattr(
            connector_paths,
            "_publish_claude_config_if_unchanged",
            crash_before_publish,
        )
        with pytest.raises(RuntimeError, match="simulated crash"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})

        assert settings.read_bytes() == original
        metadata = _claude_ownership_files(data_home)
        assert len(metadata) == 1
        pending = json.loads(metadata[0].read_text(encoding="utf-8"))["pending"]
        assert pending["old_config_b64"] is not None
        assert pending["new_config_b64"] is not None
        with pytest.raises(MCPWriteUnsupportedError, match="ownership-aware"):
            restore_managed_mcp_backup(str(settings))

        monkeypatch.setattr(
            connector_paths,
            "_publish_claude_config_if_unchanged",
            publish,
        )
        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original
        assert _claude_ownership_files(data_home) == []

    def test_recovers_crash_after_candidate_identity_before_native_publication(
        self,
        tmp_path,
        monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{\r\n "theme": "operator"\r\n}\r\n'
        settings.write_bytes(original)
        publish = connector_paths._atomic_replace_claude_with_proof

        def crash_after_candidate(snapshot, payload, **kwargs):
            if os.path.normcase(os.path.abspath(snapshot.path)) != os.path.normcase(os.path.abspath(settings)):
                return publish(snapshot, payload, **kwargs)
            before_publish = kwargs["before_publish"]

            def persist_then_crash(candidate):
                before_publish(candidate)
                raise RuntimeError("simulated crash after candidate identity")

            kwargs["before_publish"] = persist_then_crash
            return publish(snapshot, payload, **kwargs)

        monkeypatch.setattr(
            connector_paths,
            "_atomic_replace_claude_with_proof",
            crash_after_candidate,
        )
        with pytest.raises(RuntimeError, match="candidate identity"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})

        assert settings.read_bytes() == original
        metadata = _claude_ownership_files(data_home)
        assert len(metadata) == 1
        pending = json.loads(metadata[0].read_text(encoding="utf-8"))["pending"]
        assert isinstance(pending["next_state"]["postimage_identity"], dict)

        monkeypatch.setattr(
            connector_paths,
            "_atomic_replace_claude_with_proof",
            publish,
        )
        unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original
        assert _claude_ownership_files(data_home) == []

    def test_recovers_crash_after_config_publication(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{ "theme" : "operator" }\n'
        settings.write_bytes(original)
        finalize = connector_paths._finalize_claude_mcp_transaction
        save_envelope = connector_paths._save_claude_mcp_envelope
        pending_identities: list[dict[str, object]] = []

        def record_pending_identity(path, envelope):
            pending = envelope.get("pending")
            if isinstance(pending, dict):
                next_state = pending.get("next_state")
                if isinstance(next_state, dict):
                    identity = next_state.get("postimage_identity")
                    if isinstance(identity, dict):
                        pending_identities.append(dict(identity))
            return save_envelope(path, envelope)

        def crash_after_publish(*_args, **_kwargs):
            raise RuntimeError("simulated crash after config publication")

        monkeypatch.setattr(
            connector_paths,
            "_save_claude_mcp_envelope",
            record_pending_identity,
        )
        monkeypatch.setattr(
            connector_paths,
            "_finalize_claude_mcp_transaction",
            crash_after_publish,
        )
        with pytest.raises(RuntimeError, match="simulated crash"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        assert json.loads(settings.read_text(encoding="utf-8"))["mcpServers"]["demo"] == {
            "command": "inert-demo",
        }
        pending = json.loads(
            _claude_ownership_files(data_home)[0].read_text(encoding="utf-8"),
        )["pending"]
        assert pending is not None
        assert isinstance(pending["next_state"]["postimage_identity"], dict)
        # One durable write binds the staged candidate before publication;
        # the next rebinds the journal to the proven public snapshot.
        assert len(pending_identities) >= 2
        assert pending["next_state"]["postimage_identity"] == pending_identities[-1]

        monkeypatch.setattr(
            connector_paths,
            "_finalize_claude_mcp_transaction",
            finalize,
        )
        unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original
        assert _claude_ownership_files(data_home) == []

    @pytest.mark.skipif(os.name != "nt", reason="Windows publication identity hand-off")
    def test_verified_publication_rebinds_candidate_projection(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{ "theme" : "operator" }\r\n'
        settings.write_bytes(original)
        project = connector_paths._claude_postimage_identity_from_snapshot
        projections = 0

        def drift_prepublication_projection(snapshot):
            nonlocal projections
            projections += 1
            identity = project(snapshot)
            if projections == 1:
                return {
                    **identity,
                    "inode": (identity["inode"] or 0) + 1,
                }
            return identity

        monkeypatch.setattr(
            connector_paths,
            "_claude_postimage_identity_from_snapshot",
            drift_prepublication_projection,
        )
        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})

        metadata = _claude_ownership_files(data_home)
        assert len(metadata) == 1
        committed = json.loads(metadata[0].read_text(encoding="utf-8"))["committed"]
        assert projections >= 2
        assert committed["postimage_identity"] == connector_paths._capture_claude_postimage_identity(
            str(settings),
        )

        unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original
        assert _claude_ownership_files(data_home) == []

    def test_equal_byte_crash_after_publication_restores_operator_server_once(
        self,
        tmp_path,
        monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{\n  "mcpServers": {\n    "demo": {\n      "command": "inert-demo"\n    }\n  }\n}\n'
        settings.write_bytes(original)
        finalize = connector_paths._finalize_claude_mcp_transaction

        def crash_after_publish(*_args, **_kwargs):
            raise RuntimeError("simulated equal-byte post-publication crash")

        monkeypatch.setattr(
            connector_paths,
            "_finalize_claude_mcp_transaction",
            crash_after_publish,
        )
        with pytest.raises(RuntimeError, match="equal-byte"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        assert settings.read_bytes() == original

        monkeypatch.setattr(
            connector_paths,
            "_finalize_claude_mcp_transaction",
            finalize,
        )
        unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original
        assert _claude_released_names(data_home) == {"demo"}
        unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original
        assert _claude_released_names(data_home) == {"demo"}

    def test_recovers_crash_after_final_restore(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{"theme":"operator"}\n'
        settings.write_bytes(original)
        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        finalize = connector_paths._finalize_claude_mcp_transaction

        def crash_after_restore(*_args, **_kwargs):
            raise RuntimeError("simulated crash after final restore")

        monkeypatch.setattr(
            connector_paths,
            "_finalize_claude_mcp_transaction",
            crash_after_restore,
        )
        with pytest.raises(RuntimeError, match="simulated crash"):
            unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original
        assert (
            json.loads(
                _claude_ownership_files(data_home)[0].read_text(encoding="utf-8"),
            )["pending"]
            is not None
        )

        monkeypatch.setattr(
            connector_paths,
            "_finalize_claude_mcp_transaction",
            finalize,
        )
        unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original
        assert _claude_ownership_files(data_home) == []

    def test_retried_unset_preserves_preexisting_server_after_restore_crash(
        self,
        tmp_path,
        monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{\r\n "mcpServers": {"demo": {"command": "operator"}},\r\n "theme": "operator"\r\n}\r\n'
        settings.write_bytes(original)
        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        finalize = connector_paths._finalize_claude_mcp_transaction

        def crash_after_restore(*_args, **_kwargs):
            raise RuntimeError("simulated crash after operator restore")

        monkeypatch.setattr(
            connector_paths,
            "_finalize_claude_mcp_transaction",
            crash_after_restore,
        )
        with pytest.raises(RuntimeError, match="operator restore"):
            unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original

        monkeypatch.setattr(
            connector_paths,
            "_finalize_claude_mcp_transaction",
            finalize,
        )
        unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original
        assert _claude_released_names(data_home) == {"demo"}
        unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original

    def test_native_publication_race_preserves_operator_bytes(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_bytes(b'{"theme":"before"}\n')
        external = b'{ "theme": "operator-raced" }\r\n'
        raced = False

        if os.name == "nt":
            from defenseclaw.observability import v8_activation

            native_claim = v8_activation._claim_windows_file

            def claim_with_race(path, *, missing_ok):
                nonlocal raced
                if not raced and os.path.normcase(path) == os.path.normcase(str(settings)):
                    raced = True
                    settings.write_bytes(external)
                return native_claim(path, missing_ok=missing_ok)

            monkeypatch.setattr(v8_activation, "_claim_windows_file", claim_with_race)
            race_module = v8_activation
            race_name = "_claim_windows_file"
            native_race = native_claim
        else:
            from defenseclaw.observability import v8_activation

            native_exchange = v8_activation._exchange_entries

            def exchange_with_race(parent_fd, first, second, target):
                nonlocal raced
                if not raced and os.path.abspath(target) == os.path.abspath(settings):
                    raced = True
                    settings.write_bytes(external)
                return native_exchange(parent_fd, first, second, target)

            monkeypatch.setattr(v8_activation, "_exchange_entries", exchange_with_race)
            race_module = v8_activation
            race_name = "_exchange_entries"
            native_race = native_exchange

        with pytest.raises(MCPWriteUnsupportedError, match="identity-bound"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        assert raced
        assert settings.read_bytes() == external

        monkeypatch.setattr(race_module, race_name, native_race)
        unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == external
        assert _claude_released_names(data_home) == {"demo"}

    def test_parent_swap_before_native_replace_preserves_new_tree(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_bytes(b'{"theme":"original-tree"}\n')
        displaced = tmp_path / ".claude-displaced"
        external = b'{"theme":"new-tree"}\n'

        atomic_replace = connector_paths._atomic_replace_claude_with_proof
        swapped = False

        def replace_after_parent_swap(
            snapshot,
            payload,
            *,
            default_mode,
            metadata=None,
            before_publish=None,
        ):
            nonlocal swapped
            if not swapped and os.path.normcase(snapshot.path) == os.path.normcase(str(settings)):
                swapped = True
                settings.parent.rename(displaced)
                settings.parent.mkdir()
                settings.write_bytes(external)
            return atomic_replace(
                snapshot,
                payload,
                default_mode=default_mode,
                metadata=metadata,
                before_publish=before_publish,
            )

        monkeypatch.setattr(
            connector_paths,
            "_atomic_replace_claude_with_proof",
            replace_after_parent_swap,
        )
        with pytest.raises(MCPWriteUnsupportedError, match="identity-bound|ancestor changed"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})

        assert swapped
        assert settings.read_bytes() == external
        assert (displaced / "settings.json").read_bytes() == b'{"theme":"original-tree"}\n'

    @pytest.mark.skipif(os.name != "nt", reason="exact raw DACL contract is Windows-specific")
    def test_set_unset_preserves_exact_windows_security(self, tmp_path, monkeypatch):
        from defenseclaw import windows_acl

        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{"theme":"operator"}\r\n'
        settings.write_bytes(original)
        security = windows_acl.capture_path(str(settings))

        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        assert windows_acl.capture_path(str(settings)) == security
        unset_mcp_server("claudecode", "demo")

        assert settings.read_bytes() == original
        assert windows_acl.capture_path(str(settings)) == security

    @pytest.mark.parametrize(
        "metadata_change",
        [
            {"flags": 1},
            {"darwin_acl": b"inert-acl"},
        ],
    )
    def test_posix_publisher_rejects_unrepresentable_metadata(
        self,
        tmp_path,
        metadata_change,
    ):
        from defenseclaw.observability import v8_activation

        settings = tmp_path / "settings.json"
        original = b'{"theme":"operator"}\n'
        settings.write_bytes(original)
        snapshot = v8_activation._snapshot_regular_file(str(settings), required=True)

        with pytest.raises(OSError, match="cannot be represented"):
            connector_paths._atomic_replace_claude_posix_with_proof(
                snapshot,
                b"{}\n",
                default_mode=0o600,
                metadata=replace(snapshot, **metadata_change),
            )
        assert settings.read_bytes() == original

    @pytest.mark.skipif(os.name != "nt", reason="Windows owner binding contract")
    def test_new_settings_reject_foreign_owned_parent(self, tmp_path, monkeypatch):
        from defenseclaw import windows_acl

        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        capture = windows_acl.capture_path

        def capture_with_foreign_settings_parent(path, *, directory=False):
            security = capture(path, directory=directory)
            if directory and os.path.normcase(os.path.abspath(path)) == os.path.normcase(
                os.path.abspath(settings.parent),
            ):
                return replace(security, owner=b"mocked-foreign-owner")
            return security

        monkeypatch.setattr(windows_acl, "capture_path", capture_with_foreign_settings_parent)
        with pytest.raises(MCPWriteUnsupportedError, match="unexpected owner"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        assert not settings.exists()

    @pytest.mark.parametrize(
        "corrupt",
        [b"\xff", b"{broken", b'{"schema":999}\n'],
        ids=["invalid-utf8", "invalid-json", "unsupported-schema"],
    )
    @pytest.mark.parametrize("operation", ["set", "unset"])
    def test_corrupt_ownership_metadata_fails_closed(
        self,
        tmp_path,
        monkeypatch,
        corrupt,
        operation,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        before = settings.read_bytes()
        metadata = _claude_ownership_files(data_home)
        assert len(metadata) == 1
        metadata[0].write_bytes(corrupt)

        with pytest.raises(MCPWriteUnsupportedError, match="metadata"):
            if operation == "set":
                set_mcp_server("claudecode", "other", {"command": "inert-other"})
            else:
                unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == before

    def test_retires_legacy_backup_and_preserves_other_registry_entries(
        self,
        tmp_path,
        monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{ "theme": "operator" }\n'
        settings.write_bytes(original)
        backup = Path(connector_paths._managed_mcp_backup_path(str(settings)))
        backup.write_bytes(original)
        connector_paths._registry_register(str(settings.resolve()), str(backup))

        other = tmp_path / "other.json"
        other_backup = tmp_path / ".defenseclaw-other.json.bak"
        other_backup.write_bytes(b"{}\n")
        connector_paths._registry_register(str(other.resolve()), str(other_backup))

        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})

        assert not backup.exists()
        assert lookup_managed_mcp_backup(str(settings)) is None
        assert lookup_managed_mcp_backup(str(other)) == str(other_backup.resolve())
        with pytest.raises(MCPWriteUnsupportedError, match="ownership-aware"):
            restore_managed_mcp_backup(str(settings))

        unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original
        assert not backup.exists()
        assert restore_managed_mcp_backup(str(settings)) is False
        assert lookup_managed_mcp_backup(str(other)) == str(other_backup.resolve())

    @pytest.mark.parametrize("operation", ["capture", "retire"])
    def test_legacy_registry_mutation_holds_target_lock(self, tmp_path, monkeypatch, operation):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_bytes(b'{"theme":"operator"}\n')
        ownership = os.path.abspath(connector_paths._claude_mcp_ownership_path(str(settings)))
        registry = os.path.abspath(connector_paths._registry_path())
        lock = connector_paths._locked_claude_file_update
        active: list[str] = []
        serialized = False

        if operation == "retire":
            backup = Path(connector_paths._managed_mcp_backup_path(str(settings)))
            backup.write_bytes(settings.read_bytes())
            connector_paths._registry_register(str(settings), str(backup))

        @contextmanager
        def track(path, *, label):
            nonlocal serialized
            normalized = os.path.normcase(os.path.abspath(path))
            if normalized == os.path.normcase(registry):
                serialized = os.path.normcase(ownership) in {os.path.normcase(item) for item in active}
            active.append(normalized)
            try:
                with lock(path, label=label) as bound:
                    yield bound
            finally:
                active.pop()

        monkeypatch.setattr(connector_paths, "_locked_claude_file_update", track)
        if operation == "capture":
            connector_paths._capture_managed_mcp_backup(str(settings))
        else:
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        assert serialized

    def test_lock_sentinel_swap_fails_before_publication(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        assert_guard = connector_paths._assert_claude_mutation_guard
        attempted = False

        def swap_then_assert():
            nonlocal attempted
            guard = connector_paths._CLAUDE_MUTATION_GUARD.get()
            if guard is not None and not attempted:
                attempted = True
                lock_path = Path(guard["bound_locks"][0]["path"])
                replacement = lock_path.with_name("operator-lock-replacement")
                file_permissions.atomic_write_private_bytes(replacement, b"")
                try:
                    os.replace(replacement, lock_path)
                except OSError as exc:
                    raise MCPWriteUnsupportedError(
                        "refusing Claude MCP mutation: lock swap was rejected",
                    ) from exc
            return assert_guard()

        monkeypatch.setattr(
            connector_paths,
            "_assert_claude_mutation_guard",
            swap_then_assert,
        )
        with pytest.raises(MCPWriteUnsupportedError, match="lock"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        assert attempted
        assert not settings.exists()
        assert _claude_ownership_files(data_home) == []

    @pytest.mark.skipif(os.name != "nt", reason="Windows registry alias contract")
    def test_windows_legacy_aliases_share_ownership_and_retire_together(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_bytes(b'{"theme":"operator"}\n')
        backup = Path(connector_paths._managed_mcp_backup_path(str(settings)))
        backup.write_bytes(settings.read_bytes())
        connector_paths._registry_register(str(settings), str(backup))

        alias = str(settings).upper().replace("\\", "/")
        assert connector_paths._claude_mcp_ownership_path(alias) == connector_paths._claude_mcp_ownership_path(
            str(settings)
        )
        registry_path = Path(connector_paths._registry_path())
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        raw_alias_key = connector_paths.hashlib.sha256(os.path.abspath(alias).encode("utf-8")).hexdigest()
        registry[raw_alias_key] = {
            "path": alias,
            "backup": str(backup).upper().replace("\\", "/"),
            "ts": "inert",
        }
        registry["unrelated"] = {
            "path": str(tmp_path / "other.json"),
            "backup": str(tmp_path / "other.bak"),
            "ts": "inert",
        }
        file_permissions.atomic_write_private_bytes(
            registry_path,
            (json.dumps(registry, sort_keys=True) + "\n").encode(),
        )

        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})

        remaining = json.loads(registry_path.read_text(encoding="utf-8"))
        assert raw_alias_key not in remaining
        retirement = remaining[connector_paths._registry_key(str(settings))]
        assert retirement["retired"] is True
        assert retirement["backup"] == ""
        assert "unrelated" in remaining

    def test_legacy_backup_retirement_preserves_same_byte_replacement(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{"theme":"operator"}\n'
        settings.write_bytes(original)
        backup = Path(connector_paths._managed_mcp_backup_path(str(settings)))
        backup.write_bytes(original)
        connector_paths._registry_register(str(settings), str(backup))
        delete = connector_paths._delete_private_regular_file

        def replace_before_delete(path, **kwargs):
            if os.path.normcase(os.path.abspath(path)) == os.path.normcase(os.path.abspath(backup)):
                replacement = backup.with_name("operator-same-backup.bak")
                replacement.write_bytes(backup.read_bytes())
                os.replace(replacement, backup)
            return delete(path, **kwargs)

        monkeypatch.setattr(
            connector_paths,
            "_delete_private_regular_file",
            replace_before_delete,
        )
        with pytest.raises(MCPWriteUnsupportedError, match="metadata changed"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})

        assert settings.read_bytes() == original
        assert backup.read_bytes() == original
        registry = json.loads(Path(connector_paths._registry_path()).read_text(encoding="utf-8"))
        retirement = registry[connector_paths._registry_key(str(settings))]
        assert retirement["retired"] is True
        assert retirement["backup"] == ""
        assert lookup_managed_mcp_backup(str(settings)) is None
        assert restore_managed_mcp_backup(str(settings)) is False
        assert settings.read_bytes() == original
        assert backup.read_bytes() == original

    def test_retired_legacy_backup_never_revives_from_reappearing_sibling(
        self,
        tmp_path,
        monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{"theme":"operator"}\n'
        settings.write_bytes(original)
        backup = Path(connector_paths._managed_mcp_backup_path(str(settings)))
        backup.write_bytes(b'{"theme":"stale-pre-episode"}\n')
        connector_paths._registry_register(str(settings), str(backup))

        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original
        assert not backup.exists()

        stale = b'{"theme":"reappeared-stale"}\n'
        backup.write_bytes(stale)
        connector_paths._capture_managed_mcp_backup(str(settings))
        assert lookup_managed_mcp_backup(str(settings)) is None
        assert backup.read_bytes() == stale
        assert restore_managed_mcp_backup(str(settings)) is False
        assert settings.read_bytes() == original
        assert backup.read_bytes() == stale
        registry = json.loads(Path(connector_paths._registry_path()).read_text(encoding="utf-8"))
        assert registry[connector_paths._registry_key(str(settings))]["retired"] is True

    @pytest.mark.parametrize(
        "corruption",
        [
            "missing-old",
            "missing-new",
            "missing-next",
            "old-mismatch",
            "new-mismatch",
            "new-absent",
            "episode-preimage",
            "exact-restore",
            "retained-prior",
            "added-prior",
            "postimage-identity",
        ],
    )
    def test_pending_metadata_cross_fields_fail_closed(
        self,
        tmp_path,
        monkeypatch,
        corruption,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        set_mcp_server("claudecode", "first", {"command": "inert-first"})
        publish = connector_paths._publish_claude_config_if_unchanged

        def stop_before_publish(*_args, **_kwargs):
            raise RuntimeError("stop before config")

        monkeypatch.setattr(
            connector_paths,
            "_publish_claude_config_if_unchanged",
            stop_before_publish,
        )
        with pytest.raises(RuntimeError, match="stop before config"):
            set_mcp_server("claudecode", "second", {"command": "inert-second"})
        monkeypatch.setattr(connector_paths, "_publish_claude_config_if_unchanged", publish)

        metadata = Path(connector_paths._claude_mcp_ownership_path(str(settings)))
        envelope = json.loads(metadata.read_text(encoding="utf-8"))
        pending = envelope["pending"]
        if corruption.startswith("missing-"):
            pending.pop(
                {
                    "missing-old": "old_config_b64",
                    "missing-new": "new_config_b64",
                    "missing-next": "next_state",
                }[corruption],
            )
        elif corruption == "old-mismatch":
            pending["old_config_b64"] = base64.b64encode(b"{}\n").decode("ascii")
        elif corruption == "new-mismatch":
            pending["new_config_b64"] = base64.b64encode(b'{"mcpServers":{}}\n').decode("ascii")
        elif corruption == "episode-preimage":
            alternate = b'{"mcpServers":{}}\n'
            next_state = pending["next_state"]
            next_state["file_preexisting"] = True
            next_state["preimage_b64"] = base64.b64encode(alternate).decode("ascii")
            next_state["container_preexisting"] = True
            next_state["container_preimage"] = {}
        elif corruption == "exact-restore":
            pending["next_state"]["exact_restore"] = not envelope["committed"]["exact_restore"]
        elif corruption == "retained-prior":
            record = pending["next_state"]["managed"]["first"]
            record["prior_present"] = True
            record["prior"] = {"command": "tampered-prior"}
        elif corruption == "added-prior":
            record = pending["next_state"]["managed"]["second"]
            record["prior_present"] = True
            record["prior"] = {"command": "tampered-prior"}
        elif corruption == "postimage-identity":
            pending["next_state"]["postimage_identity"] = {
                **envelope["committed"]["postimage_identity"],
                "inode": True,
            }
        else:
            pending["new_config_b64"] = None
        corrupt_bytes = (json.dumps(envelope, sort_keys=True) + "\n").encode()
        metadata.write_bytes(corrupt_bytes)
        settings_before = settings.read_bytes()

        with pytest.raises(MCPWriteUnsupportedError, match="metadata|pending"):
            set_mcp_server("claudecode", "third", {"command": "inert-third"})
        assert settings.read_bytes() == settings_before
        assert metadata.read_bytes() == corrupt_bytes

    def test_initial_pending_episode_preimage_mismatch_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{"theme":"operator"}\n'
        settings.write_bytes(original)
        publish = connector_paths._publish_claude_config_if_unchanged

        def stop_before_publish(*_args, **_kwargs):
            raise RuntimeError("stop before config")

        monkeypatch.setattr(
            connector_paths,
            "_publish_claude_config_if_unchanged",
            stop_before_publish,
        )
        with pytest.raises(RuntimeError, match="stop before config"):
            set_mcp_server("claudecode", "first", {"command": "inert-first"})
        monkeypatch.setattr(
            connector_paths,
            "_publish_claude_config_if_unchanged",
            publish,
        )

        metadata = Path(connector_paths._claude_mcp_ownership_path(str(settings)))
        envelope = json.loads(metadata.read_text(encoding="utf-8"))
        alternate = b'{"mcpServers":{},"theme":"other"}\n'
        next_state = envelope["pending"]["next_state"]
        next_state["file_preexisting"] = True
        next_state["preimage_b64"] = base64.b64encode(alternate).decode("ascii")
        next_state["container_preexisting"] = True
        next_state["container_preimage"] = {}
        corrupt_bytes = (json.dumps(envelope, sort_keys=True) + "\n").encode()
        metadata.write_bytes(corrupt_bytes)

        with pytest.raises(MCPWriteUnsupportedError, match="episode preimage"):
            set_mcp_server("claudecode", "second", {"command": "inert-second"})
        assert settings.read_bytes() == original
        assert metadata.read_bytes() == corrupt_bytes

    @pytest.mark.parametrize("field", ["old_config_b64", "new_config_b64"])
    def test_unowned_pending_config_must_be_a_json_object(self, tmp_path, monkeypatch, field):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{"mcpServers":{"demo":{"command":"operator"}}}\n'
        settings.write_bytes(original)
        publish = connector_paths._publish_claude_config_if_unchanged

        def stop_before_publish(*_args, **_kwargs):
            raise RuntimeError("stop before config")

        monkeypatch.setattr(
            connector_paths,
            "_publish_claude_config_if_unchanged",
            stop_before_publish,
        )
        with pytest.raises(RuntimeError, match="stop before config"):
            unset_mcp_server("claudecode", "demo")
        monkeypatch.setattr(
            connector_paths,
            "_publish_claude_config_if_unchanged",
            publish,
        )

        metadata = Path(connector_paths._claude_mcp_ownership_path(str(settings)))
        envelope = json.loads(metadata.read_text(encoding="utf-8"))
        assert envelope["committed"] is None
        assert envelope["pending"]["next_state"] is None
        envelope["pending"][field] = base64.b64encode(b"[]\n").decode("ascii")
        corrupt_bytes = (json.dumps(envelope, sort_keys=True) + "\n").encode()
        metadata.write_bytes(corrupt_bytes)

        with pytest.raises(MCPWriteUnsupportedError, match="JSON object"):
            unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == original
        assert metadata.read_bytes() == corrupt_bytes

    @pytest.mark.parametrize(
        "postimage",
        [
            b"{broken",
            b"[]\n",
            b'{"mcpServers":{"demo":{"command":"different"}}}\n',
        ],
        ids=["malformed", "array", "owned-value-mismatch"],
    )
    def test_committed_postimage_corruption_fails_closed(
        self,
        tmp_path,
        monkeypatch,
        postimage,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        metadata = Path(connector_paths._claude_mcp_ownership_path(str(settings)))
        envelope = json.loads(metadata.read_text(encoding="utf-8"))
        envelope["committed"]["postimage_b64"] = base64.b64encode(postimage).decode("ascii")
        corrupt_bytes = (json.dumps(envelope, sort_keys=True) + "\n").encode()
        metadata.write_bytes(corrupt_bytes)
        settings_before = settings.read_bytes()

        with pytest.raises(MCPWriteUnsupportedError):
            set_mcp_server("claudecode", "other", {"command": "inert-other"})
        assert settings.read_bytes() == settings_before
        assert metadata.read_bytes() == corrupt_bytes

    @pytest.mark.parametrize(
        "non_finite",
        [b'{"value":NaN}\n', b'{"value":Infinity}\n', b'{"value":-Infinity}\n'],
    )
    def test_non_finite_settings_fail_closed(self, tmp_path, monkeypatch, non_finite):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_bytes(non_finite)

        with pytest.raises(MCPWriteUnsupportedError, match="JSON object"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        assert settings.read_bytes() == non_finite

    @pytest.mark.parametrize(
        "invalid_container",
        [None, [], "servers", 1, True],
        ids=["null", "list", "string", "number", "boolean"],
    )
    @pytest.mark.parametrize("operation", ["set", "unset"])
    def test_explicit_non_object_mcp_servers_fails_closed_without_journal(
        self,
        tmp_path,
        monkeypatch,
        invalid_container,
        operation,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = (json.dumps({"mcpServers": invalid_container}) + "\n").encode()
        settings.write_bytes(original)

        with pytest.raises(MCPWriteUnsupportedError, match="mcpServers.*JSON object"):
            if operation == "set":
                set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
            else:
                unset_mcp_server("claudecode", "demo")

        assert settings.read_bytes() == original
        assert _claude_ownership_files(data_home) == []

    def test_non_finite_entry_fails_before_publication(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"

        with pytest.raises(MCPWriteUnsupportedError, match="not finite"):
            set_mcp_server("claudecode", "demo", {"command": "inert", "value": float("nan")})
        assert not settings.exists()

    def test_absent_settings_parent_swap_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        displaced = tmp_path / ".claude-displaced"
        marker = b"operator tree"
        make_private = connector_paths.make_private_directory
        swapped = False

        def create_then_swap(path):
            nonlocal swapped
            make_private(path)
            if not swapped and os.path.normcase(os.path.abspath(path)) == os.path.normcase(
                os.path.abspath(settings.parent),
            ):
                swapped = True
                settings.parent.rename(displaced)
                settings.parent.mkdir()
                (settings.parent / "marker").write_bytes(marker)

        monkeypatch.setattr(connector_paths, "make_private_directory", create_then_swap)
        with pytest.raises(MCPWriteUnsupportedError, match="identity|parent|changed"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})

        assert swapped
        assert (settings.parent / "marker").read_bytes() == marker
        assert not settings.exists()
        assert not (displaced / "settings.json").exists()

    @pytest.mark.skipif(os.name != "nt", reason="Windows lock-leaf reparse contract")
    @pytest.mark.parametrize("reject_on", [1, 2], ids=["preexisting", "acquisition-race"])
    def test_windows_lock_leaf_reparse_fails_before_mutation(
        self,
        tmp_path,
        monkeypatch,
        reject_on,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        lock_path = connector_paths._claude_mcp_ownership_path(str(settings)) + ".lock"
        reject = connector_paths.reject_reparse_path
        seen = 0

        def reject_mocked_lock(path):
            nonlocal seen
            if os.path.normcase(os.path.abspath(path)) == os.path.normcase(os.path.abspath(lock_path)):
                seen += 1
                if seen == reject_on:
                    raise OSError("mocked lock reparse")
            return reject(path)

        monkeypatch.setattr(connector_paths, "reject_reparse_path", reject_mocked_lock)
        with pytest.raises(OSError, match="mocked lock reparse"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        assert not settings.exists()
        assert not Path(connector_paths._claude_mcp_ownership_path(str(settings))).exists()

    @pytest.mark.skipif(os.name != "nt", reason="Windows absent-publication race")
    def test_windows_failed_absent_move_preserves_same_byte_external_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        move = windows_acl.move_file_no_replace

        def install_external_then_fail(source, target):
            if os.path.normcase(os.path.abspath(target)) != os.path.normcase(os.path.abspath(settings)):
                return move(source, target)
            settings.write_bytes(Path(source).read_bytes())
            raise windows_acl.WindowsAclError("mocked ambiguous move failure")

        monkeypatch.setattr(
            windows_acl,
            "move_file_no_replace",
            install_external_then_fail,
        )
        with pytest.raises(MCPWriteUnsupportedError, match="publication failed"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})

        external_bytes = settings.read_bytes()
        assert json.loads(external_bytes)["mcpServers"]["demo"] == {"command": "inert-demo"}
        monkeypatch.setattr(windows_acl, "move_file_no_replace", move)
        with pytest.raises(MCPWriteUnsupportedError, match="pending ownership"):
            unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == external_bytes
        assert _claude_released_names(data_home) == {"demo"}

    @pytest.mark.skipif(os.name != "nt", reason="Windows ambiguous-move edit race")
    def test_windows_failed_absent_move_preserves_in_place_external_edit(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        move = windows_acl.move_file_no_replace
        external = b'{"mcpServers":{"operator":{"command":"external"}}}\n'

        def publish_edit_then_fail(source, target):
            if os.path.normcase(os.path.abspath(target)) != os.path.normcase(os.path.abspath(settings)):
                return move(source, target)
            move(source, target)
            settings.write_bytes(external)
            raise windows_acl.WindowsAclError("mocked completed move with external edit")

        monkeypatch.setattr(
            windows_acl,
            "move_file_no_replace",
            publish_edit_then_fail,
        )
        with pytest.raises(MCPWriteUnsupportedError, match="publication failed"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        assert settings.read_bytes() == external

        monkeypatch.setattr(windows_acl, "move_file_no_replace", move)
        unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == external
        assert _claude_released_names(data_home) == {"demo"}

    @pytest.mark.skipif(os.name == "nt", reason="POSIX absent-leaf publication race")
    def test_posix_absent_leaf_creator_is_preserved(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        external = b'{"mcpServers":{"operator":{"command":"external"}}}\n'
        publish = connector_paths._atomic_replace_claude_with_proof

        def publish_with_creator(snapshot, payload, **kwargs):
            if os.path.abspath(snapshot.path) != os.path.abspath(settings):
                return publish(snapshot, payload, **kwargs)
            before_publish = kwargs["before_publish"]

            def create_external(candidate):
                before_publish(candidate)
                replacement = settings.with_name("operator-created-settings.json")
                replacement.write_bytes(external)
                os.replace(replacement, settings)

            kwargs["before_publish"] = create_external
            return publish(snapshot, payload, **kwargs)

        monkeypatch.setattr(
            connector_paths,
            "_atomic_replace_claude_with_proof",
            publish_with_creator,
        )
        with pytest.raises(MCPWriteUnsupportedError, match="publication failed"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        assert settings.read_bytes() == external

        monkeypatch.setattr(
            connector_paths,
            "_atomic_replace_claude_with_proof",
            publish,
        )
        # The public dispatcher is consistently a command-style API: internal
        # Claude recovery may report whether it mutated state, but callers see
        # the documented ``None`` result used by every connector branch.
        assert unset_mcp_server("claudecode", "demo") is None
        assert settings.read_bytes() == external
        assert _claude_released_names(data_home) == {"demo"}

    @pytest.mark.skipif(os.name != "nt", reason="Windows private journal ACL contract")
    @pytest.mark.parametrize("leaf", ["ownership", "lock"])
    def test_windows_unsafe_private_journal_acl_fails_closed(self, tmp_path, monkeypatch, leaf):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        set_mcp_server("claudecode", "first", {"command": "inert-first"})
        ownership = Path(connector_paths._claude_mcp_ownership_path(str(settings)))
        target = ownership if leaf == "ownership" else Path(f"{ownership}.lock")
        settings_before = settings.read_bytes()
        target_before = target.read_bytes()
        acl_check = file_permissions.windows_acl_write_error

        def reject_target(path):
            if os.path.normcase(os.path.abspath(path)) == os.path.normcase(os.path.abspath(target)):
                return "mocked unsafe journal DACL"
            return acl_check(path)

        monkeypatch.setattr(file_permissions, "windows_acl_write_error", reject_target)
        with pytest.raises(MCPWriteUnsupportedError, match="not private"):
            set_mcp_server("claudecode", "second", {"command": "inert-second"})

        assert settings.read_bytes() == settings_before
        assert target.read_bytes() == target_before

    @pytest.mark.skipif(os.name == "nt", reason="POSIX private journal mode contract")
    @pytest.mark.parametrize("leaf", ["ownership", "lock"])
    def test_posix_unsafe_private_journal_mode_fails_closed(self, tmp_path, monkeypatch, leaf):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        set_mcp_server("claudecode", "first", {"command": "inert-first"})
        ownership = Path(connector_paths._claude_mcp_ownership_path(str(settings)))
        target = ownership if leaf == "ownership" else Path(f"{ownership}.lock")
        settings_before = settings.read_bytes()
        target_before = target.read_bytes()
        target.chmod(0o644)

        with pytest.raises(MCPWriteUnsupportedError, match="owner-only permissions"):
            set_mcp_server("claudecode", "second", {"command": "inert-second"})

        assert settings.read_bytes() == settings_before
        assert target.read_bytes() == target_before

    def test_shared_registry_concurrent_edit_is_preserved(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{"theme":"operator"}\n'
        settings.write_bytes(original)
        backup = Path(connector_paths._managed_mcp_backup_path(str(settings)))
        backup.write_bytes(original)
        connector_paths._registry_register(str(settings.resolve()), str(backup))
        registry_path = Path(connector_paths._registry_path())
        write_metadata = connector_paths._write_claude_private_metadata
        lock_update = connector_paths._locked_claude_file_update
        locked: list[str] = []
        concurrent_bytes = b""
        raced = False

        @contextmanager
        def track_lock(path, *, label):
            locked.append(os.path.abspath(path))
            with lock_update(path, label=label) as lock:
                yield lock

        def write_after_registry_race(path, payload, *args, **kwargs):
            nonlocal raced, concurrent_bytes
            if not raced and os.path.normcase(os.path.abspath(path)) == os.path.normcase(
                os.path.abspath(registry_path),
            ):
                raced = True
                concurrent = json.loads(registry_path.read_text(encoding="utf-8"))
                concurrent["concurrent"] = {
                    "path": str(tmp_path / "other"),
                    "backup": str(tmp_path / "other.bak"),
                    "ts": "2026-01-01T00:00:00Z",
                }
                concurrent_bytes = (json.dumps(concurrent, sort_keys=True) + "\n").encode()
                file_permissions.atomic_write_private_bytes(registry_path, concurrent_bytes)
            return write_metadata(path, payload, *args, **kwargs)

        monkeypatch.setattr(
            connector_paths,
            "_locked_claude_file_update",
            track_lock,
        )
        monkeypatch.setattr(
            connector_paths,
            "_write_claude_private_metadata",
            write_after_registry_race,
        )
        with pytest.raises(MCPWriteUnsupportedError, match="metadata|changed|publication"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})

        assert raced
        assert settings.read_bytes() == original
        assert registry_path.read_bytes() == concurrent_bytes
        assert os.path.abspath(registry_path) in locked

    def test_ownership_metadata_concurrent_edit_is_preserved(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        set_mcp_server("claudecode", "first", {"command": "inert-first"})
        settings_before = settings.read_bytes()
        metadata = Path(connector_paths._claude_mcp_ownership_path(str(settings)))
        write_metadata = connector_paths._write_claude_private_metadata
        concurrent_bytes = b""
        raced = False

        def write_after_ownership_race(path, payload, *args, **kwargs):
            nonlocal raced, concurrent_bytes
            if not raced and os.path.normcase(os.path.abspath(path)) == os.path.normcase(
                os.path.abspath(metadata),
            ):
                raced = True
                concurrent = json.loads(metadata.read_text(encoding="utf-8"))
                concurrent["operator_note"] = "preserve"
                concurrent_bytes = (json.dumps(concurrent, sort_keys=True) + "\n").encode()
                file_permissions.atomic_write_private_bytes(metadata, concurrent_bytes)
            return write_metadata(path, payload, *args, **kwargs)

        monkeypatch.setattr(
            connector_paths,
            "_write_claude_private_metadata",
            write_after_ownership_race,
        )
        with pytest.raises(MCPWriteUnsupportedError, match="metadata|changed|publication"):
            set_mcp_server("claudecode", "second", {"command": "inert-second"})

        assert raced
        assert settings.read_bytes() == settings_before
        assert metadata.read_bytes() == concurrent_bytes

    def test_ownership_metadata_delete_cas_preserves_same_byte_replacement(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{ "theme" : "operator" }\n'
        settings.write_bytes(original)
        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        metadata = _claude_ownership_files(data_home)[0]
        delete = connector_paths._delete_private_regular_file
        replaced_bytes = b""

        def replace_before_delete(path, **kwargs):
            nonlocal replaced_bytes
            if os.path.normcase(os.path.abspath(path)) == os.path.normcase(os.path.abspath(metadata)):
                replaced_bytes = metadata.read_bytes()
                replacement = metadata.with_name("operator-same-metadata.json")
                replacement.write_bytes(replaced_bytes)
                os.replace(replacement, metadata)
            return delete(path, **kwargs)

        monkeypatch.setattr(
            connector_paths,
            "_delete_private_regular_file",
            replace_before_delete,
        )
        with pytest.raises(MCPWriteUnsupportedError, match="metadata changed"):
            unset_mcp_server("claudecode", "demo")

        assert settings.read_bytes() == original
        assert metadata.read_bytes() == replaced_bytes

    def test_ownership_metadata_same_byte_publish_race_is_not_rebound(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{"theme":"operator"}\n'
        settings.write_bytes(original)
        metadata_path = Path(connector_paths._claude_mcp_ownership_path(str(settings)))
        publish = connector_paths._atomic_replace_claude_with_proof
        replacement_bytes = b""

        def publish_then_replace(snapshot, payload, **kwargs):
            nonlocal replacement_bytes
            proven = publish(snapshot, payload, **kwargs)
            if os.path.normcase(os.path.abspath(snapshot.path)) == os.path.normcase(os.path.abspath(metadata_path)):
                replacement_bytes = payload
                replacement = metadata_path.with_name("operator-same-journal.json")
                replacement.write_bytes(payload)
                os.replace(replacement, metadata_path)
            return proven

        monkeypatch.setattr(
            connector_paths,
            "_atomic_replace_claude_with_proof",
            publish_then_replace,
        )
        with pytest.raises(MCPWriteUnsupportedError, match="metadata was replaced"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})

        assert settings.read_bytes() == original
        assert metadata_path.read_bytes() == replacement_bytes

    @pytest.mark.parametrize("preexisting", [False, True])
    def test_same_byte_external_replacement_is_not_deleted(
        self,
        tmp_path,
        monkeypatch,
        preexisting,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        if preexisting:
            settings.parent.mkdir()
            settings.write_bytes(b'{"theme":"operator"}\n')
        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        managed_bytes = settings.read_bytes()
        replacement = settings.with_name("operator-settings.json")
        replacement.write_bytes(managed_bytes)
        os.replace(replacement, settings)

        unset_mcp_server("claudecode", "demo")

        assert settings.exists()
        assert settings.read_bytes() == managed_bytes
        assert _claude_released_names(data_home) == {"demo"}

    @pytest.mark.parametrize("preexisting", [False, True])
    def test_same_byte_replacement_between_publish_and_observation_is_never_owned(
        self,
        tmp_path,
        monkeypatch,
        preexisting,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        if preexisting:
            settings.parent.mkdir()
            settings.write_bytes(b'{"theme":"operator"}\n')
        publish = connector_paths._atomic_replace_claude_with_proof

        def publish_then_replace(snapshot, payload, **kwargs):
            proven = publish(snapshot, payload, **kwargs)
            if os.path.normcase(os.path.abspath(snapshot.path)) == os.path.normcase(os.path.abspath(settings)):
                replacement = settings.with_name("operator-same-bytes.json")
                replacement.write_bytes(payload)
                os.replace(replacement, settings)
            return proven

        monkeypatch.setattr(connector_paths, "_atomic_replace_claude_with_proof", publish_then_replace)
        with pytest.raises(MCPWriteUnsupportedError, match="replaced after publication"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})

        external_bytes = settings.read_bytes()
        metadata = _claude_ownership_files(data_home)
        assert len(metadata) == 1
        envelope = json.loads(metadata[0].read_text(encoding="utf-8"))
        assert isinstance(
            envelope["pending"]["next_state"]["postimage_identity"],
            dict,
        )

        monkeypatch.setattr(connector_paths, "_atomic_replace_claude_with_proof", publish)
        with pytest.raises(MCPWriteUnsupportedError, match="pending ownership"):
            unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == external_bytes
        assert _claude_released_names(data_home) == {"demo"}

    def test_same_byte_replacement_during_finalize_releases_ownership(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        finalize = connector_paths._finalize_claude_mcp_transaction

        def replace_before_finalize(path, next_state, next_released):
            if next_state is not None:
                payload = settings.read_bytes()
                replacement = settings.with_name("operator-finalize-bytes.json")
                replacement.write_bytes(payload)
                os.replace(replacement, settings)
            return finalize(path, next_state, next_released)

        monkeypatch.setattr(
            connector_paths,
            "_finalize_claude_mcp_transaction",
            replace_before_finalize,
        )
        with pytest.raises(MCPWriteUnsupportedError, match="published ownership"):
            set_mcp_server("claudecode", "demo", {"command": "inert-demo"})

        external_bytes = settings.read_bytes()
        assert json.loads(external_bytes)["mcpServers"]["demo"] == {"command": "inert-demo"}
        assert _claude_released_names(data_home) == {"demo"}

    def test_same_byte_replacement_before_exact_delete_is_preserved(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        managed_bytes = settings.read_bytes()
        delete = connector_paths._delete_private_regular_file

        def replace_before_delete(path, **kwargs):
            if os.path.normcase(os.path.abspath(path)) == os.path.normcase(os.path.abspath(settings)):
                replacement = settings.with_name("operator-delete-race.json")
                replacement.write_bytes(settings.read_bytes())
                os.replace(replacement, settings)
            return delete(path, **kwargs)

        monkeypatch.setattr(
            connector_paths,
            "_delete_private_regular_file",
            replace_before_delete,
        )
        with pytest.raises(MCPWriteUnsupportedError, match="changed before deletion"):
            unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == managed_bytes

        monkeypatch.setattr(connector_paths, "_delete_private_regular_file", delete)
        with pytest.raises(MCPWriteUnsupportedError, match="pending ownership"):
            unset_mcp_server("claudecode", "demo")
        assert settings.read_bytes() == managed_bytes
        assert _claude_released_names(data_home) == {"demo"}

    def test_ambiguous_recovery_never_acquires_next_only_server(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        set_mcp_server("claudecode", "first", {"command": "inert-first"})
        publish = connector_paths._publish_claude_config_if_unchanged

        def stop_before_publish(*_args, **_kwargs):
            raise RuntimeError("stop before config")

        monkeypatch.setattr(
            connector_paths,
            "_publish_claude_config_if_unchanged",
            stop_before_publish,
        )
        with pytest.raises(RuntimeError, match="stop before config"):
            set_mcp_server("claudecode", "second", {"command": "inert-second"})
        monkeypatch.setattr(connector_paths, "_publish_claude_config_if_unchanged", publish)

        external = json.loads(settings.read_text(encoding="utf-8"))
        external["theme"] = "operator"
        external["mcpServers"]["second"] = {"command": "inert-second"}
        settings.write_text(json.dumps(external), encoding="utf-8")
        set_mcp_server("claudecode", "third", {"command": "inert-third"})
        unset_mcp_server("claudecode", "first")
        unset_mcp_server("claudecode", "third")

        result = json.loads(settings.read_text(encoding="utf-8"))
        assert result["theme"] == "operator"
        assert result["mcpServers"] == {"second": {"command": "inert-second"}}

    def test_journal_preimage_continues_across_managed_server_episode(
        self,
        tmp_path,
        monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        data_home = tmp_path / "d"
        monkeypatch.setenv("DEFENSECLAW_HOME", str(data_home))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{\r\n  "mcpServers": {},\r\n  "theme": "operator"\r\n}\r\n'
        settings.write_bytes(original)

        def assert_episode_preimage() -> None:
            metadata = _claude_ownership_files(data_home)
            assert len(metadata) == 1
            envelope = json.loads(metadata[0].read_text(encoding="utf-8"))
            committed = envelope["committed"]
            assert base64.b64decode(committed["preimage_b64"], validate=True) == original
            assert committed["file_preexisting"] is True
            assert committed["container_preexisting"] is True
            assert committed["container_preimage"] == {}

        set_mcp_server("claudecode", "first", {"command": "inert-first"})
        assert_episode_preimage()
        set_mcp_server("claudecode", "second", {"command": "inert-second"})
        assert_episode_preimage()
        unset_mcp_server("claudecode", "first")
        assert_episode_preimage()
        unset_mcp_server("claudecode", "second")

        assert settings.read_bytes() == original
        assert _claude_ownership_files(data_home) == []

    @pytest.mark.skipif(os.name != "nt", reason="Windows publisher identity contract")
    def test_windows_existing_publish_verifies_target_bound_same_byte_identity(
        self,
        tmp_path,
        monkeypatch,
    ):
        from defenseclaw.observability import v8_activation

        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "d"))
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir()
        original = b'{ "theme" : "operator" }\r\n'
        settings.write_bytes(original)
        verify = v8_activation._repair_and_verify_windows_publication
        verified_settings: list[str] = []

        def verify_target_identity(path, staged, expected):
            if os.path.normcase(os.path.abspath(path)) == os.path.normcase(
                os.path.abspath(settings),
            ):
                current = v8_activation._snapshot_regular_file(path, required=True)
                assert os.path.normcase(os.path.abspath(staged.path)) == os.path.normcase(
                    os.path.abspath(path),
                )
                assert v8_activation._same_windows_publication_identity(current, staged)
                assert v8_activation._matches_expected_state(current, expected)
                assert current.windows_security == expected.windows_security

                # Equal payload and metadata alone do not establish ownership:
                # a different file identity with the same bytes must fail the
                # publisher binding check.
                same_bytes_impostor = replace(current, inode=(current.inode or 0) + 1)
                assert v8_activation._matches_expected_state(
                    same_bytes_impostor,
                    expected,
                )
                assert not v8_activation._same_windows_publication_identity(
                    same_bytes_impostor,
                    staged,
                )
                verified_settings.append(path)
            return verify(path, staged, expected)

        monkeypatch.setattr(
            v8_activation,
            "_repair_and_verify_windows_publication",
            verify_target_identity,
        )
        set_mcp_server("claudecode", "demo", {"command": "inert-demo"})
        unset_mcp_server("claudecode", "demo")

        assert verified_settings
        assert settings.read_bytes() == original

    @pytest.mark.skipif(os.name != "nt", reason="Windows native identity contract")
    def test_windows_journal_identity_ignores_only_crt_projection_fields(
        self,
        tmp_path,
    ):
        from defenseclaw.observability import v8_activation

        settings = tmp_path / "settings.json"
        settings.write_bytes(b"{}\n")
        snapshot = v8_activation._snapshot_regular_file(str(settings), required=True)
        identity = connector_paths._claude_postimage_identity_from_snapshot(snapshot)

        projected = replace(
            snapshot,
            mode=(snapshot.mode or 0) + 1,
            uid=(snapshot.uid or 0) + 1,
            gid=(snapshot.gid or 0) + 1,
        )
        assert connector_paths._claude_postimage_identity_from_snapshot(projected) == identity

        different_file = replace(snapshot, inode=(snapshot.inode or 0) + 1)
        assert connector_paths._claude_postimage_identity_from_snapshot(different_file) != identity

        assert snapshot.windows_security is not None
        different_security = replace(
            snapshot,
            windows_security=replace(
                snapshot.windows_security,
                dacl=snapshot.windows_security.dacl + b"\x00",
            ),
        )
        assert connector_paths._claude_postimage_identity_from_snapshot(different_security) != identity


# ---------------------------------------------------------------------------
# Codex — patches ~/.codex/config.toml by default
# ---------------------------------------------------------------------------


class TestCodexWrites:
    def test_set_creates_global_config_toml(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("codex", "demo", {"command": "uvx", "args": ["d"]})

        path = tmp_path / ".codex" / "config.toml"
        assert path.is_file()
        entries = connector_paths.mcp_servers("codex")
        assert [e.name for e in entries] == ["demo"]
        assert entries[0].command == "uvx"
        assert entries[0].args == ["d"]

    def test_set_uses_0o600(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("codex", "demo", {"command": "uvx"})
        path = tmp_path / ".codex" / "config.toml"
        assert_owner_only_file(path)

    def test_unset_removes_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        path = tmp_path / ".codex" / "config.toml"
        path.parent.mkdir()
        path.write_text('[mcp_servers.demo]\ncommand = "x"\n\n[mcp_servers.keep]\ncommand = "y"\n')
        unset_mcp_server("codex", "demo")
        entries = connector_paths.mcp_servers("codex")
        assert [e.name for e in entries] == ["keep"]
        assert entries[0].command == "y"

    def test_set_captures_restorable_backup(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        path = tmp_path / ".codex" / "config.toml"
        path.parent.mkdir()
        path.write_text('[mcp_servers.old]\ncommand = "old"\n')

        set_mcp_server("codex", "demo", {"command": "uvx"})
        assert (tmp_path / ".codex" / ".defenseclaw-config.toml.bak").is_file()
        assert restore_managed_mcp_backup(str(path))

        entries = connector_paths.mcp_servers("codex")
        assert [e.name for e in entries] == ["old"]
        assert entries[0].command == "old"

    def test_set_records_absolute_target_in_registry(self, tmp_path, monkeypatch):
        """C-2: workspace MCP backup must persist the absolute target path.

        Without this, ``restore_managed_mcp_backup`` could not be
        called from a different cwd (Copilot, Codex, Cursor all use
        workspace-scoped paths), and a ``cd`` between setup and
        teardown would silently lose the original config.
        """
        # DEFENSECLAW_HOME isolates the registry for this test run.
        monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dchome"))
        workspace = tmp_path / "ws"
        workspace.mkdir()
        monkeypatch.chdir(workspace)
        path = workspace / ".mcp.json"
        path.write_text(json.dumps({"mcpServers": {"old": {"command": "old"}}}))

        set_mcp_server("codex", "demo", {"command": "uvx"}, workspace_dir=str(workspace))

        recorded = lookup_managed_mcp_backup(str(path))
        assert recorded is not None
        assert os.path.isabs(recorded), recorded
        # The registry directory itself must be 0o700 because it
        # leaks every config path DefenseClaw has ever touched.
        registry_dir = tmp_path / "dchome" / "connector_backups" / "mcp"
        assert registry_dir.is_dir()
        assert_owner_only_directory(registry_dir)

        # Restore from a totally different cwd — proves the fix.
        far_away = tmp_path / "elsewhere"
        far_away.mkdir()
        monkeypatch.chdir(far_away)
        assert restore_managed_mcp_backup(str(path)) is True
        data = json.loads(path.read_text())
        assert "demo" not in data["mcpServers"]
        assert data["mcpServers"]["old"]["command"] == "old"


# ---------------------------------------------------------------------------
# Antigravity — patches ~/.gemini/config/mcp_config.json by default
# ---------------------------------------------------------------------------


class TestAntigravityWrites:
    def _global(self, home) -> os.PathLike:
        return home / ".gemini" / "config" / "mcp_config.json"

    def test_set_remote_uses_server_url_and_preserves_unknowns(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        path = self._global(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text(
            json.dumps(
                {
                    "theme": "dark",
                    "mcpServers": {
                        "demo": {
                            "url": "https://old.example/mcp",
                            "x-antigravity": {"keep": True},
                        },
                        "keep": {"command": "stay"},
                    },
                }
            )
        )

        set_mcp_server(
            "antigravity",
            "demo",
            {
                "url": "https://new.example/mcp",
                "transport": "sse",
                "headers": {"Authorization": "Bearer ${AGY_MCP_TOKEN}"},
                "authProviderType": "oauth",
                "oauth": {"issuer": "https://accounts.example.com"},
                "futureField": {"enabled": True},
            },
        )

        data = json.loads(path.read_text())
        assert data["theme"] == "dark"
        assert data["mcpServers"]["keep"] == {"command": "stay"}
        demo = data["mcpServers"]["demo"]
        assert demo["serverUrl"] == "https://new.example/mcp"
        assert "url" not in demo
        assert "httpUrl" not in demo
        assert demo["transport"] == "sse"
        assert demo["headers"] == {"Authorization": "Bearer ${AGY_MCP_TOKEN}"}
        assert demo["authProviderType"] == "oauth"
        assert demo["oauth"] == {"issuer": "https://accounts.example.com"}
        assert demo["x-antigravity"] == {"keep": True}
        assert demo["futureField"] == {"enabled": True}
        entries = connector_paths.mcp_servers("antigravity")
        assert entries[0].transport == "sse"

    def test_set_local_supports_native_fields(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server(
            "antigravity",
            "local",
            {
                "command": "/opt/defenseclaw/bin/defenseclaw",
                "args": ["mcp", "serve"],
                "env": {"AGY_PROFILE": "default"},
                "cwd": "/workspace/project",
                "disabled": True,
                "disabledTools": ["unsafe_tool"],
            },
        )

        data = json.loads(self._global(tmp_path).read_text())
        assert data["mcpServers"]["local"] == {
            "command": "/opt/defenseclaw/bin/defenseclaw",
            "args": ["mcp", "serve"],
            "env": {"AGY_PROFILE": "default"},
            "cwd": "/workspace/project",
            "disabled": True,
            "disabledTools": ["unsafe_tool"],
        }

    def test_workspace_writes_agents_mcp_config(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        workspace = tmp_path / "ws"
        workspace.mkdir()

        set_mcp_server(
            "antigravity",
            "demo",
            {"command": "npx", "args": ["demo-mcp"]},
            workspace_dir=str(workspace),
        )

        project_config = workspace / ".agents" / "mcp_config.json"
        assert project_config.is_file()
        assert not self._global(tmp_path / "home").exists()
        entries = connector_paths.mcp_servers("antigravity", workspace_dir=str(workspace))
        assert [e.name for e in entries] == ["demo"]
        assert entries[0].command == "npx"
        assert entries[0].args == ["demo-mcp"]

    def test_set_uses_0o600(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server(
            "antigravity",
            "demo",
            {"command": "x", "env": {"API_KEY": "secret"}},
        )
        assert_owner_only_file(self._global(tmp_path))

    def test_unset_removes_entry_preserves_others(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        path = self._global(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "demo": {"command": "x"},
                        "keep": {"serverUrl": "https://keep.example/mcp"},
                    },
                }
            )
        )

        unset_mcp_server("antigravity", "demo")

        data = json.loads(path.read_text())
        assert "demo" not in data["mcpServers"]
        assert data["mcpServers"]["keep"] == {"serverUrl": "https://keep.example/mcp"}

    def test_round_trip_set_read_unset(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("antigravity", "demo", {"url": "https://x.example/mcp"})
        entries = connector_paths.mcp_servers("antigravity")
        assert [e.name for e in entries] == ["demo"]
        assert entries[0].url == "https://x.example/mcp"
        assert entries[0].transport == "http"

        unset_mcp_server("antigravity", "demo")
        assert connector_paths.mcp_servers("antigravity") == []


# ---------------------------------------------------------------------------
# Round-trip: set → mcp_servers() → unset → mcp_servers()
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_codex_set_then_read_then_unset(self, tmp_path, monkeypatch):
        # Isolate HOME so the real user's ``~/.codex/config.toml``
        # (which may register global MCP servers like ``playwright``)
        # doesn't bleed into ``mcp_servers("codex")`` — the codex
        # reader merges the global TOML table with the project-local
        # ``./.mcp.json`` we're about to write, and without HOME
        # pinned to ``tmp_path`` this assertion is non-deterministic
        # across dev machines.
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(tmp_path)

        set_mcp_server(
            "codex",
            "demo",
            {"command": "uvx", "args": ["demo-mcp"]},
        )
        entries = connector_paths.mcp_servers("codex")
        assert [e.name for e in entries] == ["demo"]
        assert entries[0].command == "uvx"
        assert entries[0].args == ["demo-mcp"]

        unset_mcp_server("codex", "demo")
        entries = connector_paths.mcp_servers("codex")
        assert entries == []

    def test_claudecode_set_then_read_then_unset(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(tmp_path)

        set_mcp_server("claudecode", "ccd", {"command": "ccd-mcp"})
        entries = connector_paths.mcp_servers("claudecode")
        assert "ccd" in [e.name for e in entries]

        unset_mcp_server("claudecode", "ccd")
        entries = connector_paths.mcp_servers("claudecode")
        assert "ccd" not in [e.name for e in entries]


# ---------------------------------------------------------------------------
# Atomicity — partially-broken existing file gets reset to {} not crashed
# ---------------------------------------------------------------------------


class TestAtomicity:
    def test_set_recovers_from_corrupt_json(self, tmp_path, monkeypatch):
        if os.name == "nt":
            file_permissions._set_windows_owner_only_acl(os.fspath(tmp_path))
        path = tmp_path / ".mcp.json"
        path.write_text("{ this is not valid json")

        set_mcp_server("codex", "demo", {"command": "uvx"}, workspace_dir=str(tmp_path))

        data = json.loads(path.read_text())
        assert data["mcpServers"]["demo"]["command"] == "uvx"

    def test_set_does_not_leave_tempfile_on_success(
        self,
        tmp_path,
        monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("codex", "demo", {"command": "uvx"})
        # No leftover .dc-mcp- temp files
        codex_dir = tmp_path / ".codex"
        leftovers = [p for p in os.listdir(codex_dir) if p.startswith(".dc-mcp-")]
        assert leftovers == []


# ---------------------------------------------------------------------------
# All known connectors are covered (no silent fallthrough)
# ---------------------------------------------------------------------------


class TestCoverage:
    def test_every_known_connector_has_explicit_set_behavior(self, tmp_path):
        """Loop over KNOWN_CONNECTORS and assert each branch is reached.
        Catches the "added a connector but forgot to teach the
        writer" bug class.
        """
        for name in KNOWN_CONNECTORS:
            if name == "openclaw":
                # Requires injected setter — assert it raises without one.
                with pytest.raises(RuntimeError):
                    set_mcp_server(name, "x", {"command": "y"})
            elif name in {"zeptoclaw", "omnigent"}:
                with pytest.raises(MCPWriteUnsupportedError):
                    set_mcp_server(name, "x", {"command": "y"})
            elif name == "windsurf":
                with pytest.MonkeyPatch.context() as m:
                    m.setenv("HOME", str(tmp_path / "isolated-home"))
                    with pytest.raises(MCPWriteUnsupportedError):
                        set_mcp_server(name, "x", {"command": "y"})
            elif name == "antigravity":
                # Antigravity now has a documented native MCP write path:
                # ~/.gemini/config/mcp_config.json.
                with pytest.MonkeyPatch.context() as m:
                    m.setenv("HOME", str(tmp_path / "agy-home"))
                    set_mcp_server(name, "x", {"command": "y"})
                    assert (tmp_path / "agy-home" / ".gemini" / "config" / "mcp_config.json").is_file()
            elif name == "opencode":
                # opencode now has full MCP write parity (mcp.md M2/M5):
                # set writes the global ~/.config/opencode/opencode.json.
                with pytest.MonkeyPatch.context() as m:
                    m.setenv("HOME", str(tmp_path / "oc-home"))
                    set_mcp_server(name, "x", {"command": "y"})
                    assert (tmp_path / "oc-home" / ".config" / "opencode" / "opencode.json").is_file()
            else:
                # All other connectors have a documented MCP write path.
                # Use chdir + isolated HOME so the test doesn't trash
                # the developer's real config files.
                with pytest.MonkeyPatch.context() as m:
                    m.chdir(tmp_path)
                    m.setenv("HOME", str(tmp_path))
                    if name == "hermes":
                        m.setenv("HERMES_HOME", str(tmp_path / ".hermes"))
                    set_mcp_server(name, "x", {"command": "y"})


class TestHermesWrites:
    def test_set_and_unset_honor_hermes_home(self, tmp_path, monkeypatch):
        hermes_home = tmp_path / "custom-hermes"
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))

        set_mcp_server("hermes", "demo", {"command": "hermes-mcp"})

        config = hermes_home / "config.yaml"
        assert config.is_file()
        assert [entry.name for entry in connector_paths.mcp_servers("hermes")] == ["demo"]

        unset_mcp_server("hermes", "demo")

        assert connector_paths.mcp_servers("hermes") == []


# ---------------------------------------------------------------------------
# opencode — full read+write parity (mcp.md M2/M5). Writes the global
# ~/.config/opencode/opencode.json (project file under explicit workspace),
# mapping into opencode's `mcp` schema (type/command-argv/environment).
# ---------------------------------------------------------------------------


class TestOpenCodeWrites:
    def _global(self, home) -> os.PathLike:
        return home / ".config" / "opencode" / "opencode.json"

    def test_set_creates_global_with_opencode_schema(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server(
            "opencode",
            "demo",
            {"command": "npx", "args": ["-y", "demo-mcp"], "env": {"K": "v"}},
        )
        path = self._global(tmp_path)
        assert path.is_file()
        data = json.loads(path.read_text())
        # opencode's bespoke schema: top-level `mcp`, fused command argv,
        # `environment` (not `env`), explicit type + enabled.
        assert data["mcp"]["demo"] == {
            "type": "local",
            "command": ["npx", "-y", "demo-mcp"],
            "enabled": True,
            "environment": {"K": "v"},
        }

    def test_set_remote_server(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("opencode", "api", {"url": "https://x.example/mcp"})
        data = json.loads(self._global(tmp_path).read_text())
        assert data["mcp"]["api"] == {
            "type": "remote",
            "url": "https://x.example/mcp",
            "enabled": True,
        }

    def test_set_preserves_unrelated_keys(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        path = self._global(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text(
            json.dumps(
                {
                    "$schema": "https://opencode.ai/config.json",
                    "theme": "tokyonight",
                    "mcp": {"existing": {"type": "local", "command": ["keep"]}},
                }
            )
        )
        set_mcp_server("opencode", "demo", {"command": "npx"})
        data = json.loads(path.read_text())
        assert data["$schema"] == "https://opencode.ai/config.json"
        assert data["theme"] == "tokyonight"
        assert data["mcp"]["existing"] == {"type": "local", "command": ["keep"]}
        assert data["mcp"]["demo"]["command"] == ["npx"]

    def test_set_uses_0o600(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("opencode", "demo", {"command": "x", "env": {"API_KEY": "s"}})
        assert_owner_only_file(self._global(tmp_path))

    def test_unset_removes_entry_preserves_others(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        path = self._global(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text(
            json.dumps(
                {
                    "mcp": {
                        "demo": {"type": "local", "command": ["x"]},
                        "keep": {"type": "local", "command": ["y"]},
                    },
                }
            )
        )
        unset_mcp_server("opencode", "demo")
        data = json.loads(path.read_text())
        assert "demo" not in data["mcp"]
        assert data["mcp"]["keep"] == {"type": "local", "command": ["y"]}

    def test_unset_missing_is_noop(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        unset_mcp_server("opencode", "demo")  # no file — must not raise

    def test_round_trip_set_read_unset(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        set_mcp_server("opencode", "demo", {"command": "npx", "args": ["demo-mcp"]})
        entries = connector_paths.mcp_servers("opencode")
        assert [e.name for e in entries] == ["demo"]
        assert entries[0].command == "npx"
        assert entries[0].args == ["demo-mcp"]

        unset_mcp_server("opencode", "demo")
        assert connector_paths.mcp_servers("opencode") == []

    def test_workspace_writes_project_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        workspace = tmp_path / "ws"
        workspace.mkdir()
        set_mcp_server(
            "opencode",
            "demo",
            {"command": "npx"},
            workspace_dir=str(workspace),
        )
        # Project file written; global left untouched.
        assert (workspace / "opencode.json").is_file()
        assert not self._global(tmp_path / "home").exists()
        names = {e.name for e in connector_paths.mcp_servers("opencode", workspace_dir=str(workspace))}
        assert names == {"demo"}

    def test_set_fails_closed_on_unparseable_existing(self, tmp_path, monkeypatch):
        """A config we can't safely parse must NOT be clobbered — the
        writer raises instead of overwriting unrelated content."""
        monkeypatch.setenv("HOME", str(tmp_path))
        path = self._global(tmp_path)
        path.parent.mkdir(parents=True)
        # Valid JSON but not an object (top-level array) → unexpected shape.
        original = json.dumps([1, 2, 3])
        path.write_text(original)
        with pytest.raises(MCPWriteUnsupportedError):
            set_mcp_server("opencode", "demo", {"command": "x"})
        # File left exactly as it was.
        assert path.read_text() == original
