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

"""Go/Python parity of the sandbox floors (openshell.admin managed keys and
guardrail.profiles.<p>.sandbox).

The corpus is shared with the Go loader test
(internal/config/openshell_tighten_corpus_test.go): both must accept and
refuse the same cases with the same message. The Secure Client refusals
match the Go golden line for line.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from defenseclaw import config as cfgmod
from defenseclaw import config_writer

_REPO = Path(__file__).resolve().parents[2]
_CORPUS = _REPO / "internal" / "config" / "testdata" / "sandbox_floor_cases.yaml"
_SC_GOLDEN = _REPO / "internal" / "config" / "testdata" / "sandbox_secure_client_refusals.golden"


def _cases() -> list[dict]:
    corpus = yaml.safe_load(_CORPUS.read_text(encoding="utf-8"))
    assert corpus["schema_version"] == 1
    return corpus["cases"]


@pytest.fixture(autouse=True)
def _unmanaged_host(monkeypatch):
    monkeypatch.setattr(config_writer, "machine_managed_standalone", lambda: False)
    monkeypatch.delenv(cfgmod.DEPLOYMENT_MODE_ENV, raising=False)
    monkeypatch.delenv("DEFENSECLAW_ENTERPRISE_PROFILE", raising=False)


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_shared_corpus_matches_go(case, tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(case["source"] + f"data_dir: {tmp_path}\n", encoding="utf-8")
    if case["valid"]:
        cfgmod.load()
        return
    with pytest.raises(ValueError) as exc:
        cfgmod.load()
    # Go's loader message is "config: " + Python's.
    assert case["error"] in "config: " + str(exc.value)


def test_secure_client_refusals_match_go_golden():
    golden = _SC_GOLDEN.read_text(encoding="utf-8").splitlines()
    admins = [
        {"allowed": True},
        {"required_for": ["codex"]},
        {"when_unavailable": "alert"},
        {"user_approvals": "none"},
        {"allowed_credentials": ["bedrock"]},
        {"on_silence": "stop"},
        {"max_silence_after": "5m"},
        {"process_tree": True},
        {"foreign_sandboxes": "alert"},
        {"allow_upstream_telemetry": False},
        {"delete_stopped_after": "14d"},
        {"request_access": "it@example.com"},
        {"driver_fallback": "none"},
        {"allowed": True, "request_access": "it@example.com"},
    ]
    assert len(golden) == len(admins)
    sc = {"deployment_mode": "managed_enterprise", "enterprise": {"profile": "secure_client"}}
    for admin, line in zip(admins, golden):
        with pytest.raises(ValueError) as exc:
            cfgmod.validate_sandbox_floors({**sc, "openshell": {"admin": admin}})
        assert str(exc.value) == "openshell: " + line
    # Secure Client stays unchanged without the new keys.
    cfgmod.validate_sandbox_floors({**sc, "openshell": {"admin": {"egress_block": ["paste.example"]}}})
    with pytest.raises(ValueError, match="not supported with the Secure Client integration"):
        cfgmod.validate_sandbox_floors({**sc, "guardrail": {"profiles": {"p": {"sandbox": {"process_tree": True}}}}})


def test_profile_sandbox_parses_and_saves_only_set_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(
        "config_version: 9\n"
        "openshell:\n  admin: {request_access: it@example.com, foreign_sandboxes: stop}\n"
        "guardrail:\n  profiles:\n    contractors:\n      sandbox:\n"
        "        required_for: [claudecode]\n        allow_mount: false\n        allowed_credentials: [none]\n"
        "        max_resources: {cpu: '2'}\n"
        "enterprise:\n  openshell: {install: setup, driver: vm, version: 0.1.3, gateway_port: 17671}\n",
        encoding="utf-8",
    )
    cfg = cfgmod.load()
    sandbox = cfg.guardrail.profiles["contractors"].sandbox
    assert sandbox is not None
    assert sandbox.required_for == ["claudecode"]
    assert sandbox.allow_mount is False
    assert sandbox.allowed_credentials == ["none"]
    assert sandbox.allowed is None and sandbox.allowed_harnesses == []
    assert cfg.openshell.admin.request_access == "it@example.com"
    assert cfg.openshell.admin.required_for is None
    # gateway_port and the other lifecycle keys still load (Go owns them).
    assert cfg.enterprise_openshell == cfgmod.EnterpriseOpenShellConfig(driver="vm")
    data = cfgmod._config_to_dict(cfg)
    assert "enterprise_openshell" not in data and "enterprise" not in data
    assert data["guardrail"]["profiles"]["contractors"]["sandbox"] == {
        "required_for": ["claudecode"],
        "allow_mount": False,
        "allowed_credentials": ["none"],
        "max_resources": {"cpu": "2"},
    }


def test_standalone_managed_writes_refused_even_for_admins(tmp_path, monkeypatch):
    path = str(tmp_path / "config.yaml")
    monkeypatch.setattr(cfgmod, "_is_admin_process", lambda: True)
    standalone = {"deployment_mode": "managed_enterprise", "enterprise": {"profile": "standalone"}}
    with pytest.raises(config_writer.ManagedConfigWriteError) as refused:
        cfgmod._assert_config_write_allowed(path, standalone)
    # One static class, both a writer refusal and a PermissionError.
    assert type(refused.value) is cfgmod.ManagedStandaloneWriteError
    assert isinstance(refused.value, PermissionError)
    with pytest.raises(config_writer.ManagedConfigWriteError):
        cfgmod._assert_config_write_allowed(
            path, standalone, config_writer.current_actor(config_writer.ACTOR_PREFIX_CLI)
        )
    cfgmod._assert_config_write_allowed(path, standalone, config_writer.ACTOR_LIFECYCLE)
    cfgmod._assert_config_write_allowed(path, standalone, config_writer.ACTOR_MIGRATION)
    # The Secure Client branch is unchanged: administrators may write.
    secure_client = {"deployment_mode": "managed_enterprise", "enterprise": {"profile": "secure_client"}}
    cfgmod._assert_config_write_allowed(path, secure_client)
    monkeypatch.setattr(cfgmod, "_is_admin_process", lambda: False)
    with pytest.raises(PermissionError, match="administrator privileges"):
        cfgmod._assert_config_write_allowed(path, secure_client)
    # Unmanaged documents are not gated.
    cfgmod._assert_config_write_allowed(path, {"deployment_mode": ""})
