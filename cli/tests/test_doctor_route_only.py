# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Doctor and status rows for route-only mode (S1 1.0.10 items 3 and 4)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw import doctor_route_only as dro
from defenseclaw import routing_route_only as ro

_ANTHROPIC = {"base_url": "https://api.anthropic.com", "api": "messages"}
_BEDROCK_PROFILE = {
    "base_url": "https://bedrock-runtime.us-west-2.amazonaws.com",
    "api": "invoke",
    "bedrock": {"auth": "profile", "profile": "bedrock-dev", "region": "us-west-2"},
}


def _cfg(tmp_path: Path, upstreams: dict, *, enabled: bool = True, models: list | None = None) -> SimpleNamespace:
    routing = SimpleNamespace(
        enabled=enabled, models=models or [], route_only={"connectors": list(upstreams), "upstreams": upstreams}
    )
    return SimpleNamespace(
        routing=routing, gateway=SimpleNamespace(api_port=18970), data_dir=str(tmp_path), deployment_mode=""
    )


def _health(*rows: dict) -> dict:
    return {"routing": {"state": "running", "details": {"enabled": True, "route_only": list(rows)}}}


@pytest.fixture(autouse=True)
def homes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in ("claude", "codex"):
        (tmp_path / name).mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "claude"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    for k in list(os.environ):
        if k.startswith(("ANTHROPIC_", "CLAUDE_CODE_", "AWS_")):
            monkeypatch.delenv(k, raising=False)
    return tmp_path


def _by_label(rows: list[dro.Row]) -> dict[str, dro.Row]:
    return {row.label: row for row in rows}


def _render_claude(tmp_path: Path, base: str = "http://127.0.0.1:18970/r/claudecode") -> None:
    env = {"ANTHROPIC_BASE_URL": base, "ANTHROPIC_CUSTOM_HEADERS": "X-DC-Route-Auth: dcr1-abc"}
    (tmp_path / "claude" / "settings.json").write_text(json.dumps({"env": env}), encoding="utf-8")


def test_nothing_routed_and_routing_off(tmp_path: Path) -> None:
    assert dro.route_only_rows(_cfg(tmp_path, {}), None) == []
    rows = dro.route_only_rows(_cfg(tmp_path, {"claudecode": _ANTHROPIC}, enabled=False), None)
    assert [r.tag for r in rows] == ["warn"] and "routing.enabled is false" in rows[0].detail


def test_ready_passthrough_and_agent_config(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {"claudecode": _ANTHROPIC})
    live = _health(
        {
            "connector": "claudecode",
            "mounted": True,
            "ready": True,
            "credential": "agent",
            "provider": "anthropic",
            "upstream": "https://api.anthropic.com",
        }
    )
    rows = _by_label(dro.route_only_rows(cfg, live, platform="linux"))
    assert rows["Route-only claudecode"].tag == "pass"
    assert "agent credential is passed through" in rows["Route-only claudecode"].detail
    assert rows["Route-only claudecode agent config"].tag == "warn"
    _render_claude(tmp_path)
    rows = _by_label(dro.route_only_rows(cfg, live, platform="linux"))
    assert rows["Route-only claudecode agent config"].tag == "pass"
    _render_claude(tmp_path, "https://api.anthropic.com")
    drift = _by_label(dro.route_only_rows(cfg, live, platform="linux"))["Route-only claudecode agent config"]
    assert drift.tag == "warn" and "defenseclaw-gateway restart" in drift.fix


def test_codex_agent_config(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {"codex": {"base_url": "https://api.openai.com/v1", "api": "responses"}})
    (tmp_path / "codex" / "config.toml").write_text(
        'model_provider = "defenseclaw_route"\n\n[model_providers.defenseclaw_route]\n'
        'base_url = "http://127.0.0.1:18970/r/codex"\n',
        encoding="utf-8",
    )
    rows = _by_label(dro.route_only_rows(cfg, _health(), platform="linux"))
    assert rows["Route-only codex agent config"].tag == "pass"
    assert rows["Route-only codex"].tag == "warn"  # an older gateway reports no state


def test_custody_without_a_gateway_key_fails(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {"claudecode": _ANTHROPIC})
    fix = "set routing.models[].credential for anthropic (base_url https://api.anthropic.com) in the policy bundle"
    live = _health(
        {
            "connector": "claudecode",
            "mounted": True,
            "custody": True,
            "ready": False,
            "credential": "missing",
            "problem": "every model call answers 503",
            "fix": fix,
        }
    )
    row = _by_label(dro.route_only_rows(cfg, live, profile="standalone", platform="darwin"))["Route-only claudecode"]
    assert row.tag == "fail" and row.fix == fix
    # Gateway down: the same gap is found offline from config.yaml.
    row = dro.route_only_rows(cfg, None, profile="standalone", platform="darwin")[0]
    assert row.tag == "fail" and row.fix == fix
    covered = _cfg(
        tmp_path, {"claudecode": _ANTHROPIC}, models=[{"name": "s", "provider": "anthropic", "credential": "org"}]
    )
    row = dro.route_only_rows(covered, None, profile="standalone", platform="darwin")[0]
    assert row.tag == "fail" and "guardian" in row.fix
    assert dro.route_only_rows(cfg, None, profile="standalone", platform="linux")[0].fix.startswith("the guardian")
    assert not dro.custody_covered(
        _cfg(tmp_path, {}, models=[{"provider": "anthropic", "credential": "org", "base_url": "https://llm.corp"}]),
        _ANTHROPIC,
    )
    assert dro.custody_covered(
        cfg,
        {
            "base_url": "https://bedrock-runtime.us-east-1.amazonaws.com",
            "api": "invoke",
            "bedrock": {"auth": "instance_role"},
        },
    )


def test_gateway_down_names_the_way_back(tmp_path: Path) -> None:
    row = dro.route_only_rows(_cfg(tmp_path, {"claudecode": _ANTHROPIC}), None, platform="linux")[0]
    assert row.tag == "fail" and "defenseclaw routing disable --connector claudecode" in row.fix
    row = dro.route_only_rows(_cfg(tmp_path, {"claudecode": {}}), None, platform="linux")[0]
    assert row.tag == "fail" and "routing enable --connector claudecode" in row.fix


def test_bedrock_signing_rows_from_the_gateway(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {"claudecode": _BEDROCK_PROFILE})
    good = {
        "auth": "profile",
        "profile": "bedrock-dev",
        "profile_found": True,
        "region": "us-west-2",
        "region_ok": True,
        "signer": True,
        "credential": True,
    }
    live = _health(
        {"connector": "claudecode", "mounted": True, "ready": True, "credential": "gateway_signing", "signing": good}
    )
    rows = _by_label(dro.route_only_rows(cfg, live, platform="linux"))
    for name in ("signer", "region", "profile", "credential"):
        assert rows[f"Route-only claudecode Bedrock {name}"].tag == "pass", name
    bad = {
        "auth": "profile",
        "profile": "bedrock-dev",
        "profile_found": True,
        "region": "us-west-2",
        "region_ok": True,
        "signer": True,
        "credential": False,
        "credential_error": "the SSO session has expired",
    }
    live = _health(
        {
            "connector": "claudecode",
            "mounted": True,
            "ready": False,
            "credential": "gateway_signing",
            "signing": bad,
            "problem": "gateway Bedrock signing is not ready",
            "fix": "check it",
        }
    )
    rows = _by_label(dro.route_only_rows(cfg, live, platform="linux"))
    assert rows["Route-only claudecode"].tag == "fail"
    cred = rows["Route-only claudecode Bedrock credential"]
    assert cred.tag == "fail" and "SSO session" in cred.detail and "aws sso login" in cred.fix
    missing = dict(bad, signer=False, profile_found=False, signer_error="profile gone")
    rows = _by_label(
        dro.route_only_rows(
            cfg, _health({"connector": "claudecode", "ready": False, "signing": missing}), platform="linux"
        )
    )
    assert rows["Route-only claudecode Bedrock profile"].tag == "fail"
    assert "Route-only claudecode Bedrock credential" not in rows  # no signer, nothing fetched


def test_bedrock_signing_rows_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    aws = tmp_path / "aws"
    aws.mkdir()
    (aws / "config").write_text("[profile bedrock-dev]\nregion = us-west-2\n", encoding="utf-8")
    (aws / "credentials").write_text("", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(aws / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(aws / "credentials"))
    rows = _by_label(dro.route_only_rows(_cfg(tmp_path, {"claudecode": _BEDROCK_PROFILE}), None, platform="linux"))
    assert rows["Route-only claudecode Bedrock region"].tag == "pass"
    assert rows["Route-only claudecode Bedrock profile"].tag == "pass"
    assert rows["Route-only claudecode Bedrock credential"].tag == "skip"
    other = dict(_BEDROCK_PROFILE, bedrock={"auth": "profile", "profile": "gone", "region": "eu-west-1"})
    rows = _by_label(dro.route_only_rows(_cfg(tmp_path, {"claudecode": other}), None, platform="linux"))
    assert rows["Route-only claudecode Bedrock region"].tag == "fail"
    assert "us-west-2" in rows["Route-only claudecode Bedrock region"].detail
    assert rows["Route-only claudecode Bedrock profile"].tag == "fail"
    passthrough = dict(_BEDROCK_PROFILE, bedrock={"auth": "passthrough"})
    assert not dro.signing_rows("claudecode", passthrough, None)


def test_held_api_port_and_shared_mac(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {"claudecode": _ANTHROPIC})
    (tmp_path / "hooks").mkdir()
    (tmp_path / "hooks" / dro.PORT_HELD_MARK).write_text(json.dumps({"uid": 4242}), encoding="utf-8")
    users = tmp_path / "Users"
    for name in ("alice", "Shared", ".localized"):
        (users / name).mkdir(parents=True)
    rows = _by_label(dro.route_only_rows(cfg, None, platform="darwin", users_dir=str(users)))
    held = rows["Route-only API port"]
    assert held.tag == "fail" and "uid 4242" in held.detail and "sport = :18970" in held.fix
    assert "Route-only on a shared Mac" not in rows
    (users / "bob").mkdir()
    rows = _by_label(dro.route_only_rows(cfg, None, platform="darwin", users_dir=str(users)))
    assert rows["Route-only on a shared Mac"].tag == "warn"
    assert "Route-only on a shared Mac" not in _by_label(
        dro.route_only_rows(cfg, None, platform="linux", users_dir=str(users))
    )
    assert "Route-only on a shared Mac" not in _by_label(
        dro.route_only_rows(cfg, None, profile="standalone", platform="darwin", users_dir=str(users))
    )


def test_status_keeps_one_state_per_connector(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw.commands import cmd_status

    monkeypatch.setattr(cmd_status, "_enterprise_profile", lambda cfg: "")
    cfg = _cfg(tmp_path, {"claudecode": _BEDROCK_PROFILE})
    rows = cmd_status._route_only_status(cfg, None)
    assert [r["label"] for r in rows] == ["Route-only claudecode"] and rows[0]["tag"] == "fail"


def test_enable_on_a_managed_host_names_the_bundle_and_custody_key(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, {})
    cfg.deployment_mode = "managed_enterprise"
    with pytest.raises(ro.RouteOnlyError, match=r"policy bundle .*routing\.models\[\]\.credential"):
        ro.enable(cfg, "claudecode")
