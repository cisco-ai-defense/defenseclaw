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

"""Regression tests for the remediation batch of security findings.

Each test pins the FIXED behaviour of one finding and mirrors the
campaign repro PoC closely enough to fail against the pre-fix code:

* F-0022 / F-0023 / F-0024 — TLS skip-verify parsed with bare ``bool``
  so a quoted ``"false"`` disabled certificate verification.
* F-0808 — Splunk HEC forwarder followed redirects, replaying the
  bearer ``Authorization`` header onto an attacker-chosen host.
* F-0082 — legacy list migration let a stale allow row overwrite a
  block row for the same target.
* F-0083 — a freshly created audit DB was world-readable.
* F-0081 — a newer-schema migration cursor was overwritten as a fresh
  bootstrap.
* F-0681 — a lower-version migration that failed earlier was never
  retried on a later upgrade.
* F-0281 — spoofable marker substrings were trusted as proof CodeGuard
  was already installed.
* F-0141 — supplying a TLS CA file left a prior skip-verify flag enabled.
* F-0001 — the version probe ignored ``DEFENSECLAW_GATEWAY_BIN``.
* F-0442 — a pre-existing loose-permission dotenv was not tightened
  before secrets were written into it.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys
import urllib.error
import urllib.request
from email.message import Message
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import __version__, codeguard_skill, migration_state
from defenseclaw import logger as logger_mod
from defenseclaw.commands import cmd_version
from defenseclaw.config import _coerce_bool, load
from defenseclaw.db import Store
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.logger import Logger
from defenseclaw.migrations import run_migrations
from defenseclaw.observability.writer import apply_preset

from tests.permissions import assert_owner_only_file

# ---------------------------------------------------------------------------
# F-0022 / F-0023 / F-0024 — robust TLS boolean coercion
# ---------------------------------------------------------------------------


def test_coerce_bool_parses_quoted_and_typed_scalars():
    # Real bools pass through.
    assert _coerce_bool(True) is True
    assert _coerce_bool(False) is False
    # The security-critical case: a quoted "false" is NOT truthy.
    assert _coerce_bool("false") is False
    assert _coerce_bool("False") is False
    assert _coerce_bool("FALSE") is False
    assert _coerce_bool("0") is False
    assert _coerce_bool("no") is False
    assert _coerce_bool("off") is False
    assert _coerce_bool("") is False
    # Truthy tokens.
    assert _coerce_bool("true") is True
    assert _coerce_bool("True") is True
    assert _coerce_bool("1") is True
    assert _coerce_bool("yes") is True
    assert _coerce_bool("on") is True
    # Numerics.
    assert _coerce_bool(0) is False
    assert _coerce_bool(1) is True
    # Unknown/None fall back to the supplied default.
    assert _coerce_bool("maybe") is False
    assert _coerce_bool("maybe", default=True) is True
    assert _coerce_bool(None, default=True) is True


def _resolved_llm_skip_verify(home: Path, monkeypatch, config_yaml, overlay=None):
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text(config_yaml, encoding="utf-8")
    if overlay is not None:
        (home / "custom-providers.json").write_text(
            json.dumps(overlay), encoding="utf-8"
        )
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    tls = load().resolve_llm("").tls
    return None if tls is None else tls.insecure_skip_verify


def test_f0022_llm_tls_quoted_false_keeps_verification(tmp_path, monkeypatch):
    # Control: a YAML boolean false → verification on.
    assert (
        _resolved_llm_skip_verify(
            tmp_path / "control",
            monkeypatch,
            "llm:\n  base_url: https://llm.example.test/v1\n"
            "  tls:\n    insecure_skip_verify: false\n",
        )
        is False
    )
    # The bug: a quoted "false" must ALSO resolve to False (verify on),
    # not collapse to True via bool("false").
    assert (
        _resolved_llm_skip_verify(
            tmp_path / "quoted",
            monkeypatch,
            "llm:\n  base_url: https://llm.example.test/v1\n"
            '  tls:\n    insecure_skip_verify: "false"\n',
        )
        is False
    )
    # Custom-provider overlay path must coerce the same way.
    assert (
        _resolved_llm_skip_verify(
            tmp_path / "overlay",
            monkeypatch,
            "llm:\n  instance_name: acme\n",
            overlay={
                "providers": [
                    {
                        "name": "acme",
                        "base_provider_type": "openai",
                        "base_url": "https://llm.example.test/v1",
                        "tls": {"insecure_skip_verify": "false"},
                    }
                ]
            },
        )
        is False
    )
    # A genuine opt-in still disables verification.
    assert (
        _resolved_llm_skip_verify(
            tmp_path / "optin",
            monkeypatch,
            "llm:\n  base_url: https://llm.example.test/v1\n"
            '  tls:\n    insecure_skip_verify: "true"\n',
        )
        is True
    )


def test_f0023_audit_sink_hec_quoted_false_keeps_verification(tmp_path, monkeypatch):
    home = tmp_path / "f0023"
    home.mkdir()
    (home / "config.yaml").write_text(
        "audit_sinks:\n"
        "  - name: splunk-prod\n"
        "    kind: splunk_hec\n"
        "    enabled: true\n"
        "    splunk_hec:\n"
        "      endpoint: https://splunk.example.test:8088/services/collector/event\n"
        "      token_env: DEFENSECLAW_SPLUNK_HEC_TOKEN\n"
        '      insecure_skip_verify: "false"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    cfg = load()
    # Quoted "false" mirrors to a real False and leaves verification ON.
    assert cfg.splunk.insecure_skip_verify is False
    assert cfg.splunk.tls_verify_enabled() is True


def test_f0024_legacy_splunk_quoted_false_keeps_verification(tmp_path, monkeypatch):
    home = tmp_path / "f0024"
    home.mkdir()
    (home / "config.yaml").write_text(
        "splunk:\n"
        "  enabled: true\n"
        "  hec_endpoint: https://splunk.example.test:8088/services/collector/event\n"
        "  hec_token_env: F0024_SPLUNK_HEC_TOKEN\n"
        '  insecure_skip_verify: "false"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.setenv("F0024_SPLUNK_HEC_TOKEN", "secret-token")
    cfg = load()
    assert cfg.splunk.insecure_skip_verify is False
    assert cfg.splunk.tls_verify_enabled() is True


# ---------------------------------------------------------------------------
# F-0808 — Splunk HEC forwarder must not follow redirects
# ---------------------------------------------------------------------------


class _MemResponse:
    """Minimal in-memory urllib response (mirrors the F-0808 PoC)."""

    def __init__(self, url, status, reason, headers=None, body=b""):
        self.url = url
        self.status = status
        self.code = status
        self.msg = reason
        self._body = BytesIO(body)
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def info(self):
        return self.headers

    def geturl(self):
        return self.url

    def getcode(self):
        return self.status

    def read(self, *args):
        return self._body.read(*args)

    def close(self):
        self._body.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


class _RecordingTransport(urllib.request.BaseHandler):
    """Records every hop and 302s the first one to a foreign origin."""

    handler_order = 100

    def __init__(self, configured_origin, redirect_url):
        self.configured_origin = configured_origin.rstrip("/")
        self.redirect_url = redirect_url
        self.first_hop = []
        self.redirected_hop = []

    def http_open(self, req):
        record = {
            "url": req.full_url,
            "authorization": req.headers.get("Authorization", ""),
        }
        if req.full_url.startswith(self.configured_origin):
            self.first_hop.append(record)
            return _MemResponse(
                req.full_url, 302, "Found", headers={"Location": self.redirect_url}
            )
        self.redirected_hop.append(record)
        return _MemResponse(req.full_url, 200, "OK", body=b"ok")


def test_f0808_no_redirect_handler_refuses_and_keeps_token_on_origin():
    origin = "http://configured-hec.invalid:18088"
    transport = _RecordingTransport(origin, "http://attacker.invalid:19099/capture")
    opener = urllib.request.build_opener(logger_mod._NoRedirectHandler(), transport)
    req = urllib.request.Request(
        f"{origin}/services/collector/event",
        data=b"{}",
        method="POST",
        headers={"Authorization": "Splunk top-secret"},
    )
    # The redirect is refused (surfaced as HTTPError) instead of followed.
    with pytest.raises(urllib.error.HTTPError):
        opener.open(req, timeout=5)
    # The token reached the configured origin exactly once...
    assert [h["authorization"] for h in transport.first_hop] == ["Splunk top-secret"]
    # ...and was never replayed onto the redirect target.
    assert transport.redirected_hop == []


def test_f0808_build_hec_opener_wires_in_no_redirect_handler():
    opener = logger_mod._build_hec_opener(None)
    assert any(
        isinstance(h, logger_mod._NoRedirectHandler) for h in opener.handlers
    )


class _FakeSplunkCfg:
    enabled = True
    hec_endpoint = "http://configured-hec.invalid:18088"
    index = "defenseclaw"
    source = "defenseclaw"
    sourcetype = "_json"

    def tls_verify_enabled(self):
        return True

    def resolved_hec_token(self):
        return "f0808-secret-token"


def test_f0808_forward_event_does_not_leak_token_across_redirect(tmp_path):
    origin = "http://configured-hec.invalid:18088"
    transport = _RecordingTransport(origin, "http://attacker.invalid:19099/capture")

    def fake_opener(ctx):
        # Exercise the REAL no-redirect handler through the forwarder.
        return urllib.request.build_opener(
            logger_mod._NoRedirectHandler(), transport
        )

    store = Store(str(tmp_path / "audit.db"))
    store.init()
    try:
        with patch("defenseclaw.logger._build_hec_opener", fake_opener):
            logger = Logger(store, _FakeSplunkCfg())
            logger.log_action("f0808", "redirected-hec", "redirect leak check")
    finally:
        store.close()

    assert [h["authorization"] for h in transport.first_hop] == [
        "Splunk f0808-secret-token"
    ]
    # The attacker origin never saw the bearer token.
    assert transport.redirected_hop == []


# ---------------------------------------------------------------------------
# F-0082 — block precedence during legacy list migration
# ---------------------------------------------------------------------------


def test_f0082_block_wins_over_allow_during_migration(tmp_path):
    db_path = str(tmp_path / "legacy.db")
    db = sqlite3.connect(db_path)
    db.executescript(
        """
        CREATE TABLE block_list (
            id TEXT PRIMARY KEY, target_type TEXT, target_name TEXT,
            reason TEXT, created_at TEXT
        );
        CREATE TABLE allow_list (
            id TEXT PRIMARY KEY, target_type TEXT, target_name TEXT,
            reason TEXT, created_at TEXT
        );
        INSERT INTO block_list VALUES
            ('block-row', 'skill', 'evil', 'operator blocked first',
             '2026-01-01T00:00:00Z');
        INSERT INTO allow_list VALUES
            ('allow-row', 'skill', 'evil', 'stale allow row',
             '2026-01-02T00:00:00Z');
        """
    )
    db.commit()
    db.close()

    store = Store(db_path)
    store.init()
    try:
        pe = PolicyEngine(store)
        row = store.db.execute(
            "SELECT actions_json FROM actions "
            "WHERE target_type = 'skill' AND target_name = 'evil'"
        ).fetchone()
        # The surviving row is the BLOCK, not the stale allow.
        assert row is not None
        assert json.loads(row[0]) == {"install": "block"}
        assert pe.is_blocked("skill", "evil") is True
        assert pe.is_allowed("skill", "evil") is False
    finally:
        store.close()


# ---------------------------------------------------------------------------
# F-0083 — audit DB must be created owner-only (0600)
# ---------------------------------------------------------------------------


def test_f0083_fresh_audit_db_is_owner_only(tmp_path):
    root = tmp_path / "audit_root"
    root.mkdir()
    os.chmod(root, 0o755)
    db_path = root / "audit.db"

    old_umask = os.umask(0o022)
    try:
        store = Store(str(db_path))
        store.init()
        store.close()
    finally:
        os.umask(old_umask)

    assert_owner_only_file(db_path)
    if os.name != "nt":
        parent_mode = stat.S_IMODE(os.stat(root).st_mode)
        assert not (parent_mode & stat.S_IRWXO), oct(parent_mode)


def test_f0083_existing_loose_db_is_tightened_without_data_loss(tmp_path):
    db_path = str(tmp_path / "existing.db")
    store = Store(db_path)
    store.init()
    store.close()
    # Simulate a pre-existing DB left world/group-readable.
    os.chmod(db_path, 0o644)

    store2 = Store(db_path)
    store2.init()
    try:
        # Re-opening tightens perms back to owner-only...
        assert_owner_only_file(db_path)
        # ...and the DB is still usable (init is idempotent).
        store2.db.execute("SELECT 1").fetchone()
    finally:
        store2.close()


# ---------------------------------------------------------------------------
# F-0081 — never overwrite a newer-schema migration cursor
# ---------------------------------------------------------------------------


def test_f0081_future_schema_cursor_is_preserved(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    openclaw_home = tmp_path / "oc"
    openclaw_home.mkdir()

    cursor_path = migration_state.state_path(str(data_dir))
    original = {
        "schema": migration_state.CURRENT_SCHEMA_VERSION + 1,
        "package_version": "9.9.9",
        "applied": ["9.9.9"],
        "applied_at": {"9.9.9": "future-build"},
        "future_field": {"keep": True},
    }
    with open(cursor_path, "w") as f:
        json.dump(original, f, sort_keys=True)
    config_path = data_dir / "config.yaml"
    legacy_config = (
        "config_version: 6\n"
        "otel:\n"
        "  enabled: true\n"
        "  endpoint: 127.0.0.1:4317\n"
    )
    config_path.write_text(legacy_config)

    # Detection helpers tell a newer cursor apart from a missing one.
    assert (
        migration_state.detect_schema(str(data_dir))
        == migration_state.CURRENT_SCHEMA_VERSION + 1
    )
    assert migration_state.is_future_schema(str(data_dir)) is True
    # load() still collapses it to None (its documented contract)...
    assert migration_state.load(str(data_dir)) is None

    # ...but run_migrations refuses rather than bootstrapping over it.
    with pytest.raises(migration_state.FutureSchemaError):
        run_migrations("9.9.9", "9.9.9", str(openclaw_home), str(data_dir))

    # The newer cursor is byte-for-byte intact.
    with open(cursor_path) as f:
        assert json.load(f) == original
    # Refusal happens before any configuration-schema write as well. An older
    # upgrader must not partially mutate a host owned by a newer cursor.
    assert config_path.read_text() == legacy_config
    assert not (data_dir / "config.yaml.pre-observability-migration.bak").exists()


def test_f0081_missing_cursor_still_bootstraps(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    openclaw_home = tmp_path / "oc"
    openclaw_home.mkdir()
    assert migration_state.is_future_schema(str(data_dir)) is False
    # No cursor → safe to bootstrap, no exception.
    run_migrations("9.9.9", "9.9.9", str(openclaw_home), str(data_dir))
    assert os.path.exists(migration_state.state_path(str(data_dir)))


# ---------------------------------------------------------------------------
# F-0681 — retry an unapplied lower-version migration on a later upgrade
# ---------------------------------------------------------------------------


def _read_cursor(data_dir: str) -> dict:
    with open(os.path.join(data_dir, ".migration_state.json")) as f:
        return json.load(f)


def test_f0681_unapplied_lower_migration_is_retried(tmp_path):
    attempts = {"0.3.0": 0, "0.4.0": 0, "0.5.0": 0}

    def flaky_repair(_ctx):
        attempts["0.3.0"] += 1
        if attempts["0.3.0"] == 1:
            raise RuntimeError("transient repair failure")

    def stable_040(_ctx):
        attempts["0.4.0"] += 1

    def stable_050(_ctx):
        attempts["0.5.0"] += 1

    migrations = [
        ("0.3.0", "flaky repair/security migration", flaky_repair),
        ("0.4.0", "later successful migration", stable_040),
        ("0.5.0", "future normal upgrade migration", stable_050),
    ]

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    openclaw_home = tmp_path / "oc"
    openclaw_home.mkdir()

    with patch("defenseclaw.migrations.MIGRATIONS", migrations):
        run_migrations("0.2.0", "0.4.0", str(openclaw_home), str(data_dir))
        after_first = _read_cursor(str(data_dir))
        run_migrations("0.4.0", "0.5.0", str(openclaw_home), str(data_dir))
        after_second = _read_cursor(str(data_dir))

    # 0.3.0 failed on the first upgrade and was retried (and succeeded)
    # on the later one, instead of being skipped by version comparison.
    assert attempts == {"0.3.0": 2, "0.4.0": 1, "0.5.0": 1}
    assert after_first["applied"] == ["0.4.0"]
    assert sorted(after_second["applied"]) == ["0.3.0", "0.4.0", "0.5.0"]


# ---------------------------------------------------------------------------
# F-0281 — CodeGuard install must verify asset provenance, not markers
# ---------------------------------------------------------------------------


def _codeguard_cfg(home: Path):
    return SimpleNamespace(
        active_connector=lambda: "codex",
        data_dir=str(home / ".defenseclaw"),
        claw=SimpleNamespace(
            home_dir=str(home / ".openclaw"),
            config_file=str(home / ".openclaw" / "openclaw.json"),
        ),
    )


def test_f0281_marker_only_spoof_is_not_trusted(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))

    skill_dir = home / ".codex" / "skills" / "codeguard"
    skill_dir.mkdir(parents=True)
    # Marker substrings the old heuristic trusted as "installed".
    (skill_dir / "SKILL.md").write_text(
        "malicious replacement\nCodeGuard\nCG-CRED-001\n", encoding="utf-8"
    )
    (skill_dir / "main.py").write_text(
        "print('attacker controlled helper')\n", encoding="utf-8"
    )

    cfg = _codeguard_cfg(home)
    status = codeguard_skill.codeguard_status(cfg, connector="codex", target="skill")
    # Provenance mismatch → conflict, NOT a trusted "installed".
    assert status.status == "conflict"

    result = codeguard_skill.install_codeguard_asset(
        cfg, connector="codex", target="skill", replace=False
    )
    # The genuine install is no longer silently skipped as already-present.
    assert result.startswith("conflict at")
    assert "already installed" not in result


def test_f0281_genuine_install_is_recognized(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    cfg = _codeguard_cfg(home)

    first = codeguard_skill.install_codeguard_asset(
        cfg, connector="codex", target="skill", replace=False
    )
    assert first.startswith("installed to")

    # A byte-identical canonical install is recognized via its content
    # signature, so a second install is a clean no-op.
    status = codeguard_skill.codeguard_status(cfg, connector="codex", target="skill")
    assert status.status == "installed"
    second = codeguard_skill.install_codeguard_asset(
        cfg, connector="codex", target="skill", replace=False
    )
    assert second.startswith("already installed at")


# ---------------------------------------------------------------------------
# F-0141 — CA-file setup clears prior LLM TLS skip-verify
# ---------------------------------------------------------------------------

_POC0141_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAdummy\n"
    "-----END CERTIFICATE-----\n"
)


def test_f0141_ca_file_clears_prior_skip_verify(tmp_path):
    """Later --tls-ca-cert-file must disable a persisted skip-verify flag."""
    from defenseclaw.commands.cmd_setup import _apply_llm_provider_typed_flags
    from defenseclaw.config import LLMConfig, LLMTLSConfig, _merge_tls

    ca_path = tmp_path / "root-ca.pem"
    ca_path.write_text(_POC0141_PEM, encoding="utf-8")

    llm = LLMConfig(tls=LLMTLSConfig(insecure_skip_verify=True))
    _apply_llm_provider_typed_flags(llm, tls_ca_cert_file=str(ca_path))
    assert llm.tls is not None
    assert llm.tls.ca_cert_pem
    assert llm.tls.insecure_skip_verify is False

    merged = _merge_tls(
        {"ca_cert_pem": _POC0141_PEM, "insecure_skip_verify": True}
    )
    assert merged is not None
    assert merged.insecure_skip_verify is False


# ---------------------------------------------------------------------------
# F-0001 — version probe honours DEFENSECLAW_GATEWAY_BIN
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX shell gateway probe; native Windows executable probing has dedicated coverage"
)
def test_f0001_version_probe_uses_configured_gateway(tmp_path, monkeypatch):
    fake_version = "9.9.9" if __version__ != "9.9.9" else "0.0.1"
    fake_gateway = tmp_path / "custom-defenseclaw-gateway"
    fake_gateway.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' 'defenseclaw-gateway version {fake_version} "
        "(commit=test, built=test)'\n",
        encoding="utf-8",
    )
    fake_gateway.chmod(fake_gateway.stat().st_mode | stat.S_IXUSR)

    empty_path = tmp_path / "empty"
    empty_path.mkdir()
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_BIN", str(fake_gateway))
    monkeypatch.setenv("PATH", str(empty_path))

    component = cmd_version._gateway_component()
    # Resolved through resolve_gateway_binary(), so the configured binary
    # is interrogated rather than reported "(not installed)".
    assert component.status == "ok"
    assert component.version == fake_version
    assert component.origin == str(fake_gateway)


# ---------------------------------------------------------------------------
# F-0442 — dotenv writes must tighten pre-existing loose permissions
# ---------------------------------------------------------------------------


def test_f0442_existing_loose_dotenv_is_tightened(tmp_path):
    data_dir = str(tmp_path)
    with open(os.path.join(data_dir, "config.yaml"), "w") as f:
        f.write("claw:\n  mode: openclaw\n")

    dotenv_path = os.path.join(data_dir, ".env")
    with open(dotenv_path, "w") as f:
        f.write("OLD=value\n")
    os.chmod(dotenv_path, 0o644)

    secret = "dd-secret-from-f0442"
    apply_preset("datadog", {"site": "us5"}, data_dir, secret_value=secret)

    content = Path(dotenv_path).read_text(encoding="utf-8")
    # The pre-existing world/group-readable dotenv is tightened to 0600...
    assert_owner_only_file(dotenv_path)
    # ...and still carries the freshly written secret.
    assert f"DD_API_KEY={secret}" in content


def test_f0442_fresh_dotenv_is_owner_only(tmp_path):
    data_dir = str(tmp_path)
    with open(os.path.join(data_dir, "config.yaml"), "w") as f:
        f.write("claw:\n  mode: openclaw\n")

    secret = "dd-secret-fresh"
    apply_preset("datadog", {"site": "us5"}, data_dir, secret_value=secret)

    dotenv_path = os.path.join(data_dir, ".env")
    assert_owner_only_file(dotenv_path)
    assert f"DD_API_KEY={secret}" in Path(dotenv_path).read_text(encoding="utf-8")
