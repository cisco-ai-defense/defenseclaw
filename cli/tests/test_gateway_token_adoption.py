# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""R-TOK: the OpenClaw gateway token is never the DefenseClaw master token.

DefenseClaw 1.0.9 and earlier copied the token OpenClaw holds in openclaw.json
under both gateway-token names and marked the copy with a comment (GAP-0847).
From 1.0.10 OPENCLAW_GATEWAY_TOKEN is only the credential the gateway presents
to the OpenClaw WebSocket, and DEFENSECLAW_GATEWAY_TOKEN is a separate value.
"""

from __future__ import annotations

import os
import re
from types import SimpleNamespace

import click
import pytest
from defenseclaw import config as config_module
from defenseclaw import credential_provenance
from defenseclaw.commands import cmd_doctor, cmd_setup
from defenseclaw.commands.cmd_setup import _ensure_master_gateway_token, _save_secret_to_dotenv
from defenseclaw.file_permissions import MAX_DOTENV_BYTES

# The comment line 1.0.9 wrote after an adoption: only a comment now.
OLD_MARKER = (
    "# defenseclaw: adopted gateway token sha256=5d4686f6ad6a5e224c3961e4d3ed3c65f192697ec734fa02b244e42df5900a84"
)
NAMES = ("DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN")
MINTED = re.compile(r"^[0-9a-f]{64}$")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    credential_provenance._reset_for_tests()
    for name in NAMES:
        monkeypatch.delenv(name, raising=False)
    yield
    for name in NAMES:
        os.environ.pop(name, None)
    credential_provenance._reset_for_tests()


def _seed(tmp_path, body: bytes):
    path = tmp_path / ".env"
    path.write_bytes(body)
    path.chmod(0o600)
    return path


def _resolve(tmp_path, body: str, **gateway) -> str:
    _seed(tmp_path, body.encode())
    config_module._load_dotenv_into_os(str(tmp_path))
    return config_module.GatewayConfig(**gateway).resolved_token()


def _dotenv(tmp_path) -> dict[str, str]:
    out = {}
    for line in (tmp_path / ".env").read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep and not key.startswith("#"):
            out[key] = value
    return out


@pytest.mark.parametrize(
    ("body", "want"),
    [
        ("OPENCLAW_GATEWAY_TOKEN=oc\n", ""),
        ("DEFENSECLAW_GATEWAY_TOKEN=master\nOPENCLAW_GATEWAY_TOKEN=oc\n", "master"),
        ("OPENCLAW_GATEWAY_TOKEN=oc\nDEFENSECLAW_GATEWAY_TOKEN=master\n", "master"),
        # A 1.0.9 adoption: the OpenClaw token under both names is no master.
        (f"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=adopted\n{OLD_MARKER}\n", ""),
        (f"DEFENSECLAW_GATEWAY_TOKEN=master\nOPENCLAW_GATEWAY_TOKEN=adopted\n{OLD_MARKER}\n", "master"),
    ],
)
def test_resolved_token_never_returns_the_openclaw_token(tmp_path, body, want):
    assert _resolve(tmp_path, body) == want


def test_a_token_env_naming_the_openclaw_credential_is_skipped(tmp_path):
    body = "DEFENSECLAW_GATEWAY_TOKEN=master\nOPENCLAW_GATEWAY_TOKEN=oc\n"
    assert _resolve(tmp_path, body, token_env="OPENCLAW_GATEWAY_TOKEN") == "master"
    os.environ.pop("DEFENSECLAW_GATEWAY_TOKEN")
    assert _resolve(tmp_path, "OPENCLAW_GATEWAY_TOKEN=oc\n", token_env="OPENCLAW_GATEWAY_TOKEN") == ""


def test_the_openclaw_name_compares_like_the_platform(monkeypatch):
    assert config_module.is_openclaw_gateway_token_env("OPENCLAW_GATEWAY_TOKEN")
    assert config_module.is_openclaw_gateway_token_env(" OPENCLAW_GATEWAY_TOKEN ")
    assert not config_module.is_openclaw_gateway_token_env("DEFENSECLAW_GATEWAY_TOKEN")
    if os.name != "nt":
        assert not config_module.is_openclaw_gateway_token_env("openclaw_gateway_token")
    monkeypatch.setattr(config_module.os, "name", "nt")
    assert config_module.is_openclaw_gateway_token_env("openclaw_gateway_token")


def test_a_literal_equal_to_the_openclaw_token_is_skipped(monkeypatch):
    monkeypatch.setenv("OPENCLAW_GATEWAY_TOKEN", "oc")
    assert config_module.GatewayConfig(token="oc").resolved_token() == ""
    assert config_module.GatewayConfig(token="literal").resolved_token() == "literal"
    monkeypatch.setenv("CUSTOM_TOKEN", "oc")
    assert config_module.GatewayConfig(token_env="CUSTOM_TOKEN").resolved_token() == ""


def test_a_shell_export_still_beats_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_TOKEN", "from-shell")
    assert _resolve(tmp_path, "DEFENSECLAW_GATEWAY_TOKEN=master\nOPENCLAW_GATEWAY_TOKEN=oc\n") == "from-shell"


def test_the_old_marker_no_longer_drops_the_openclaw_credential(tmp_path):
    body = f"DEFENSECLAW_GATEWAY_TOKEN=master\nOPENCLAW_GATEWAY_TOKEN=adopted\n{OLD_MARKER}\n"
    assert _resolve(tmp_path, body) == "master"
    assert os.environ["OPENCLAW_GATEWAY_TOKEN"] == "adopted"


def test_doctor_picks_the_token_the_runtime_resolves(tmp_path):
    runtime = _resolve(tmp_path, "DEFENSECLAW_GATEWAY_TOKEN=master\nOPENCLAW_GATEWAY_TOKEN=oc\n")
    cfg = SimpleNamespace(data_dir=str(tmp_path), gateway=config_module.GatewayConfig())
    assert cmd_doctor._daemon_effective_gateway_token(cfg)[:2] == (runtime, "DEFENSECLAW_GATEWAY_TOKEN")


def test_doctor_does_not_count_a_master_equal_to_the_openclaw_token(tmp_path):
    assert _resolve(tmp_path, "DEFENSECLAW_GATEWAY_TOKEN=oc\nOPENCLAW_GATEWAY_TOKEN=oc\n") == ""
    cfg = SimpleNamespace(data_dir=str(tmp_path), gateway=config_module.GatewayConfig())
    assert cmd_doctor._daemon_effective_gateway_token(cfg)[0] == ""
    assert "holds the OpenClaw gateway token" in cmd_doctor._missing_gateway_token_detail(cfg)


def _setup_openclaw(tmp_path, monkeypatch, detected: str) -> list:
    """Run the setup openclaw token step against tmp_path; return keep_running_gateway_token calls."""
    calls: list = []
    monkeypatch.setattr(cmd_setup, "_detect_openclaw_gateway_token", lambda *_a, **_k: detected)
    monkeypatch.setattr(cmd_setup, "keep_running_gateway_token", lambda *a: calls.append(a))
    config_module._load_dotenv_into_os(str(tmp_path))
    app = SimpleNamespace(
        cfg=SimpleNamespace(
            data_dir=str(tmp_path),
            claw=SimpleNamespace(config_file="unused"),
            gateway=config_module.GatewayConfig(),
        ),
        logger=None,
    )
    cmd_setup._adopt_openclaw_gateway_token(app)
    return calls


def test_setup_openclaw_saves_only_the_openclaw_credential(tmp_path, monkeypatch):
    _seed(tmp_path, b"DEFENSECLAW_LLM_KEY=keep\nDEFENSECLAW_GATEWAY_TOKEN=master\nOPENCLAW_GATEWAY_TOKEN=old-oc\n")
    calls = _setup_openclaw(tmp_path, monkeypatch, "new-oc")
    assert _dotenv(tmp_path) == {
        "DEFENSECLAW_LLM_KEY": "keep",
        "DEFENSECLAW_GATEWAY_TOKEN": "master",
        "OPENCLAW_GATEWAY_TOKEN": "new-oc",
    }
    assert calls == []  # the master did not change, so a running gateway keeps working
    assert config_module.GatewayConfig().resolved_token() == "master"


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"OPENCLAW_GATEWAY_TOKEN=oc\n",
        b"DEFENSECLAW_GATEWAY_TOKEN=oc\nOPENCLAW_GATEWAY_TOKEN=oc\n" + OLD_MARKER.encode() + b"\n",
    ],
    ids=["empty", "openclaw-only", "1.0.9-adoption"],
)
def test_setup_openclaw_gives_the_gateway_a_master_of_its_own(tmp_path, monkeypatch, body):
    _seed(tmp_path, body)
    _setup_openclaw(tmp_path, monkeypatch, "oc")
    saved = _dotenv(tmp_path)
    assert saved["OPENCLAW_GATEWAY_TOKEN"] == "oc"
    assert MINTED.match(saved["DEFENSECLAW_GATEWAY_TOKEN"])
    assert config_module.GatewayConfig().resolved_token() == saved["DEFENSECLAW_GATEWAY_TOKEN"]
    before = (tmp_path / ".env").read_bytes()
    _setup_openclaw(tmp_path, monkeypatch, "oc")
    assert (tmp_path / ".env").read_bytes() == before


def test_ensure_master_keeps_a_usable_one_and_an_exported_one(tmp_path, monkeypatch):
    _seed(tmp_path, b"DEFENSECLAW_GATEWAY_TOKEN=master\nOPENCLAW_GATEWAY_TOKEN=oc\n")
    assert not _ensure_master_gateway_token(str(tmp_path))
    assert _ensure_master_gateway_token(str(tmp_path), openclaw_token="master")  # openclaw.json holds it
    _seed(tmp_path, b"OPENCLAW_GATEWAY_TOKEN=oc\n")
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_TOKEN", "exported")
    assert not _ensure_master_gateway_token(str(tmp_path))
    assert "DEFENSECLAW_GATEWAY_TOKEN" not in _dotenv(tmp_path)


OLD_TOKEN = "old-token"
NEW_TOKEN = "new-token-one-byte-longer"
OLD_TOKENS = f"DEFENSECLAW_GATEWAY_TOKEN=master-token\nOPENCLAW_GATEWAY_TOKEN={OLD_TOKEN}\n"


def _dotenv_whose_adoption_is(tmp_path, size: int, ending: bytes) -> bytes:
    """Write a .env that the NEW_TOKEN adoption turns into exactly *size* bytes; return it."""
    # The longer OpenClaw token, and the final newline a file without one gains.
    gain = len(NEW_TOKEN) - len(OLD_TOKEN)
    if not ending:
        gain += 1
    padding = b"#" + b"x" * (size - gain - len(OLD_TOKENS) - 1 - len(ending)) + ending
    original = OLD_TOKENS.encode() + padding
    _seed(tmp_path, original)
    return original


@pytest.mark.parametrize("ending", [b"\n", b""], ids=["final-newline", "no-final-newline"])
def test_adoption_that_lands_exactly_on_the_limit_is_published(tmp_path, monkeypatch, ending):
    _dotenv_whose_adoption_is(tmp_path, MAX_DOTENV_BYTES, ending)
    _setup_openclaw(tmp_path, monkeypatch, NEW_TOKEN)
    assert (tmp_path / ".env").stat().st_size == MAX_DOTENV_BYTES
    assert _dotenv(tmp_path)["OPENCLAW_GATEWAY_TOKEN"] == NEW_TOKEN


@pytest.mark.parametrize("ending", [b"\n", b""], ids=["final-newline", "no-final-newline"])
def test_adoption_one_byte_over_the_limit_changes_nothing_and_names_the_cause(tmp_path, monkeypatch, ending):
    original = _dotenv_whose_adoption_is(tmp_path, MAX_DOTENV_BYTES + 1, ending)
    with pytest.raises(click.ClickException, match=r"over the \d+-byte limit"):
        _setup_openclaw(tmp_path, monkeypatch, NEW_TOKEN)
    assert (tmp_path / ".env").read_bytes() == original


def test_a_single_secret_save_one_byte_over_the_limit_changes_nothing(tmp_path):
    key, value = "DEFENSECLAW_LLM_KEY", "sk-test"
    line = f"{key}={value}\n".encode()
    original = b"#" + b"x" * (MAX_DOTENV_BYTES - len(line) - 2) + b"\n"
    _seed(tmp_path, original)
    _save_secret_to_dotenv(key, value, str(tmp_path))
    assert (tmp_path / ".env").stat().st_size == MAX_DOTENV_BYTES
    (tmp_path / ".env").write_bytes(original)
    with pytest.raises(click.ClickException, match="over the"):
        _save_secret_to_dotenv(key, value + "x", str(tmp_path))
    assert (tmp_path / ".env").read_bytes() == original


def test_the_mint_is_one_publish_and_an_interrupted_one_leaves_the_file_as_it_was(tmp_path, monkeypatch):
    path = _seed(
        tmp_path,
        f"DEFENSECLAW_LLM_KEY=keep\nDEFENSECLAW_GATEWAY_TOKEN={OLD_TOKEN}\nOPENCLAW_GATEWAY_TOKEN={OLD_TOKEN}\n".encode(),
    )
    original = path.read_bytes()
    real = cmd_setup.atomic_write_private_bytes

    def interrupted(*_args, **_kwargs):
        raise OSError("interrupted")

    monkeypatch.setattr(cmd_setup, "atomic_write_private_bytes", interrupted)
    with pytest.raises(OSError, match="interrupted"):
        _ensure_master_gateway_token(str(tmp_path))
    assert path.read_bytes() == original
    assert os.environ.get("DEFENSECLAW_GATEWAY_TOKEN") is None

    published: list[bytes] = []

    def counting(target, body, *args, **kwargs):
        published.append(body)
        return real(target, body, *args, **kwargs)

    monkeypatch.setattr(cmd_setup, "atomic_write_private_bytes", counting)
    assert _ensure_master_gateway_token(str(tmp_path))
    assert len(published) == 1
    saved = _dotenv(tmp_path)
    assert saved["OPENCLAW_GATEWAY_TOKEN"] == OLD_TOKEN and saved["DEFENSECLAW_LLM_KEY"] == "keep"
    assert MINTED.match(saved["DEFENSECLAW_GATEWAY_TOKEN"])
    assert os.environ["DEFENSECLAW_GATEWAY_TOKEN"] == saved["DEFENSECLAW_GATEWAY_TOKEN"]
