# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0847: an adopted gateway token copy never shadows the token the operator saved."""

from __future__ import annotations

import os
from types import SimpleNamespace

import click
import pytest
from defenseclaw import config as config_module
from defenseclaw import credential_provenance, gateway_token_adoption
from defenseclaw.commands import cmd_doctor, cmd_setup
from defenseclaw.commands.cmd_setup import _save_adopted_gateway_token, _save_secret_to_dotenv
from defenseclaw.file_permissions import MAX_DOTENV_BYTES

# The line the Go gateway writes for the token "adopted"
# (internal/envvars/gateway_token_adoption_test.go asserts the same text).
GO_MARKER = "# defenseclaw: adopted gateway token sha256=5d4686f6ad6a5e224c3961e4d3ed3c65f192697ec734fa02b244e42df5900a84"
NAMES = ("DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    credential_provenance._reset_for_tests()
    for name in NAMES:
        monkeypatch.delenv(name, raising=False)
    yield
    for name in NAMES:
        os.environ.pop(name, None)
    credential_provenance._reset_for_tests()


def _resolve(tmp_path, body: str) -> str:
    (tmp_path / ".env").write_text(body)
    (tmp_path / ".env").chmod(0o600)
    config_module._load_dotenv_into_os(str(tmp_path))
    return config_module.GatewayConfig().resolved_token()


def test_marker_matches_the_go_gateway():
    assert gateway_token_adoption.marker_line("adopted") == GO_MARKER.encode()


@pytest.mark.parametrize(
    ("body", "want"),
    [
        (f"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=edited\n{GO_MARKER}\n", "edited"),
        (f"DEFENSECLAW_GATEWAY_TOKEN=\"edited\"\nOPENCLAW_GATEWAY_TOKEN=adopted\n{GO_MARKER}\n", "edited"),
        # Unedited adopted copies, no marker, or a marker for another value: the earlier spelling wins as before.
        (f"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=adopted\n{GO_MARKER}\n", "adopted"),
        ("DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=edited\n", "adopted"),
        (f"DEFENSECLAW_GATEWAY_TOKEN=one\nOPENCLAW_GATEWAY_TOKEN=two\n{GO_MARKER}\n", "one"),
        (f"OPENCLAW_GATEWAY_TOKEN=adopted\n{GO_MARKER}\n", "adopted"),
    ],
)
def test_resolved_token_prefers_the_value_the_operator_saved(tmp_path, body, want):
    assert _resolve(tmp_path, body) == want


def test_a_reload_drops_the_adopted_copy_an_earlier_load_injected(tmp_path):
    # The TUI loads .env once, then the operator edits one spelling and it loads again.
    assert _resolve(tmp_path, f"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=adopted\n{GO_MARKER}\n") == "adopted"
    assert _resolve(tmp_path, f"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=edited\n{GO_MARKER}\n") == "edited"
    assert "DEFENSECLAW_GATEWAY_TOKEN" not in os.environ


def test_a_shell_export_still_beats_the_file(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_TOKEN", "from-shell")
    body = f"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=edited\n{GO_MARKER}\n"
    assert _resolve(tmp_path, body) == "from-shell"


def test_setup_records_the_token_it_copied_and_a_later_edit_wins(tmp_path):
    (tmp_path / ".env").write_text("DEFENSECLAW_LLM_KEY=keep\nDEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=adopted\n")
    (tmp_path / ".env").chmod(0o600)
    _save_adopted_gateway_token(list(NAMES), "adopted", str(tmp_path))
    _save_adopted_gateway_token(list(NAMES), "adopted", str(tmp_path))
    body = (tmp_path / ".env").read_text()
    assert body.count(GO_MARKER) == 1
    assert "DEFENSECLAW_LLM_KEY=keep" in body
    edited = body.replace("OPENCLAW_GATEWAY_TOKEN=adopted", "OPENCLAW_GATEWAY_TOKEN=edited")
    for name in NAMES:  # the save also set this process environment; the next process starts without it
        os.environ.pop(name, None)
    assert _resolve(tmp_path, edited) == "edited"


@pytest.mark.parametrize("edited", NAMES)
def test_doctor_picks_the_token_the_runtime_resolves(tmp_path, edited):
    # Doctor authenticates with this answer; it must be the one the daemon starts with.
    values = {name: "adopted" for name in NAMES}
    values[edited] = "edited"
    body = "".join(f"{name}={values[name]}\n" for name in NAMES) + GO_MARKER + "\n"
    runtime = _resolve(tmp_path, body)
    cfg = SimpleNamespace(data_dir=str(tmp_path), gateway=config_module.GatewayConfig())
    assert cmd_doctor._daemon_effective_gateway_token(cfg)[0] == runtime == "edited"


def test_doctor_keeps_an_unedited_adopted_token(tmp_path):
    body = f"DEFENSECLAW_GATEWAY_TOKEN=adopted\nOPENCLAW_GATEWAY_TOKEN=adopted\n{GO_MARKER}\n"
    assert _resolve(tmp_path, body) == "adopted"
    cfg = SimpleNamespace(data_dir=str(tmp_path), gateway=config_module.GatewayConfig())
    token, name, _ = cmd_doctor._daemon_effective_gateway_token(cfg)
    assert (token, name) == ("adopted", "DEFENSECLAW_GATEWAY_TOKEN")


OLD_TOKEN = "old-token"
NEW_TOKEN = "new-token-one-byte-longer"
OLD_TOKENS = f"DEFENSECLAW_GATEWAY_TOKEN={OLD_TOKEN}\nOPENCLAW_GATEWAY_TOKEN={OLD_TOKEN}\n"


def _dotenv_whose_adoption_is(tmp_path, size: int, ending: bytes) -> bytes:
    """Write a .env that the NEW_TOKEN adoption turns into exactly *size* bytes; return it."""
    # Longer token under both spellings, the marker line, and the final newline a file without one gains.
    gain = 2 * (len(NEW_TOKEN) - len(OLD_TOKEN)) + len(gateway_token_adoption.marker_line(NEW_TOKEN)) + 1
    if not ending:
        gain += 1
    padding = b"#" + b"x" * (size - gain - len(OLD_TOKENS) - 1 - len(ending)) + ending
    original = OLD_TOKENS.encode() + padding
    path = tmp_path / ".env"
    path.write_bytes(original)
    path.chmod(0o600)
    return original


def _resolved_after_load(tmp_path) -> str:
    config_module._load_dotenv_into_os(str(tmp_path))
    return config_module.GatewayConfig().resolved_token()


@pytest.mark.parametrize("ending", [b"\n", b""], ids=["final-newline", "no-final-newline"])
def test_adoption_that_lands_exactly_on_the_limit_is_published_and_readable(tmp_path, ending):
    _dotenv_whose_adoption_is(tmp_path, MAX_DOTENV_BYTES, ending)
    _save_adopted_gateway_token(list(NAMES), NEW_TOKEN, str(tmp_path))
    assert (tmp_path / ".env").stat().st_size == MAX_DOTENV_BYTES
    assert _resolved_after_load(tmp_path) == NEW_TOKEN


@pytest.mark.parametrize("ending", [b"\n", b""], ids=["final-newline", "no-final-newline"])
def test_adoption_one_byte_over_the_limit_changes_nothing_and_names_the_cause(tmp_path, ending):
    original = _dotenv_whose_adoption_is(tmp_path, MAX_DOTENV_BYTES + 1, ending)
    with pytest.raises(click.ClickException, match=r"over the \d+-byte limit"):
        _save_adopted_gateway_token(list(NAMES), NEW_TOKEN, str(tmp_path))
    assert (tmp_path / ".env").read_bytes() == original
    assert _resolved_after_load(tmp_path) == OLD_TOKEN
    assert "DEFENSECLAW_GATEWAY_TOKEN" not in os.environ or os.environ["DEFENSECLAW_GATEWAY_TOKEN"] == OLD_TOKEN


@pytest.mark.parametrize("excess", [0, 1], ids=["exact-limit", "one-byte-over"])
def test_setup_adoption_checks_the_complete_dotenv_before_gateway_stop(tmp_path, monkeypatch, excess):
    original = _dotenv_whose_adoption_is(tmp_path, MAX_DOTENV_BYTES + excess, b"\n")
    path = tmp_path / ".env"
    before = path.stat()
    events: list[str] = []
    app = SimpleNamespace(
        cfg=SimpleNamespace(
            data_dir=str(tmp_path),
            claw=SimpleNamespace(config_file="unused"),
            gateway=SimpleNamespace(resolved_token=lambda: OLD_TOKEN, token_env=""),
        ),
        logger=None,
    )
    monkeypatch.setattr(cmd_setup, "_detect_openclaw_gateway_token", lambda *_args, **_kwargs: NEW_TOKEN)
    monkeypatch.setattr(cmd_setup, "_stop_gateway_before_token_swap", lambda _dir: events.append("stop") or True)
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", lambda _dir: events.append("restart"))

    if excess:
        with pytest.raises(click.ClickException, match=r"over the \d+-byte limit"):
            cmd_setup._adopt_openclaw_gateway_token(app, restart=True)
        after = path.stat()
        assert events == []
        assert path.read_bytes() == original
        assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    else:
        cmd_setup._adopt_openclaw_gateway_token(app, restart=True)
        assert events == ["stop", "restart"]
        assert path.stat().st_size == MAX_DOTENV_BYTES


def test_a_single_secret_save_one_byte_over_the_limit_changes_nothing(tmp_path):
    key, value = "DEFENSECLAW_LLM_KEY", "sk-test"
    line = f"{key}={value}\n".encode()
    original = b"#" + b"x" * (MAX_DOTENV_BYTES - len(line) - 2) + b"\n"
    (tmp_path / ".env").write_bytes(original)
    (tmp_path / ".env").chmod(0o600)
    _save_secret_to_dotenv(key, value, str(tmp_path))
    assert (tmp_path / ".env").stat().st_size == MAX_DOTENV_BYTES
    (tmp_path / ".env").write_bytes(original)
    with pytest.raises(click.ClickException, match="over the"):
        _save_secret_to_dotenv(key, value + "x", str(tmp_path))
    assert (tmp_path / ".env").read_bytes() == original


def test_the_two_token_save_is_one_publish_and_an_interrupted_one_leaves_the_file_as_it_was(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text("DEFENSECLAW_LLM_KEY=keep\n" + OLD_TOKENS)
    path.chmod(0o600)
    original = path.read_bytes()
    real = cmd_setup.atomic_write_private_bytes

    def interrupted(*_args, **_kwargs):
        raise OSError("interrupted")

    monkeypatch.setattr(cmd_setup, "atomic_write_private_bytes", interrupted)
    with pytest.raises(OSError, match="interrupted"):
        _save_adopted_gateway_token(list(NAMES), NEW_TOKEN, str(tmp_path))
    assert path.read_bytes() == original
    assert os.environ.get("DEFENSECLAW_GATEWAY_TOKEN") is None

    published: list[bytes] = []

    def counting(target, body, *args, **kwargs):
        published.append(body)
        return real(target, body, *args, **kwargs)

    monkeypatch.setattr(cmd_setup, "atomic_write_private_bytes", counting)
    _save_adopted_gateway_token(list(NAMES), NEW_TOKEN, str(tmp_path))
    assert len(published) == 1
    # The file keeps the line ending it had (write_text gives CRLF on Windows),
    # so the lines are compared without it.
    lines = published[0].decode().splitlines()
    assert lines.count(f"DEFENSECLAW_GATEWAY_TOKEN={NEW_TOKEN}") == 1
    assert lines.count(f"OPENCLAW_GATEWAY_TOKEN={NEW_TOKEN}") == 1
    assert "DEFENSECLAW_LLM_KEY=keep" in lines
    assert _resolved_after_load(tmp_path) == NEW_TOKEN


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"], ids=["lf", "crlf"])
def test_the_token_save_writes_one_line_ending_whatever_the_os(tmp_path, ending):
    path = tmp_path / ".env"
    path.write_bytes(ending.join([b"DEFENSECLAW_LLM_KEY=keep", f"DEFENSECLAW_GATEWAY_TOKEN={OLD_TOKEN}".encode(), b""]))
    path.chmod(0o600)
    _save_adopted_gateway_token(list(NAMES), NEW_TOKEN, str(tmp_path))
    body = path.read_bytes()
    assert body.endswith(ending)
    assert body.count(b"\n") == body.count(ending)
    lines = body.decode().split(ending.decode())[:-1]
    assert lines.count(f"DEFENSECLAW_GATEWAY_TOKEN={NEW_TOKEN}") == 1
    assert lines.count(f"OPENCLAW_GATEWAY_TOKEN={NEW_TOKEN}") == 1
    assert _resolved_after_load(tmp_path) == NEW_TOKEN


# The earlier Go writer left a CRLF .env with LF on the lines it replaced or added.
MIXED_ENV = (
    b"DEFENSECLAW_LLM_KEY=keep\r\n"
    + f"DEFENSECLAW_GATEWAY_TOKEN={OLD_TOKEN}\n".encode()
    + b"OTHER=1\r\nLAST=2\n"
)


def _one_ending(body: bytes, ending: bytes) -> bool:
    # A replace-in-place keeps a missing final newline; every line break there is is the one ending.
    return body.count(b"\n") == body.count(ending)


@pytest.mark.parametrize("final_newline", [True, False], ids=["final-newline", "no-final-newline"])
@pytest.mark.parametrize("writer", ["adoption", "secret-save", "rotation"])
def test_every_python_writer_converges_a_mixed_dotenv_to_one_ending(tmp_path, writer, final_newline):
    path = tmp_path / ".env"
    seed = MIXED_ENV if final_newline else MIXED_ENV.rstrip(b"\n")
    path.write_bytes(seed)
    path.chmod(0o600)
    if writer == "adoption":
        _save_adopted_gateway_token(list(NAMES), NEW_TOKEN, str(tmp_path))
    elif writer == "secret-save":
        _save_secret_to_dotenv("DEFENSECLAW_LLM_KEY", "changed", str(tmp_path))
    else:
        cmd_setup._rotate_token_atomic_write(str(path), NEW_TOKEN)
    body = path.read_bytes()
    assert _one_ending(body, b"\r\n")
    if final_newline:
        assert body.endswith(b"\r\n")
    lines = body.decode().split("\r\n")
    assert "OTHER=1" in lines
    assert "LAST=2" in lines
    if writer == "secret-save":
        assert "DEFENSECLAW_LLM_KEY=changed" in lines
    else:
        assert f"DEFENSECLAW_GATEWAY_TOKEN={NEW_TOKEN}" in lines
        assert _resolved_after_load(tmp_path) == NEW_TOKEN


def test_a_dotenv_without_crlf_stays_lf_after_every_python_writer(tmp_path):
    path = tmp_path / ".env"
    path.write_bytes(MIXED_ENV.replace(b"\r\n", b"\n"))
    path.chmod(0o600)
    _save_adopted_gateway_token(list(NAMES), NEW_TOKEN, str(tmp_path))
    _save_secret_to_dotenv("DEFENSECLAW_LLM_KEY", "changed", str(tmp_path))
    cmd_setup._rotate_token_atomic_write(str(path), NEW_TOKEN)
    assert b"\r" not in path.read_bytes()
