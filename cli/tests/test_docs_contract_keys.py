# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The keys page says what a running gateway does after ``keys set`` of its token."""

import os
import re
from pathlib import Path
from types import SimpleNamespace

from click.testing import CliRunner
from defenseclaw import ux
from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_keys import keys_cmd
from defenseclaw.config import Config, GatewayConfig
from defenseclaw.context import AppContext
from defenseclaw.logger import _running_gateway_token

DOCS = Path(__file__).resolve().parents[2] / "docs-site/content/docs"


def _gateway_token_bullet():
    text = (DOCS / "reference/configuration/keys.mdx").read_text(encoding="utf-8")
    start = text.index("- `keys set DEFENSECLAW_GATEWAY_TOKEN`")
    return " ".join(re.split(r"\n(?:- |\s*\n)", text[start + 2 :], maxsplit=1)[0].split())


def test_keys_set_gateway_token_page_matches_what_the_cli_sends(tmp_path, monkeypatch, capsys):
    # GAP-0583: the page said a running gateway keeps accepting CLI commands
    # across saved changes; doctor and the TUI got HTTP 401 until a restart.
    monkeypatch.delenv("OPENCLAW_GATEWAY_TOKEN", raising=False)
    (tmp_path / ".env").write_text("DEFENSECLAW_GATEWAY_TOKEN=loaded-token\n", encoding="utf-8")
    os.chmod(tmp_path / ".env", 0o600)
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_TOKEN", "loaded-token")
    (tmp_path / "gateway.pid").write_text(str(os.getpid()), encoding="utf-8")  # the running gateway
    app = AppContext()
    app.cfg = Config(data_dir=str(tmp_path), gateway=GatewayConfig())

    result = CliRunner().invoke(keys_cmd, ["set", "DEFENSECLAW_GATEWAY_TOKEN", "--value", "saved-token"], obj=app)
    assert result.exit_code == 0, result.output
    capsys.readouterr()

    # CLI audit events keep the token the running gateway loaded.
    assert _running_gateway_token(str(tmp_path)) == "loaded-token"

    # Other CLI calls send the saved token; the running gateway accepts only
    # the one it loaded, so doctor's probe gets 401.
    sent = []

    def probe(_url, *, headers, **_kwargs):
        sent.append(headers["Authorization"])
        return (200, b"{}") if headers["Authorization"] == "Bearer loaded-token" else (401, b"")

    monkeypatch.setattr(
        cmd_doctor, "_trusted_gateway_listener", lambda _cfg: SimpleNamespace(trusted=True, pid=os.getpid(), detail="")
    )
    monkeypatch.setattr(cmd_doctor, "_http_probe", probe)
    monkeypatch.setattr(cmd_doctor, "_json_mode", False)
    r = cmd_doctor._DoctorResult()
    r.gateway_down = ""
    cmd_doctor._check_gateway_auth(Config(data_dir=str(tmp_path), gateway=GatewayConfig()), r)
    row = " ".join(capsys.readouterr().out.split())
    assert sent == ["Bearer saved-token"]

    bullet = _gateway_token_bullet()
    assert "keeps accepting" not in bullet
    assert "audit events still use that token" in bullet
    # Either a gateway restart or doctor --fix (which restarts it on a rejected
    # token, test_cmd_doctor_gateway_auth_fix.py) clears the 401.
    assert "HTTP 401 until the gateway restarts" in bullet
    assert "run `defenseclaw-gateway restart`, or run `defenseclaw doctor --fix`" in bullet
    quoted = re.search(r"`defenseclaw doctor` reports `([^`]+)`", bullet)
    # The quote is the whole row, label and detail, as doctor prints it. A console
    # without UTF-8 shows the em dash as "-", so render the quote the same way.
    assert quoted and " ".join(ux.console_text(quoted.group(1)).split()) == row.strip(), (
        quoted and quoted.group(1),
        row,
    )


def test_no_page_says_a_running_gateway_keeps_accepting_the_cli_after_a_token_change():
    claim = re.compile(r"[^.]*\b(?:keeps? accepting|still accepts?)\b[^.]*\bCLI\b[^.]*\.")
    found = [
        f"{page.relative_to(DOCS)}: {m.group(0).strip()}"
        for page in sorted(DOCS.rglob("*.mdx"))
        for m in claim.finditer(" ".join(page.read_text(encoding="utf-8").split()))
        if "token" in m.group(0) or "saved change" in m.group(0)
    ]
    assert not found, found
