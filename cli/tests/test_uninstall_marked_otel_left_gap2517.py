"""GAP-2517: uninstall removes the agent OTel entries that carry DefenseClaw's markers and keeps the rest."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from defenseclaw import codex_toml
from defenseclaw.commands import cmd_uninstall

BEARER = "0123456789abcdef" * 4

MARKED_CODEX = f"""model = "gpt-5"

[otel]
environment = "windows"

[otel.exporter.otlp-http]
endpoint = 'http://127.0.0.1:19020/v1/logs'
protocol = 'json'

[otel.exporter.otlp-http.headers]
authorization = 'Bearer {BEARER}'
x-defenseclaw-client = 'codex-otel/1.0'
x-defenseclaw-source = 'codex'
"""

OPERATOR_CODEX = f"""[otel.exporter.otlp-http]
endpoint = 'http://127.0.0.1:4318/v1/logs'

[otel.exporter.otlp-http.headers]
authorization = 'Bearer {BEARER}'
x-tenant = 'logs'
"""

MARKED_HEADERS = (
    f"authorization=Bearer {BEARER},x-defenseclaw-client=claudecode-otel/1.0,x-defenseclaw-source=claudecode"
)


def _homes(tmp_path, monkeypatch, codex: str, claude_env: dict) -> tuple[str, str]:
    codex_home = tmp_path / "codex"
    claude_home = tmp_path / "claude"
    codex_home.mkdir()
    claude_home.mkdir()
    (codex_home / "config.toml").write_text(codex, encoding="utf-8")
    (claude_home / "settings.json").write_text(json.dumps({"env": claude_env}), encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude_home))
    return str(codex_home / "config.toml"), str(claude_home / "settings.json")


def _run_uninstall(monkeypatch) -> str:
    plan = SimpleNamespace(connectors=())
    monkeypatch.setattr(cmd_uninstall, "_dispatch_native_windows_uninstall", lambda **_: False)
    monkeypatch.setattr(cmd_uninstall, "_build_plan", lambda **_: plan)
    monkeypatch.setattr(cmd_uninstall, "_with_listed_sandboxes", lambda p, _stop: p)
    monkeypatch.setattr(cmd_uninstall, "_render_plan", lambda *_a, **_k: None)
    monkeypatch.setattr(cmd_uninstall, "_refuse_running_sandboxes", lambda _p: None)
    monkeypatch.setattr(cmd_uninstall, "_execute_plan", lambda _p: None)
    monkeypatch.setattr(cmd_uninstall, "_render_kept_and_next_steps", lambda _p: None)
    result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"])
    assert result.exit_code == 0, result.output
    return result.output


def test_uninstall_removes_the_marked_otel_entries_and_keeps_the_rest_gap2517(tmp_path, monkeypatch):
    codex_config, claude_settings = _homes(
        tmp_path,
        monkeypatch,
        MARKED_CODEX + "\n[otel.metrics_exporter.otlp-http]\nendpoint = \x27http://127.0.0.1:4318/v1/metrics\x27\n",
        {
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:19010",
            "OTEL_EXPORTER_OTLP_HEADERS": MARKED_HEADERS,
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "http://user:pw@127.0.0.1:19010/v1/logs",
            "OTEL_EXPORTER_OTLP_LOGS_HEADERS": MARKED_HEADERS,
            "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://127.0.0.1:4318/v1/metrics",
            "OTEL_EXPORTER_OTLP_METRICS_HEADERS": "x-tenant=metrics",
            "OTEL_LOGS_EXPORTER": "otlp",
        },
    )
    out = _run_uninstall(monkeypatch)
    flat = " ".join(out.split())
    codex = codex_toml.loads(open(codex_config, "rb").read())
    assert codex["model"] == "gpt-5"
    assert codex["otel"] == {
        "environment": "windows",
        "metrics_exporter": {"otlp-http": {"endpoint": "http://127.0.0.1:4318/v1/metrics"}},
    }
    env = json.loads(open(claude_settings, encoding="utf-8").read())["env"]
    # The unmarked metrics pair and the unrelated key are the user\x27s and stay.
    assert env == {
        "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://127.0.0.1:4318/v1/metrics",
        "OTEL_EXPORTER_OTLP_METRICS_HEADERS": "x-tenant=metrics",
        "OTEL_LOGS_EXPORTER": "otlp",
    }
    assert f"{codex_config}: removed otel.exporter" in flat
    assert (
        f"{claude_settings}: removed env OTEL_EXPORTER_OTLP_HEADERS, OTEL_EXPORTER_OTLP_LOGS_HEADERS, "
        "OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"
    ) in flat
    assert "127.0.0.1:19010" in flat and "127.0.0.1:19020" in flat
    assert "user:pw" not in out
    assert "METRICS" not in out
    assert BEARER not in out


def test_uninstall_keeps_an_operator_collector_byte_for_byte_gap2517(tmp_path, monkeypatch):
    codex_config, claude_settings = _homes(
        tmp_path,
        monkeypatch,
        OPERATOR_CODEX,
        {"OTEL_EXPORTER_OTLP_HEADERS": f"authorization=Bearer {BEARER},x-tenant=logs"},
    )
    before = (open(codex_config, "rb").read(), open(claude_settings, "rb").read())
    out = _run_uninstall(monkeypatch)
    assert (open(codex_config, "rb").read(), open(claude_settings, "rb").read()) == before
    assert "removed" not in out
    assert "x-defenseclaw-source" not in out


def test_uninstall_without_agent_configs_says_nothing_gap2517(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "no-codex"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "no-claude"))
    out = _run_uninstall(monkeypatch)
    assert "x-defenseclaw-source" not in out
    assert "removed" not in out


def test_uninstall_keeps_an_inline_codex_exporter_it_cannot_cut_and_names_the_step_gap2517(tmp_path, monkeypatch):
    inline = (
        "[otel]\nexporter = { otlp-http = { endpoint = \x27http://127.0.0.1:19020/v1/logs\x27, headers = { "
        f"authorization = \x27Bearer {BEARER}\x27, x-defenseclaw-client = \x27codex-otel/1.0\x27, "
        "x-defenseclaw-source = \x27codex\x27 } } }\n"
    )
    codex_config, _ = _homes(tmp_path, monkeypatch, inline, {})
    out = _run_uninstall(monkeypatch)
    flat = " ".join(out.split())
    assert open(codex_config, encoding="utf-8").read() == inline
    assert "could not be removed safely" in flat
    assert f"delete the otel.exporter tables from {codex_config}" in flat
    assert BEARER not in out


def test_uninstall_does_not_replace_a_linked_claude_settings_file_gap2517(tmp_path, monkeypatch):
    if not hasattr(os, "symlink"):
        pytest.skip("no symlinks")
    _, claude_settings = _homes(tmp_path, monkeypatch, "", {"OTEL_EXPORTER_OTLP_HEADERS": MARKED_HEADERS})
    real = tmp_path / "real-settings.json"
    os.replace(claude_settings, real)
    try:
        os.symlink(real, claude_settings)
    except OSError:
        pytest.skip("symlink not permitted")
    before = real.read_bytes()
    out = _run_uninstall(monkeypatch)
    assert os.path.islink(claude_settings)
    assert real.read_bytes() == before
    assert "could not be removed safely" in " ".join(out.split())
