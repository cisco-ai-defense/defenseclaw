"""GAP-2517: uninstall names the agent OTel entries it keeps that carry DefenseClaw's markers."""

from __future__ import annotations

import json
from types import SimpleNamespace

from click.testing import CliRunner
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


def test_uninstall_names_the_marked_otel_entries_it_kept_gap2517(tmp_path, monkeypatch):
    codex_config, claude_settings = _homes(
        tmp_path,
        monkeypatch,
        MARKED_CODEX,
        {
            "OTEL_EXPORTER_OTLP_HEADERS": MARKED_HEADERS,
            "OTEL_EXPORTER_OTLP_LOGS_HEADERS": MARKED_HEADERS,
            "OTEL_LOGS_EXPORTER": "none",
        },
    )
    out = _run_uninstall(monkeypatch)
    assert codex_config in out
    assert "otel.exporter" in out
    assert "127.0.0.1:19020" in out
    assert claude_settings in out
    assert "OTEL_EXPORTER_OTLP_HEADERS, OTEL_EXPORTER_OTLP_LOGS_HEADERS" in out
    assert "if you did not add them, delete" in out
    assert BEARER not in out


def test_uninstall_says_nothing_about_an_operator_collector_gap2517(tmp_path, monkeypatch):
    _homes(
        tmp_path,
        monkeypatch,
        OPERATOR_CODEX,
        {"OTEL_EXPORTER_OTLP_HEADERS": f"authorization=Bearer {BEARER},x-tenant=logs"},
    )
    out = _run_uninstall(monkeypatch)
    assert "x-defenseclaw-source" not in out
    assert "delete" not in out


def test_uninstall_without_agent_configs_says_nothing_gap2517(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "no-codex"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "no-claude"))
    out = _run_uninstall(monkeypatch)
    assert "x-defenseclaw-source" not in out


def test_uninstall_names_the_endpoint_keys_paired_with_the_marked_headers_gap2517(tmp_path, monkeypatch):
    _, claude_settings = _homes(
        tmp_path,
        monkeypatch,
        "",
        {
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:19010",
            "OTEL_EXPORTER_OTLP_HEADERS": MARKED_HEADERS,
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "http://127.0.0.1:19010/v1/logs",
            "OTEL_EXPORTER_OTLP_LOGS_HEADERS": MARKED_HEADERS,
            "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://127.0.0.1:4318/v1/metrics",
            "OTEL_EXPORTER_OTLP_METRICS_HEADERS": "x-tenant=metrics",
        },
    )
    out = _run_uninstall(monkeypatch)
    flat = " ".join(out.split())
    assert "Claude Code still sends its telemetry and that bearer to 127.0.0.1:19010" in flat
    assert (
        "delete OTEL_EXPORTER_OTLP_HEADERS, OTEL_EXPORTER_OTLP_LOGS_HEADERS, "
        "OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_LOGS_ENDPOINT from the env block of " + claude_settings
    ) in flat
    # The unmarked metrics pair is the user's and is not named.
    assert "METRICS" not in out
    assert BEARER not in out
