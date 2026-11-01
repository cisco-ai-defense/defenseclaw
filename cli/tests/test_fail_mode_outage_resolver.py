"""The outage fail-mode readers call a resolver the real GuardrailConfig has (GAP-1354, GAP-1730, GAP-1878).

Doctor, Status and the fail-mode setter read the mode of a current hook
(call-time OpenCode/Amp plugins, the per-user shell helper) from
``GuardrailConfig.effective_hook_outage_fail_mode``. The class had no such
method and every reader took it through ``getattr(..., None)``, so on a real
install the mode read as missing: Doctor said "no readable fail mode" and
``setup opencode --mode action`` rolled back with ``rendered=missing``. These
tests use the real config class, never a stub.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw import config as dcconfig
from defenseclaw import fail_mode


def _guardrail(saved: str = "") -> dcconfig.GuardrailConfig:
    return dcconfig.GuardrailConfig(hook_fail_mode=saved)


@pytest.mark.parametrize(("saved", "want"), [("", "open"), ("open", "open"), ("closed", "closed")])
def test_real_guardrail_config_resolves_the_outage_mode(saved: str, want: str) -> None:
    assert _guardrail(saved).effective_hook_outage_fail_mode("opencode") == want
    assert _guardrail(saved).effective_hook_outage_fail_mode("amp") == want


@pytest.mark.parametrize(("saved", "want"), [("", "open"), ("closed", "closed")])
def test_call_time_amp_plugin_reads_the_real_config(tmp_path: Path, saved: str, want: str) -> None:
    plugin = tmp_path / "defenseclaw.ts"
    plugin.write_text('// defenseclaw-call-time-outage-v1\nconst DC_FAIL_MODE: string = "closed"\n', encoding="utf-8")
    cfg = SimpleNamespace(guardrail=_guardrail(saved))
    assert fail_mode._read_amp_plugin_mode(plugin, cfg) == want


@pytest.mark.parametrize(("saved", "want"), [("", "open"), ("closed", "closed")])
def test_call_time_opencode_plugin_reads_the_real_config(tmp_path: Path, saved: str, want: str) -> None:
    plugin = tmp_path / "defenseclaw.js"
    plugin.write_text('// defenseclaw-call-time-outage-v1\nconst DC_FAIL_MODE = "closed";\n', encoding="utf-8")
    (tmp_path / "hook_contract_lock.json").write_text(
        json.dumps({"connectors": {"opencode": {"locations": {"hook_config_paths": [str(plugin)]}}}}),
        encoding="utf-8",
    )
    cfg = SimpleNamespace(data_dir=str(tmp_path), guardrail=_guardrail(saved))
    assert fail_mode._read_opencode_plugin_mode(cfg) == want


def test_call_time_shell_helper_reads_the_real_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    (hooks / "codex-hook.sh").write_text('FAIL_MODE="closed"\n', encoding="utf-8")
    (hooks / "_hardening.sh").write_text("# defenseclaw-call-time-outage-v1\n", encoding="utf-8")
    cfg = SimpleNamespace(data_dir=str(tmp_path), deployment_mode="", guardrail=_guardrail())
    monkeypatch.setattr(fail_mode, "_is_windows", lambda: False)
    assert fail_mode._platform_runtime_source(cfg, "codex") == ("hook-script", "open")


def test_no_reader_takes_the_outage_resolver_through_getattr() -> None:
    root = Path(fail_mode.__file__).resolve().parent
    for path in (root / "fail_mode.py", root / "commands" / "cmd_doctor.py"):
        text = path.read_text(encoding="utf-8")
        assert '"effective_hook_outage_fail_mode", None' not in text, path
