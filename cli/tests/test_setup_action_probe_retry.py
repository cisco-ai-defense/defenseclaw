"""Setup reads an agent version once more before it refuses action mode.

A first run of an agent (a cold start, an antivirus scan of a new install) can
fail one version probe that the next one passes. The guided init used to keep
the first failure for the whole run, configure the connector in observe, and
explain it as "not being set up", which hid the real probe error.
"""

from __future__ import annotations

from pathlib import Path

from defenseclaw.commands import cmd_init, cmd_setup
from defenseclaw.inventory import agent_discovery as ad

CODEX_VERSION = "codex-cli 0.160.0"


def _codex_scans(monkeypatch, tmp_path: Path, answers: list[tuple[str, str]], binary_path: str = "/opt/codex/codex"):
    """Make each codex scan answer with the next (version, error); return the scan log."""
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / ".defenseclaw"))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", raising=False)
    seen: list[str] = []

    def fake_scan(name: str, **_kwargs) -> ad.AgentSignal:
        if name != "codex":
            return ad.AgentSignal(name=name, installed=False, config_path="", binary_path="", version="", error="")
        version, error = answers[min(len(seen), len(answers) - 1)]
        seen.append(error or version)
        return ad.AgentSignal(
            name=name,
            installed=bool(version),
            config_path="",
            binary_path=binary_path,
            version=version,
            error=error,
        )

    monkeypatch.setattr(ad, "_scan_agent", fake_scan)
    monkeypatch.setattr(ad, "_ai_discovery_trust_config", lambda _data_dir=None: (False, ()))
    monkeypatch.setattr(ad, "_publish_agent_signal", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(ad, "_write_cache", lambda *_args, **_kwargs: True)
    return seen


def _gate(tmp_path: Path) -> bool:
    return cmd_setup._check_connector_version_supported_for_setup(
        "codex", mode="action", emit=False, data_dir=str(tmp_path / ".defenseclaw"), _allow_prompt=False
    )


def test_action_gate_passes_when_a_cold_start_probe_times_out_once(monkeypatch, tmp_path):
    seen = _codex_scans(monkeypatch, tmp_path, [("", ad.VERSION_PROBE_TIMED_OUT), (CODEX_VERSION, "")])
    # Inside a guided init the first failed scan is memoized; the retry must not get it back.
    with ad.share_fresh_scans():
        assert _gate(tmp_path) is True
    assert seen == [ad.VERSION_PROBE_TIMED_OUT, CODEX_VERSION]


def test_action_gate_passes_when_the_first_probe_exits_non_zero(monkeypatch, tmp_path):
    seen = _codex_scans(monkeypatch, tmp_path, [("", "version probe exited 1: not ready"), (CODEX_VERSION, "")])
    assert _gate(tmp_path) is True
    assert len(seen) == 2


def test_action_gate_still_refuses_when_the_probe_keeps_failing_and_reads_only_twice(monkeypatch, tmp_path):
    seen = _codex_scans(monkeypatch, tmp_path, [("", ad.VERSION_PROBE_TIMED_OUT)])
    with ad.share_fresh_scans():
        assert _gate(tmp_path) is False
    assert len(seen) == 2


def test_action_gate_does_not_read_again_for_an_untrusted_binary(monkeypatch, tmp_path):
    seen = _codex_scans(monkeypatch, tmp_path, [("", ad.UNTRUSTED_PREFIX_ERROR)])
    assert _gate(tmp_path) is False
    assert len(seen) == 1


def test_action_gate_reads_a_healthy_agent_once(monkeypatch, tmp_path):
    seen = _codex_scans(monkeypatch, tmp_path, [(CODEX_VERSION, "")])
    assert _gate(tmp_path) is True
    assert len(seen) == 1


def test_action_downgrade_names_the_probe_error_of_a_connector_not_set_up_yet(monkeypatch, tmp_path):
    seen = _codex_scans(monkeypatch, tmp_path, [("", ad.VERSION_PROBE_TIMED_OUT)])
    with ad.share_fresh_scans():
        assert _gate(tmp_path) is False
        scans_by_gate = len(seen)
        record = cmd_init._fresh_action_downgrade_record(
            "codex", data_dir=str(tmp_path / ".defenseclaw"), fallback_discovery=None
        )
    assert "not being set up" not in record["reason"]
    assert record["reason"] == f"connector version could not be verified: {ad.VERSION_PROBE_TIMED_OUT}"
    assert record["next_command"] == "defenseclaw setup codex --mode action"
    # The explanation reuses the scan of the gate: it does not run the agent a third time.
    assert len(seen) == scans_by_gate


def test_action_downgrade_for_a_version_without_a_hook_contract_names_that_version(monkeypatch, tmp_path):
    _codex_scans(monkeypatch, tmp_path, [("codex-cli 0.1.0", "")])
    record = cmd_init._fresh_action_downgrade_record(
        "codex", data_dir=str(tmp_path / ".defenseclaw"), fallback_discovery=None
    )
    assert "not being set up" not in record["reason"]
    assert record["installed_version"] == "codex-cli 0.1.0"
