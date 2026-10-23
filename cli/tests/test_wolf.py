# SPDX-License-Identifier: Apache-2.0
"""Hermetic runtime, config and doctor tests; no model downloads or benchmarks."""

from dataclasses import asdict
from types import SimpleNamespace

import pytest
from defenseclaw.config import WolfConfig, _merge_guardrail
from defenseclaw.wolf import MANIFEST, Adapter, runtime_config


class Backend:
    def __init__(self, cfg):
        pass

    def score(self, text, deadline):
        return (0.9 if text == "block fixture" else 0.1), 2, 1


def settings():
    return runtime_config(asdict(WolfConfig(enabled=True, model_dir="/models/wolf")))


def test_manifest_variants_and_config_roundtrip():
    for variant in ("small", "full"):
        cfg = _merge_guardrail({"wolf": {"enabled": True, "variant": variant, "timeout_ms": 900}}, "")
        assert cfg.wolf.variant == variant
        assert _merge_guardrail(asdict(cfg), "").wolf == cfg.wolf
        assert len(MANIFEST[variant]["revision"]) == 40
        assert set(MANIFEST[variant]["sha256"]) == {"model", "tokenizer", "model_config"}


def test_worker_allow_block_and_sanitized_failure():
    a = Adapter(settings(), Backend)
    assert a.inspect({"tool": "read", "output": "allow fixture"})["action"] == "allow"
    assert a.inspect({"tool": "read", "output": "block fixture"})["action"] == "block"
    assert a.inspect({"tool": "read", "output": "x" * (256 * 1024 + 1)})["reason"] == "wolf:byte_limit"
    assert a.inspect({"output": "private"})["reason"] == "wolf:invalid_request"


def test_disabled_does_not_initialize_backend():
    cfg = settings()
    cfg["enabled"] = False

    def forbidden(_):
        pytest.fail("disabled scanner initialized model")

    assert Adapter(cfg, forbidden).inspect({"tool": "read", "output": "text"})["action"] == "allow"


def test_doctor_disabled_and_missing_runtime(monkeypatch):
    from defenseclaw.commands import cmd_doctor as doctor

    rows = []
    monkeypatch.setattr(doctor, "_emit", lambda *a, **k: rows.append((a, k)))

    def unavailable(*a, **kw):
        raise FileNotFoundError

    monkeypatch.setattr(doctor.subprocess, "run", unavailable)
    cfg = SimpleNamespace(guardrail=SimpleNamespace(wolf=WolfConfig()))
    doctor._check_wolf(cfg, None)
    assert rows[-1][0][0] == "skip"
    cfg.guardrail.wolf = WolfConfig(enabled=True, model_dir="/models/wolf", python_executable="/missing/python")
    doctor._check_wolf(cfg, None)
    assert rows[-1][0][0] == "fail"
    assert rows[-1][1]["reason_code"] == "wolf-unavailable"
    assert "provision" in rows[-1][1]["remediation"]


@pytest.mark.parametrize(
    "raw",
    [
        None,
        False,
        [],
        "enabled",
        {"unknown": True},
        {"enabled": "false"},
        {"threads": "2"},
        {"timeout_ms": 0},
        {"variant": "invalid"},
    ],
)
def test_malformed_wolf_is_a_configuration_error(raw):
    from defenseclaw.observability.v8_config import V8ConfigError

    with pytest.raises(V8ConfigError, match=r"guardrail\.wolf"):
        _merge_guardrail({"wolf": raw}, "")


def test_load_rejects_quoted_wolf_boolean(tmp_path):
    from defenseclaw.config import load
    from defenseclaw.observability.v8_config import V8ConfigError

    with pytest.raises(V8ConfigError, match=r"guardrail\.wolf\.enabled"):
        load(data_dir=tmp_path, parsed_source={"config_version": 9, "guardrail": {"wolf": {"enabled": "false"}}})


def test_missing_and_explicit_empty_wolf_keep_defaults():
    assert _merge_guardrail({"mode": "observe"}, "").wolf == WolfConfig()
    assert _merge_guardrail({"wolf": {}}, "").wolf == WolfConfig()
