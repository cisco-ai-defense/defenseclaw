"""Phase 6 of the gateway-token rebranding fix — doctor coverage.

The Phase 1+2 auto-detect ladder makes ``agent usage`` work even
when ``cfg.gateway.token_env`` points at a stale ``OPENCLAW_GATEWAY_TOKEN``
default. That's a safety net, not the design — doctor should still
flag the drift and offer to repoint via ``--fix``.

This file covers:

* ``_check_gateway_token_env_alignment`` — emits ``pass`` when the
  configured var is populated, ``fail`` when it's empty AND the
  canonical DEFENSECLAW_ var is set (the drift case), ``warn`` for
  the rarer "all vars empty" or "custom env empty + legacy populated"
  cases.
* ``_fix_gateway_token_env`` — repoints stale ``OPENCLAW_GATEWAY_TOKEN``
  to ``DEFENSECLAW_GATEWAY_TOKEN`` only when the latter is populated;
  skips silently otherwise; refuses to stomp custom operator overrides.
"""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_doctor import (
    _DoctorResult,
    _check_gateway_token_env_alignment,
    _fix_gateway_token_env,
)


# Same hygiene helper as test_cmd_agent_token_resolution.py — strip
# all gateway-related vars from the inherited environment so tests
# can't false-positive against the dev's local ~/.defenseclaw/.env.
_GATEWAY_VARS = ("DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN", "MY_CUSTOM_TOKEN")


def _clean_env(**overrides: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _GATEWAY_VARS}
    env.update(overrides)
    return env


def _make_cfg(*, token_env: str = "") -> SimpleNamespace:
    """Minimal cfg surface the check/fixer actually reads.

    We use SimpleNamespace instead of a real Config dataclass because
    the check only ever touches ``cfg.gateway.token_env`` and the
    fixer only needs ``cfg.save()`` to mutate. Mocking the dataclass
    machinery would buy nothing and obscure intent.
    """
    return SimpleNamespace(
        gateway=SimpleNamespace(token_env=token_env),
        save=MagicMock(),
    )


class CheckTests(unittest.TestCase):
    def test_pass_when_configured_var_is_populated(self):
        cfg = _make_cfg(token_env="OPENCLAW_GATEWAY_TOKEN")
        env = _clean_env(OPENCLAW_GATEWAY_TOKEN="abc123")
        r = _DoctorResult()
        with patch.dict(os.environ, env, clear=True):
            _check_gateway_token_env_alignment(cfg, r)
        self.assertEqual(r.passed, 1)
        self.assertEqual(r.failed, 0)
        self.assertEqual(r.warned, 0)

    def test_fail_when_legacy_token_env_is_empty_but_defenseclaw_is_set(self):
        """The exact bug repro: token_env points at OPENCLAW_, real
        token is in DEFENSECLAW_, doctor flags it as a failure so
        --fix has something to repair.
        """
        cfg = _make_cfg(token_env="OPENCLAW_GATEWAY_TOKEN")
        env = _clean_env(DEFENSECLAW_GATEWAY_TOKEN="abc123")
        r = _DoctorResult()
        with patch.dict(os.environ, env, clear=True):
            _check_gateway_token_env_alignment(cfg, r)
        self.assertEqual(r.failed, 1)
        # Detail should mention the actionable remediation.
        fail_msg = next(c for c in r.checks if c["status"] == "fail")["detail"]
        self.assertIn("DEFENSECLAW_GATEWAY_TOKEN", fail_msg)
        self.assertIn("doctor --fix", fail_msg)

    def test_warn_when_custom_token_env_is_empty_and_legacy_present(self):
        """Operator pinned a custom var, that var is empty, but a
        legacy OPENCLAW_ value exists somewhere — flag for review
        without auto-mutating their custom config.
        """
        cfg = _make_cfg(token_env="MY_CUSTOM_TOKEN")
        env = _clean_env(OPENCLAW_GATEWAY_TOKEN="legacy")
        r = _DoctorResult()
        with patch.dict(os.environ, env, clear=True):
            _check_gateway_token_env_alignment(cfg, r)
        self.assertEqual(r.warned, 1)
        warn_msg = next(c for c in r.checks if c["status"] == "warn")["detail"]
        self.assertIn("MY_CUSTOM_TOKEN", warn_msg)
        self.assertIn("OPENCLAW_GATEWAY_TOKEN", warn_msg)

    def test_warn_when_no_token_is_reachable_anywhere(self):
        """All env vars empty — surface the local config state so
        the operator can correlate with sidecar /health failure.
        """
        cfg = _make_cfg(token_env="OPENCLAW_GATEWAY_TOKEN")
        env = _clean_env()
        r = _DoctorResult()
        with patch.dict(os.environ, env, clear=True):
            _check_gateway_token_env_alignment(cfg, r)
        self.assertEqual(r.warned, 1)
        warn_msg = next(c for c in r.checks if c["status"] == "warn")["detail"]
        self.assertIn("defenseclaw keys set", warn_msg)

    def test_skips_when_token_env_unset(self):
        """No token_env configured at all — other checks (sidecar
        auth probe) cover this case; nothing for us to flag.
        """
        cfg = _make_cfg(token_env="")
        env = _clean_env()
        r = _DoctorResult()
        with patch.dict(os.environ, env, clear=True):
            _check_gateway_token_env_alignment(cfg, r)
        # No record at all — silent skip.
        self.assertEqual(r.passed, 0)
        self.assertEqual(r.failed, 0)
        self.assertEqual(r.warned, 0)

    def test_skips_when_no_gateway_config(self):
        """Defensive: cfg.gateway is None → no crash, no record."""
        cfg = SimpleNamespace(gateway=None)
        r = _DoctorResult()
        with patch.dict(os.environ, _clean_env(), clear=True):
            _check_gateway_token_env_alignment(cfg, r)
        self.assertEqual(r.passed, 0)
        self.assertEqual(r.failed, 0)


class FixerTests(unittest.TestCase):
    def test_repoints_stale_openclaw_token_env_to_defenseclaw(self):
        """Happy path: token_env=OPENCLAW_, DEFENSECLAW_ is populated,
        --fix flips token_env to DEFENSECLAW_ and saves config.yaml.
        """
        cfg = _make_cfg(token_env="OPENCLAW_GATEWAY_TOKEN")
        env = _clean_env(DEFENSECLAW_GATEWAY_TOKEN="abc123")
        with patch.dict(os.environ, env, clear=True):
            tag, detail = _fix_gateway_token_env(cfg, assume_yes=True)
        self.assertEqual(tag, "pass")
        self.assertIn("DEFENSECLAW_GATEWAY_TOKEN", detail)
        self.assertEqual(cfg.gateway.token_env, "DEFENSECLAW_GATEWAY_TOKEN")
        cfg.save.assert_called_once()

    def test_skips_when_already_on_canonical_name(self):
        """Idempotent: already at DEFENSECLAW_GATEWAY_TOKEN → no-op."""
        cfg = _make_cfg(token_env="DEFENSECLAW_GATEWAY_TOKEN")
        env = _clean_env(DEFENSECLAW_GATEWAY_TOKEN="abc123")
        with patch.dict(os.environ, env, clear=True):
            tag, detail = _fix_gateway_token_env(cfg, assume_yes=True)
        self.assertEqual(tag, "skip")
        self.assertIn("already", detail)
        cfg.save.assert_not_called()

    def test_skips_when_custom_token_env_is_set(self):
        """Operator override → don't auto-mutate. Their intent wins."""
        cfg = _make_cfg(token_env="MY_CUSTOM_TOKEN")
        env = _clean_env(DEFENSECLAW_GATEWAY_TOKEN="abc123")
        with patch.dict(os.environ, env, clear=True):
            tag, detail = _fix_gateway_token_env(cfg, assume_yes=True)
        self.assertEqual(tag, "skip")
        self.assertIn("custom override", detail)
        cfg.save.assert_not_called()

    def test_skips_when_canonical_var_is_not_populated(self):
        """Don't repoint at another empty var — that just hides the
        underlying 'no token anywhere' state behind a different name.
        """
        cfg = _make_cfg(token_env="OPENCLAW_GATEWAY_TOKEN")
        env = _clean_env()  # neither var set
        with patch.dict(os.environ, env, clear=True):
            tag, detail = _fix_gateway_token_env(cfg, assume_yes=True)
        self.assertEqual(tag, "skip")
        self.assertIn("not set", detail)
        cfg.save.assert_not_called()

    def test_skips_when_no_gateway_config(self):
        """Defensive: cfg.gateway is None → no crash."""
        cfg = SimpleNamespace(gateway=None)
        env = _clean_env(DEFENSECLAW_GATEWAY_TOKEN="abc123")
        with patch.dict(os.environ, env, clear=True):
            tag, detail = _fix_gateway_token_env(cfg, assume_yes=True)
        self.assertEqual(tag, "skip")
        self.assertIn("no gateway config", detail)

    def test_returns_fail_when_save_raises(self):
        """OSError from cfg.save() propagates as a "fail" outcome."""
        cfg = _make_cfg(token_env="OPENCLAW_GATEWAY_TOKEN")
        cfg.save.side_effect = OSError("disk full")
        env = _clean_env(DEFENSECLAW_GATEWAY_TOKEN="abc123")
        with patch.dict(os.environ, env, clear=True):
            tag, detail = _fix_gateway_token_env(cfg, assume_yes=True)
        self.assertEqual(tag, "fail")
        self.assertIn("disk full", detail)

    def test_respects_user_decline_when_not_assume_yes(self):
        """Without --yes, the fixer prompts; declining yields a skip."""
        cfg = _make_cfg(token_env="OPENCLAW_GATEWAY_TOKEN")
        env = _clean_env(DEFENSECLAW_GATEWAY_TOKEN="abc123")
        with patch.dict(os.environ, env, clear=True), patch(
            "click.confirm", return_value=False
        ):
            tag, detail = _fix_gateway_token_env(cfg, assume_yes=False)
        self.assertEqual(tag, "skip")
        self.assertIn("declined by user", detail)
        cfg.save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
