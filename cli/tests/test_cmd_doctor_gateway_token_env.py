"""Doctor coverage for ``gateway.token_env``.

``OPENCLAW_GATEWAY_TOKEN`` is the OpenClaw credential and never the
DefenseClaw master (R-TOK); DefenseClaw 1.0.9 and earlier saved
``token_env: OPENCLAW_GATEWAY_TOKEN``. This file covers:

* ``_check_gateway_token_env_alignment`` — warns, with the
  ``doctor --fix`` remedy, whenever token_env names the OpenClaw
  credential; ``pass`` when a custom configured var is populated;
  ``warn`` when a custom or canonical var is empty.
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
    _check_gateway_token_env_alignment,
    _DoctorResult,
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


def _make_cfg(*, token_env: str = "", active=None) -> SimpleNamespace:
    """Minimal cfg surface the check/fixer actually reads.

    We use SimpleNamespace instead of a real Config dataclass because
    the check only ever touches ``cfg.gateway.token_env`` and the
    fixer only needs ``cfg.save()`` to mutate. Mocking the dataclass
    machinery would buy nothing and obscure intent.

    ``active`` (a list of connector names) opts the cfg into the
    connector-aware token-env path (D1): it is exposed as
    ``active_connectors()`` only when a test asks for it, so the
    legacy-config branch stays covered by the default ``None``.
    """
    cfg = SimpleNamespace(
        gateway=SimpleNamespace(token_env=token_env),
        save=MagicMock(),
    )
    if active is not None:
        cfg.active_connectors = lambda: list(active)
    return cfg


class CheckTests(unittest.TestCase):
    def _run(self, cfg, **env):
        r = _DoctorResult()
        with patch.dict(os.environ, _clean_env(**env), clear=True):
            _check_gateway_token_env_alignment(cfg, r)
        return r

    def test_pass_when_configured_var_is_populated(self):
        r = self._run(_make_cfg(token_env="MY_CUSTOM_TOKEN"), MY_CUSTOM_TOKEN="abc123")
        self.assertEqual((r.passed, r.failed, r.warned), (1, 0, 0))

    def test_openclaw_token_env_warns_and_names_the_fix_even_when_populated(self):
        """R-TOK: OPENCLAW_GATEWAY_TOKEN is the OpenClaw credential, never the
        DefenseClaw token, so a token_env naming it is reported whatever it holds."""
        for env in ({}, {"OPENCLAW_GATEWAY_TOKEN": "oc"}, {"DEFENSECLAW_GATEWAY_TOKEN": "abc123"}):
            for active in (None, [], ["openclaw"], ["hermes"]):
                with self.subTest(env=sorted(env), active=active):
                    r = self._run(_make_cfg(token_env="OPENCLAW_GATEWAY_TOKEN", active=active), **env)
                    self.assertEqual((r.passed, r.failed, r.warned), (0, 0, 1))
                    msg = next(c for c in r.checks if c["status"] == "warn")["detail"]
                    self.assertIn("names the OpenClaw credential", msg)
                    self.assertIn("doctor --fix", msg)
                    self.assertIn("DEFENSECLAW_GATEWAY_TOKEN", msg)
                    self.assertNotIn("keys set", msg)

    def test_custom_token_env_empty_with_only_the_openclaw_token_is_not_told_to_copy_it(self):
        r = self._run(_make_cfg(token_env="MY_CUSTOM_TOKEN"), OPENCLAW_GATEWAY_TOKEN="oc")
        self.assertEqual(r.warned, 1)
        msg = next(c for c in r.checks if c["status"] == "warn")["detail"]
        self.assertIn("MY_CUSTOM_TOKEN", msg)
        self.assertNotIn("OPENCLAW_GATEWAY_TOKEN", msg)
        self.assertNotIn("doctor --fix", msg)

    def test_warns_without_false_fix_hint_for_custom_env_with_canonical_fallback(self):
        r = self._run(_make_cfg(token_env="MY_CUSTOM_TOKEN"), DEFENSECLAW_GATEWAY_TOKEN="canonical-fallback")
        self.assertEqual(r.warned, 1)
        msg = next(c for c in r.checks if c["status"] == "warn")["detail"]
        self.assertIn("MY_CUSTOM_TOKEN", msg)
        self.assertIn("canonical fallback", msg)
        self.assertIn("preserves custom providers", msg)
        self.assertNotIn("doctor --fix", msg)

    def test_custom_token_env_both_empty_keeps_generic_message(self):
        r = self._run(_make_cfg(token_env="MY_CUSTOM_TOKEN", active=["hermes"]))
        self.assertEqual(r.warned, 1)
        msg = next(c for c in r.checks if c["status"] == "warn")["detail"]
        self.assertIn("MY_CUSTOM_TOKEN", msg)
        self.assertIn("preserves custom providers", msg)
        self.assertNotIn("doctor --fix", msg)

    def test_canonical_token_env_empty_points_at_the_gateway_start(self):
        r = self._run(_make_cfg(token_env="DEFENSECLAW_GATEWAY_TOKEN"), OPENCLAW_GATEWAY_TOKEN="oc")
        self.assertEqual(r.warned, 1)
        msg = next(c for c in r.checks if c["status"] == "warn")["detail"]
        self.assertIn("doctor --fix", msg)

    def test_skips_when_token_env_unset(self):
        """No token_env configured at all — other checks (sidecar
        auth probe) cover this case; nothing for us to flag.
        """
        r = self._run(_make_cfg(token_env=""))
        self.assertEqual((r.passed, r.failed, r.warned), (0, 0, 0))

    def test_skips_when_no_gateway_config(self):
        """Defensive: cfg.gateway is None → no crash, no record."""
        r = self._run(SimpleNamespace(gateway=None))
        self.assertEqual((r.passed, r.failed), (0, 0))


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

    def test_repoints_a_populated_openclaw_token_env(self):
        """R-TOK: a populated OPENCLAW_GATEWAY_TOKEN is the OpenClaw credential,
        not a working DefenseClaw provider, so it is repointed too."""
        cfg = _make_cfg(token_env="OPENCLAW_GATEWAY_TOKEN")
        env = _clean_env(OPENCLAW_GATEWAY_TOKEN="oc", DEFENSECLAW_GATEWAY_TOKEN="abc123")
        with patch.dict(os.environ, env, clear=True):
            tag, _detail = _fix_gateway_token_env(cfg, assume_yes=True)
        self.assertEqual(tag, "pass")
        self.assertEqual(cfg.gateway.token_env, "DEFENSECLAW_GATEWAY_TOKEN")

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
        self.assertEqual(cfg.gateway.token_env, "OPENCLAW_GATEWAY_TOKEN")

    def test_respects_user_decline_when_not_assume_yes(self):
        """Without --yes, the fixer prompts; declining yields a skip."""
        cfg = _make_cfg(token_env="OPENCLAW_GATEWAY_TOKEN")
        env = _clean_env(DEFENSECLAW_GATEWAY_TOKEN="abc123")
        with patch.dict(os.environ, env, clear=True), patch("click.confirm", return_value=False):
            tag, detail = _fix_gateway_token_env(cfg, assume_yes=False)
        self.assertEqual(tag, "skip")
        self.assertIn("declined by user", detail)
        cfg.save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
