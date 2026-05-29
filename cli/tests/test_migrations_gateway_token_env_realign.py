"""Gateway-token rebranding fix — config.yaml realignment migration.

Tests for ``_align_gateway_token_env_in_config``: surgically rewrite
``gateway.token_env: OPENCLAW_GATEWAY_TOKEN`` →
``DEFENSECLAW_GATEWAY_TOKEN`` in config.yaml when (and only when) the
dotenv has ``DEFENSECLAW_GATEWAY_TOKEN`` set.

The migration is wired into the registry at whatever version the
release manager cuts (currently keyed at 0.7.0 — see migrations.py
for the rationale). Tests use ``_REGISTRY_VERSION`` so re-keying the
registry needs zero test changes.

Contract under test:

* **Happy path** — legacy token_env + populated dotenv → rewrite.
* **Idempotent** — already-migrated config → no-op, no changes recorded.
* **Safety gate** — dotenv lacks DEFENSECLAW_GATEWAY_TOKEN → no-op.
  This is the most important guard: without it, the migration would
  repoint at an empty env var and turn a *silently-working-via-fall-through*
  config into a *visibly-broken-with-no-fall-back* one.
* **Custom override preserved** — token_env points at a non-OPENCLAW_
  custom var → leave it alone.
* **Comment preservation** — inline comments on the token_env line
  survive the rewrite byte-for-byte.
* **Defensive** — missing config.yaml, missing data_dir, malformed
  YAML, all return cleanly without crashing the upgrade.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.migrations import (
    MIGRATIONS,
    MigrationContext,
    _align_gateway_token_env_in_config,
    _migrate_gateway_token_env_realign,
)

# Version the realignment migration is registered under. Pulled from
# the registry so a re-key in migrations.py does not break these
# tests — the contract is "this callable is wired into the registry",
# not "it's wired at a hardcoded version".
_REGISTRY_VERSION = next(
    (ver for ver, _desc, fn in MIGRATIONS if fn is _migrate_gateway_token_env_realign),
    None,
)


def _seed_dotenv(data_dir: str, **vars: str) -> None:
    """Write a minimal ``<data_dir>/.env`` with the given key=value pairs."""
    body = "".join(f"{k}={v}\n" for k, v in vars.items())
    with open(os.path.join(data_dir, ".env"), "w") as f:
        f.write(body)
    os.chmod(os.path.join(data_dir, ".env"), 0o600)


def _seed_config(data_dir: str, body: str) -> str:
    """Write ``body`` as ``<data_dir>/config.yaml`` and return the path."""
    path = os.path.join(data_dir, "config.yaml")
    with open(path, "w") as f:
        f.write(body)
    return path


def _read_config(data_dir: str) -> str:
    with open(os.path.join(data_dir, "config.yaml")) as f:
        return f.read()


class TestAlignGatewayTokenEnv(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-gw-tokenv-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _ctx(self) -> MigrationContext:
        return MigrationContext(openclaw_home=self.tmp, data_dir=self.tmp)

    def test_happy_path_rewrites_legacy_to_canonical(self):
        """Stock case: ``token_env: OPENCLAW_GATEWAY_TOKEN`` + dotenv
        carries DEFENSECLAW_GATEWAY_TOKEN → rewrite token_env in YAML.
        """
        _seed_dotenv(self.tmp, DEFENSECLAW_GATEWAY_TOKEN="abc123")
        _seed_config(self.tmp, (
            "gateway:\n"
            "  host: 127.0.0.1\n"
            "  port: 18789\n"
            "  token_env: OPENCLAW_GATEWAY_TOKEN\n"
            "  api_port: 18970\n"
            "guardrail:\n"
            "  enabled: true\n"
        ))

        ctx = self._ctx()
        _align_gateway_token_env_in_config(ctx)

        after = _read_config(self.tmp)
        self.assertIn("token_env: DEFENSECLAW_GATEWAY_TOKEN", after)
        self.assertNotIn("OPENCLAW_GATEWAY_TOKEN", after)
        # Unrelated keys untouched, line ordering preserved.
        self.assertIn("host: 127.0.0.1", after)
        self.assertIn("port: 18789", after)
        self.assertIn("api_port: 18970", after)
        # Change is recorded so the upgrade summary surfaces it.
        joined = "\n".join(ctx.changes)
        self.assertIn("repointed gateway.token_env", joined)
        self.assertIn("DEFENSECLAW_GATEWAY_TOKEN", joined)

    def test_idempotent_when_already_migrated(self):
        """Re-running on a config that already says
        DEFENSECLAW_GATEWAY_TOKEN is a silent no-op.
        """
        _seed_dotenv(self.tmp, DEFENSECLAW_GATEWAY_TOKEN="abc123")
        original = (
            "gateway:\n"
            "  token_env: DEFENSECLAW_GATEWAY_TOKEN\n"
        )
        _seed_config(self.tmp, original)

        ctx = self._ctx()
        _align_gateway_token_env_in_config(ctx)

        self.assertEqual(_read_config(self.tmp), original)
        self.assertEqual(ctx.changes, [])

    def test_safety_gate_skips_when_dotenv_has_no_canonical_token(self):
        """CRITICAL: if DEFENSECLAW_GATEWAY_TOKEN is not in the
        dotenv, do NOT repoint — that would turn a working
        fall-through into a broken-no-fall-back config.
        """
        # Dotenv exists but only has the legacy var.
        _seed_dotenv(self.tmp, OPENCLAW_GATEWAY_TOKEN="legacy-tok")
        original = (
            "gateway:\n"
            "  token_env: OPENCLAW_GATEWAY_TOKEN\n"
        )
        _seed_config(self.tmp, original)

        ctx = self._ctx()
        _align_gateway_token_env_in_config(ctx)

        # Config is untouched.
        self.assertEqual(_read_config(self.tmp), original)
        self.assertEqual(ctx.changes, [])

    def test_safety_gate_skips_when_dotenv_missing_entirely(self):
        """No .env at all → no-op (nothing to detect the canonical var)."""
        # No _seed_dotenv() call — dotenv file does not exist.
        original = (
            "gateway:\n"
            "  token_env: OPENCLAW_GATEWAY_TOKEN\n"
        )
        _seed_config(self.tmp, original)

        ctx = self._ctx()
        _align_gateway_token_env_in_config(ctx)

        self.assertEqual(_read_config(self.tmp), original)
        self.assertEqual(ctx.changes, [])

    def test_safety_gate_skips_when_canonical_token_is_empty_string(self):
        """``DEFENSECLAW_GATEWAY_TOKEN=`` (empty value) does NOT count
        as configured — same risk as a missing entry.
        """
        _seed_dotenv(self.tmp, DEFENSECLAW_GATEWAY_TOKEN="")
        original = (
            "gateway:\n"
            "  token_env: OPENCLAW_GATEWAY_TOKEN\n"
        )
        _seed_config(self.tmp, original)

        ctx = self._ctx()
        _align_gateway_token_env_in_config(ctx)

        self.assertEqual(_read_config(self.tmp), original)
        self.assertEqual(ctx.changes, [])

    def test_preserves_custom_operator_override(self):
        """Operator pinned ``token_env: MY_CUSTOM_TOKEN`` via
        ``defenseclaw setup gateway`` → migration must not stomp it.
        """
        _seed_dotenv(
            self.tmp,
            DEFENSECLAW_GATEWAY_TOKEN="abc123",
            MY_CUSTOM_TOKEN="custom-value",
        )
        original = (
            "gateway:\n"
            "  token_env: MY_CUSTOM_TOKEN\n"
        )
        _seed_config(self.tmp, original)

        ctx = self._ctx()
        _align_gateway_token_env_in_config(ctx)

        self.assertEqual(_read_config(self.tmp), original)
        self.assertEqual(ctx.changes, [])

    def test_preserves_inline_comment_on_rewritten_line(self):
        """Comment on the same line as the value must survive the
        rewrite byte-for-byte. Operator-curated context is sacred.
        """
        _seed_dotenv(self.tmp, DEFENSECLAW_GATEWAY_TOKEN="abc123")
        _seed_config(self.tmp, (
            "gateway:\n"
            "  # this comment block describes the gateway settings\n"
            "  token_env: OPENCLAW_GATEWAY_TOKEN  # legacy from 0.4.0\n"
            "  api_port: 18970\n"
        ))

        ctx = self._ctx()
        _align_gateway_token_env_in_config(ctx)

        after = _read_config(self.tmp)
        self.assertIn(
            "token_env: DEFENSECLAW_GATEWAY_TOKEN  # legacy from 0.4.0",
            after,
        )
        # The descriptive comment above is also preserved.
        self.assertIn("# this comment block describes the gateway settings", after)
        # Two-space indentation is preserved (not collapsed to tabs etc.).
        self.assertIn("  token_env: DEFENSECLAW_GATEWAY_TOKEN", after)

    def test_handles_quoted_value(self):
        """YAML formatters sometimes quote the value. Migration must
        match quoted values too and preserve the quoting style.
        """
        _seed_dotenv(self.tmp, DEFENSECLAW_GATEWAY_TOKEN="abc123")
        _seed_config(self.tmp, (
            "gateway:\n"
            '  token_env: "OPENCLAW_GATEWAY_TOKEN"\n'
        ))

        ctx = self._ctx()
        _align_gateway_token_env_in_config(ctx)

        after = _read_config(self.tmp)
        self.assertIn('token_env: "DEFENSECLAW_GATEWAY_TOKEN"', after)

    def test_no_op_when_config_yaml_missing(self):
        """Fresh install or partial-setup host → no config.yaml. The
        migration must not crash; just return silently.
        """
        _seed_dotenv(self.tmp, DEFENSECLAW_GATEWAY_TOKEN="abc123")
        # No _seed_config() — config.yaml does not exist.

        ctx = self._ctx()
        _align_gateway_token_env_in_config(ctx)

        self.assertEqual(ctx.changes, [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "config.yaml")))

    def test_no_op_when_no_gateway_block(self):
        """Defensive: config.yaml has no ``gateway:`` block at all
        (highly unlikely but possible mid-corruption) → return cleanly.
        """
        _seed_dotenv(self.tmp, DEFENSECLAW_GATEWAY_TOKEN="abc123")
        original = (
            "data_dir: /tmp/x\n"
            "guardrail:\n"
            "  enabled: true\n"
        )
        _seed_config(self.tmp, original)

        ctx = self._ctx()
        _align_gateway_token_env_in_config(ctx)

        self.assertEqual(_read_config(self.tmp), original)
        self.assertEqual(ctx.changes, [])

    def test_wrapper_swallows_step_failures(self):
        """``_migrate_gateway_token_env_realign`` (the wrapper) must
        never raise even if the inner step crashes — the playbook
        says migrations never abort an upgrade. Validated by passing
        a context with a non-existent data_dir; the inner step
        skips defensively, so the wrapper has nothing to swallow,
        but the contract that "any context completes without raising"
        still holds.
        """
        ctx = MigrationContext(
            openclaw_home="/nonexistent/path",
            data_dir="/nonexistent/path",
        )
        _migrate_gateway_token_env_realign(ctx)


class TestRegistry(unittest.TestCase):
    """Lock down the registry entry — callable identity, ordering, and
    that *some* version key exists. Catches accidental refactors that
    break the cursor-driven dispatch.

    The specific version key is intentionally NOT asserted (it's a
    release-manager decision); we only assert the callable is wired
    in and that it sorts after the prior gateway-touching migration.
    """

    def test_realign_callable_is_registered(self):
        entry = next(
            (e for e in MIGRATIONS if e[2] is _migrate_gateway_token_env_realign),
            None,
        )
        self.assertIsNotNone(
            entry,
            "_migrate_gateway_token_env_realign must be wired into MIGRATIONS",
        )
        ver, desc, fn = entry
        self.assertTrue(ver, "registry entry must carry a non-empty version key")
        self.assertIn("gateway.token_env", desc)
        self.assertIs(fn, _migrate_gateway_token_env_realign)

    def test_realign_appears_after_0_5_0_token_bootstrap(self):
        """Order matters: realignment depends on the dotenv being in
        the post-0.4.0 / 0.5.0 shape (DEFENSECLAW_GATEWAY_TOKEN
        already promoted into the .env). Must run after 0.5.0.
        """
        versions = [e[0] for e in MIGRATIONS]
        realign_idx = next(
            (i for i, e in enumerate(MIGRATIONS) if e[2] is _migrate_gateway_token_env_realign),
            -1,
        )
        self.assertGreaterEqual(realign_idx, 0)
        self.assertLess(versions.index("0.5.0"), realign_idx)


if __name__ == "__main__":
    unittest.main()
