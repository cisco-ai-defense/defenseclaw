"""Unit tests for ``cli/defenseclaw/envvars.py`` — the Python side of the
env-var registry.

These tests exercise the loader, schema validation, ``is_active`` /
``active_security_overrides`` helpers, and the cross-language contract
shared with the Go registry (categories, security-impact levels, and
truthy-value semantics).
"""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest import mock

from defenseclaw.envvars import (
    ALLOWED_CATEGORIES,
    ALLOWED_SECURITY_IMPACT,
    CATEGORY_SECURITY_OPT_OUT,
    _validate_entry,
    active_security_overrides,
    load_registry,
)


class RegistryStructureTests(unittest.TestCase):
    """The registry on disk must satisfy a handful of invariants."""

    def setUp(self) -> None:
        self.registry = load_registry()

    def test_schema_version_is_string(self) -> None:
        self.assertIsInstance(self.registry.schema_version, str)
        self.assertTrue(self.registry.schema_version)

    def test_categories_exhaustive(self) -> None:
        """$categories MUST exactly equal ALLOWED_CATEGORIES."""
        self.assertEqual(set(self.registry.categories), ALLOWED_CATEGORIES)

    def test_every_entry_has_known_category(self) -> None:
        for e in self.registry.entries:
            self.assertIn(e.category, ALLOWED_CATEGORIES, e.name)

    def test_every_entry_has_known_security_impact(self) -> None:
        for e in self.registry.entries:
            self.assertIn(e.security_impact, ALLOWED_SECURITY_IMPACT, e.name)

    def test_every_entry_has_purpose(self) -> None:
        for e in self.registry.entries:
            self.assertTrue(e.purpose, e.name)

    def test_every_entry_has_at_least_one_consumer(self) -> None:
        # test_fixture entries don't always have a singular consumer
        # (they can be hand-set in many tests); everything else must.
        for e in self.registry.entries:
            if e.category == "test_fixture":
                continue
            self.assertTrue(
                e.consumers,
                f"{e.name}: entries with category={e.category!r} must declare at least one consumer",
            )

    def test_no_duplicate_names(self) -> None:
        names = [e.name for e in self.registry.entries]
        self.assertEqual(len(names), len(set(names)))

    def test_bundled_registry_matches_source_registry(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source = root / "internal" / "envvars" / "registry.json"
        bundled = root / "cli" / "defenseclaw" / "_data" / "envvars" / "registry.json"
        self.assertEqual(json.loads(bundled.read_text()), json.loads(source.read_text()))

    def test_names_use_canonical_prefix(self) -> None:
        for e in self.registry.entries:
            if e.name == "MIGRATION_DEFENSECLAW_HOME":
                continue
            self.assertTrue(
                e.name.startswith("DEFENSECLAW_"),
                f"{e.name} must start with DEFENSECLAW_",
            )

    def test_high_impact_security_optouts_surface_in_doctor(self) -> None:
        """Every HIGH-impact security-opt-out MUST be surfaced in
        doctor — that's literally the point of the registry."""
        for e in self.registry.entries:
            if e.deprecated:
                if e.category == CATEGORY_SECURITY_OPT_OUT and e.security_impact == "high":
                    self.assertTrue(
                        e.surface_in_doctor or e.migration_only,
                        f"{e.name}: deprecated high-impact opt-out must be "
                        "migration-only or surface_in_doctor",
                    )
                continue
            if e.category != CATEGORY_SECURITY_OPT_OUT:
                continue
            if e.security_impact == "high":
                self.assertTrue(
                    e.surface_in_doctor,
                    f"{e.name}: high-impact security opt-out must surface_in_doctor",
                )

    def test_boolean_metadata_rejects_string_lookalikes(self) -> None:
        root = Path(__file__).resolve().parents[2]
        registry_path = root / "internal" / "envvars" / "registry.json"
        entry = json.loads(registry_path.read_text())["entries"][0]
        for field_name in ("deprecated", "migration_only", "surface_in_doctor"):
            with self.subTest(field_name=field_name):
                malformed = {**entry, field_name: "false"}
                with self.assertRaisesRegex(ValueError, rf"{field_name} must be a boolean"):
                    _validate_entry(malformed, registry_path)


class IsActiveTests(unittest.TestCase):
    """``EnvVar.is_active`` is the truthiness oracle used by doctor."""

    def setUp(self) -> None:
        self.disable_redaction = load_registry().get("DEFENSECLAW_DISABLE_REDACTION")
        assert self.disable_redaction is not None

    def test_unset_is_inactive(self) -> None:
        self.assertFalse(self.disable_redaction.is_active({}))

    def test_empty_string_is_inactive(self) -> None:
        self.assertFalse(self.disable_redaction.is_active({"DEFENSECLAW_DISABLE_REDACTION": ""}))

    def test_whitespace_is_inactive(self) -> None:
        self.assertFalse(self.disable_redaction.is_active({"DEFENSECLAW_DISABLE_REDACTION": "   "}))

    def test_one_is_active(self) -> None:
        self.assertTrue(self.disable_redaction.is_active({"DEFENSECLAW_DISABLE_REDACTION": "1"}))

    def test_true_is_active(self) -> None:
        self.assertTrue(self.disable_redaction.is_active({"DEFENSECLAW_DISABLE_REDACTION": "true"}))

    def test_yes_is_active(self) -> None:
        self.assertTrue(self.disable_redaction.is_active({"DEFENSECLAW_DISABLE_REDACTION": "yes"}))

    def test_case_insensitive(self) -> None:
        self.assertTrue(self.disable_redaction.is_active({"DEFENSECLAW_DISABLE_REDACTION": "True"}))
        self.assertTrue(self.disable_redaction.is_active({"DEFENSECLAW_DISABLE_REDACTION": "YES"}))

    def test_zero_is_inactive(self) -> None:
        self.assertFalse(self.disable_redaction.is_active({"DEFENSECLAW_DISABLE_REDACTION": "0"}))

    def test_arbitrary_string_is_inactive(self) -> None:
        # We're deliberately strict — only the documented truthy set
        # actually activates an opt-out. This prevents accidents like
        # `export DEFENSECLAW_DISABLE_REDACTION="false"` from being
        # treated as a value-of-"false" + active.
        self.assertFalse(self.disable_redaction.is_active({"DEFENSECLAW_DISABLE_REDACTION": "false"}))
        self.assertFalse(self.disable_redaction.is_active({"DEFENSECLAW_DISABLE_REDACTION": "no"}))


class ActiveSecurityOverridesTests(unittest.TestCase):
    """Integration-style: simulate operator env, assert active list."""

    def test_pristine_env_has_no_overrides(self) -> None:
        # Build a minimal env without any DEFENSECLAW_* keys.
        env: dict[str, str] = {}
        self.assertEqual(active_security_overrides(env), [])

    def test_deprecated_migration_input_does_not_appear(self) -> None:
        env = {"DEFENSECLAW_DISABLE_REDACTION": "1"}
        names = [e.name for e in active_security_overrides(env)]
        self.assertNotIn("DEFENSECLAW_DISABLE_REDACTION", names)

    def test_two_overrides_returns_two(self) -> None:
        env = {
            "DEFENSECLAW_ALLOW_CGNAT": "1",
            "DEFENSECLAW_CODEX_LOOPBACK_TRUST": "1",
        }
        names = [e.name for e in active_security_overrides(env)]
        self.assertEqual(
            sorted(names),
            sorted(
                [
                    "DEFENSECLAW_ALLOW_CGNAT",
                    "DEFENSECLAW_CODEX_LOOPBACK_TRUST",
                ]
            ),
        )

    def test_low_impact_can_be_filtered(self) -> None:
        # DEFENSECLAW_DEV is low-impact security_opt_out — should be in
        # the inclusive list, but not in the medium-and-up list.
        env = {"DEFENSECLAW_DEV": "1"}
        inclusive = [e.name for e in active_security_overrides(env, include_low_impact=True)]
        self.assertIn("DEFENSECLAW_DEV", inclusive)
        restricted = [e.name for e in active_security_overrides(env, include_low_impact=False)]
        self.assertNotIn("DEFENSECLAW_DEV", restricted)

    def test_strict_availability_does_not_surface(self) -> None:
        # DEFENSECLAW_STRICT_AVAILABILITY is opt-IN to stricter
        # behavior, not a bypass. It must NOT appear in active
        # overrides even when set.
        env = {"DEFENSECLAW_STRICT_AVAILABILITY": "1"}
        names = [e.name for e in active_security_overrides(env)]
        self.assertNotIn("DEFENSECLAW_STRICT_AVAILABILITY", names)


class IsActiveReadsOsEnvironTests(unittest.TestCase):
    """Sanity check: passing no env arg falls back to os.environ."""

    def test_reads_os_environ_by_default(self) -> None:
        sv = load_registry().get("DEFENSECLAW_DISABLE_REDACTION")
        assert sv is not None
        with mock.patch.dict(os.environ, {"DEFENSECLAW_DISABLE_REDACTION": "1"}, clear=False):
            self.assertTrue(sv.is_active())
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEFENSECLAW_DISABLE_REDACTION", None)
            self.assertFalse(sv.is_active())


if __name__ == "__main__":
    unittest.main()
