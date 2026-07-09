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
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import defenseclaw.envvars as envvars_module
from defenseclaw.envvars import (
    ALLOWED_CATEGORIES,
    ALLOWED_SECURITY_IMPACT,
    CATEGORY_SECURITY_OPT_OUT,
    active_security_overrides,
    load_registry,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _entries_by_name(path: Path) -> dict[str, dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {entry["name"]: entry for entry in payload["entries"]}


def _doc_rows_by_name(path: Path) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| `DEFENSECLAW_"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        rows[cells[0].strip("`")] = cells
    return rows


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

    def test_source_registry_precedes_generated_bundle(self) -> None:
        source = _REPO_ROOT / "internal" / "envvars" / "registry.json"
        with mock.patch.dict(os.environ, {"DEFENSECLAW_REPO_ROOT": ""}):
            self.assertEqual(envvars_module._registry_path(), source)

    def test_installed_package_below_checkout_prefers_its_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "checkout"
            source = checkout / "internal" / "envvars" / "registry.json"
            package = (
                checkout
                / ".venv"
                / "Lib"
                / "site-packages"
                / "defenseclaw"
            )
            bundled = package / "_data" / "envvars" / "registry.json"
            module = package / "envvars.py"
            source.parent.mkdir(parents=True)
            bundled.parent.mkdir(parents=True)
            source.write_text("source", encoding="utf-8")
            bundled.write_text("bundle", encoding="utf-8")
            module.write_text("", encoding="utf-8")

            with (
                mock.patch.object(envvars_module, "__file__", str(module)),
                mock.patch.dict(os.environ, {"DEFENSECLAW_REPO_ROOT": ""}),
            ):
                self.assertEqual(envvars_module._registry_path(), bundled)

    def test_new_windows_envvar_contract_is_pinned(self) -> None:
        expected_registry = {
            "DEFENSECLAW_CLAWHUB_CWD": {
                "category": "hook_internal",
                "default": "unset (set by the ClawHub launcher adapter on Windows)",
                "accepted_values": ["absolute directory path"],
                "security_impact": "none",
                "surface_in_doctor": False,
            },
            "DEFENSECLAW_CLAWHUB_LAUNCHER": {
                "category": "hook_internal",
                "default": "unset (set by the ClawHub launcher adapter on Windows)",
                "accepted_values": ["absolute path to a .cmd or .bat launcher"],
                "security_impact": "none",
                "surface_in_doctor": False,
            },
            "DEFENSECLAW_OBSERVABILITY_BIN": {
                "category": "runtime_path",
                "default": "defenseclaw-observability (resolved via PATH)",
                "accepted_values": ["executable name or absolute path", "unset"],
                "security_impact": "low",
                "surface_in_doctor": False,
            },
            "DEFENSECLAW_TEST_COMMAND": {
                "category": "test_fixture",
                "default": "unset",
                "accepted_values": ["start", "status", "restart", "unset"],
                "security_impact": "none",
                "surface_in_doctor": False,
            },
            "DEFENSECLAW_TEST_EXE": {
                "category": "test_fixture",
                "default": "unset",
                "accepted_values": ["absolute temporary executable path", "unset"],
                "security_impact": "none",
                "surface_in_doctor": False,
            },
            "DEFENSECLAW_TEST_MARKER": {
                "category": "test_fixture",
                "default": "unset",
                "accepted_values": ["absolute file path", "unset"],
                "security_impact": "none",
                "surface_in_doctor": False,
            },
            "DEFENSECLAW_WINDOWS_PROCESS_HELPER": {
                "category": "test_fixture",
                "default": "unset",
                "accepted_values": ["1", "unset"],
                "security_impact": "none",
                "surface_in_doctor": False,
            },
        }
        fields = tuple(next(iter(expected_registry.values())))
        registry_paths = (
            _REPO_ROOT / "internal" / "envvars" / "registry.json",
        )
        for path in registry_paths:
            entries = _entries_by_name(path)
            actual = {
                name: {field: entries[name][field] for field in fields}
                for name in expected_registry
            }
            self.assertEqual(actual, expected_registry, path)

        expected_doc_cells = {
            "DEFENSECLAW_CLAWHUB_CWD": (
                "—",
                "`unset` (set by the ClawHub launcher adapter on Windows)",
                "`absolute directory path`",
            ),
            "DEFENSECLAW_CLAWHUB_LAUNCHER": (
                "—",
                "`unset` (set by the ClawHub launcher adapter on Windows)",
                "`absolute path to a .cmd or .bat launcher`",
            ),
            "DEFENSECLAW_OBSERVABILITY_BIN": (
                "low",
                "defenseclaw-observability (resolved via PATH)",
                "`executable name or absolute path`, `unset`",
            ),
            "DEFENSECLAW_TEST_COMMAND": (
                "—",
                "`unset`",
                "`start`, `status`, `restart`, `unset`",
            ),
            "DEFENSECLAW_TEST_EXE": (
                "—",
                "`unset`",
                "`absolute temporary executable path`, `unset`",
            ),
            "DEFENSECLAW_TEST_MARKER": (
                "—",
                "`unset`",
                "`absolute file path`, `unset`",
            ),
            "DEFENSECLAW_WINDOWS_PROCESS_HELPER": (
                "—",
                "`unset`",
                "`1`, `unset`",
            ),
        }
        doc_paths = (
            _REPO_ROOT / "docs" / "ENV-VARS.md",
            _REPO_ROOT
            / "docs-site"
            / "content"
            / "docs"
            / "reference"
            / "env-vars.mdx",
        )
        for path in doc_paths:
            rows = _doc_rows_by_name(path)
            actual = {
                name: tuple(rows[name][1:4]) for name in expected_doc_cells
            }
            self.assertEqual(actual, expected_doc_cells, path)

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
            if e.category != CATEGORY_SECURITY_OPT_OUT:
                continue
            if e.security_impact == "high":
                self.assertTrue(
                    e.surface_in_doctor,
                    f"{e.name}: high-impact security opt-out must surface_in_doctor",
                )


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


class SchemaValidationInverseTests(unittest.TestCase):
    """``DEFENSECLAW_SCHEMA_VALIDATION`` is special: setting it to
    anything other than ``on`` activates the bypass (this is how the
    Go code reads it, see internal/gateway/sidecar.go:243)."""

    def setUp(self) -> None:
        self.sv = load_registry().get("DEFENSECLAW_SCHEMA_VALIDATION")
        assert self.sv is not None

    def test_unset_is_inactive(self) -> None:
        self.assertFalse(self.sv.is_active({}))

    def test_on_is_inactive(self) -> None:
        # "on" means the default (validation enabled) — therefore NOT
        # an active bypass.
        self.assertFalse(self.sv.is_active({"DEFENSECLAW_SCHEMA_VALIDATION": "on"}))

    def test_off_is_active(self) -> None:
        self.assertTrue(self.sv.is_active({"DEFENSECLAW_SCHEMA_VALIDATION": "off"}))

    def test_any_other_value_is_active(self) -> None:
        # Mirroring Go-side semantics: anything other than "on" or
        # empty disables the gate.
        self.assertTrue(self.sv.is_active({"DEFENSECLAW_SCHEMA_VALIDATION": "false"}))
        self.assertTrue(self.sv.is_active({"DEFENSECLAW_SCHEMA_VALIDATION": "disabled"}))


class ActiveSecurityOverridesTests(unittest.TestCase):
    """Integration-style: simulate operator env, assert active list."""

    def test_pristine_env_has_no_overrides(self) -> None:
        # Build a minimal env without any DEFENSECLAW_* keys.
        env: dict[str, str] = {}
        self.assertEqual(active_security_overrides(env), [])

    def test_disable_redaction_appears(self) -> None:
        env = {"DEFENSECLAW_DISABLE_REDACTION": "1"}
        names = [e.name for e in active_security_overrides(env)]
        self.assertIn("DEFENSECLAW_DISABLE_REDACTION", names)

    def test_two_overrides_returns_two(self) -> None:
        env = {
            "DEFENSECLAW_DISABLE_REDACTION": "1",
            "DEFENSECLAW_CODEX_LOOPBACK_TRUST": "1",
        }
        names = [e.name for e in active_security_overrides(env)]
        self.assertEqual(
            sorted(names),
            sorted(
                [
                    "DEFENSECLAW_DISABLE_REDACTION",
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
