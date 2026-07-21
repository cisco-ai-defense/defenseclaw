"""CI gate: every ``DEFENSECLAW_*`` callsite in the codebase MUST be
declared in ``internal/envvars/registry.json``.

This test bakes a repo-wide audit into CI so any new env-var reference
added to the codebase fails the build unless the contributor also
adds a registry entry.

How it works
------------
1. Walk the repository starting at the repo root.
2. Skip vendored dirs (``node_modules``, ``vendor``, ``.venv``,
   build outputs, dotfile dirs, etc.).
3. For every source file (Go / Python / TypeScript / shell / YAML /
   Dockerfile / extensionless shebang script / docs), regex-extract every token matching
   ``DEFENSECLAW_[A-Z0-9_]+``.
4. Build the union of all extracted names.
5. Compare to ``set(registry.names())``.
   * Names referenced in the code but not in the registry → fail.
   * Names declared in the registry but never referenced anywhere →
     warn (printed as informational; does not fail). Some entries are
     deliberately documentation-only (e.g. test placeholders).

False-positive handling
-----------------------
Code that talks ABOUT env vars (registry.json itself, env-vars.mdx,
ENV-VARS.md, this very test, the doctor check, the doc generator, the
registry modules) is allow-listed via path. Comments referencing env
vars in other source files are *not* allow-listed — they're considered
real references and contribute to the union.
"""

from __future__ import annotations

import os
import re
import unittest
from pathlib import Path

from defenseclaw.envvars import load_registry

_REPO_ROOT = Path(__file__).resolve().parents[2]

# Directories to skip wholesale. Each entry is checked against any
# path component, so "node_modules" anywhere in the tree is skipped.
# Note: any directory whose name starts with "." is also skipped
# unconditionally by the dotfile-prune in os.walk below; we don't need
# to enumerate dotfile dirs here.
_SKIP_DIRS = frozenset(
    {
        "venv",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "out",
        "target",
        "__pycache__",
        "_data",
        "agent-transcripts",
    }
)

# File extensions we scan. Anything else is ignored.
_SCAN_EXTS = frozenset(
    {
        ".go",
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".mjs",
        ".sh",
        ".bash",
        ".yaml",
        ".yml",
        ".toml",
        ".md",
        ".mdx",
        ".json",
    }
)

_SCAN_FILENAMES = frozenset({"Dockerfile", "Makefile"})

# Files / dirs that DEFINE / DOCUMENT env vars (allowlist). References
# inside these don't have to be backed by an entry in the registry —
# the file itself is the registry, the docs page, this test, or the
# doctor surface.
_ALLOWLIST_PATHS: tuple[str, ...] = (
    # Single source of truth and its loaders.
    "internal/envvars/registry.json",
    "internal/envvars/registry.go",
    "internal/envvars/registry_test.go",
    "cli/defenseclaw/envvars.py",
    "cli/tests/test_envvars.py",
    "cli/tests/test_envvars_codebase_coverage.py",
    # Generators and rendered docs.
    "scripts/gen_envvars_docs.py",
    "docs/ENV-VARS.md",
    "docs-site/content/docs/reference/env-vars.mdx",
    # Historical-upgrade harness fixture names model environment entries that
    # the later v8 migration will generate. They are test data, not bridge
    # runtime inputs, so the v7 bridge registry must not advertise them.
    "scripts/test-upgrade-release.sh",
    "scripts/test-developer-target-activation.sh",
    "cli/tests/test_upgrade_release_smoke_contract.py",
    # Configuration docs that explicitly mention env vars users SOMETIMES
    # try to set (DEFENSECLAW_DATA_DIR, DEFENSECLAW_LOG_LEVEL, ...) but
    # which DefenseClaw does NOT honor. These pages tell users to use
    # config.yaml instead — they reference the names solely to clarify
    # "this is not an env var". Not real consumers.
    "docs/CONFIG_FILES.md",
    "docs-site/content/docs/reference/configuration.mdx",
    # Fail-modes diagram embeds env-var names in JSX strings that span
    # lines (e.g. `DEFENSECLAW_STRICT\n_AVAILABILITY=1?`); the line-
    # splitting trips the regex. The values are explained in the
    # registry-backed env-vars page.
    "docs-site/content/docs/reference/fail-modes.mdx",
    # Design docs that describe future / possible env vars.
    "docs/design/openshell-standalone-sandbox.md",
    # Parity spec describing the Python<->Go TUI backend selector
    # (DEFENSECLAW_TUI_BACKEND) as a design knob, not a shipped env var.
    "docs/design/python-textual-tui-parity-spec.md",
    # Test fixtures that use synthetic env-var names as labels for
    # --auth-env / --token-env flags. The labels are example operator
    # configuration, not env vars DefenseClaw itself reads.
    "cli/tests/test_cmd_registry.py",
    "cli/tests/test_cmd_keys.py",
    # TUI agent-TTY smoke harness: DEFENSECLAW_AGENT_TTY_TESTS /
    # DEFENSECLAW_AGENT_TTY_BIN gate and parameterize a test-only PTY
    # smoke check. Never read by shipped code.
    "cli/tests/tui/test_agent_tty_smoke.py",
    # End-to-end harness scripts (developer-run, not shipped). They define
    # DEFENSECLAW_E2E_* knobs to drive throwaway stacks against real
    # providers; none are consumed by the gateway or CLI at runtime.
    "scripts/test-e2e-bedrock-region.sh",
    "scripts/test-e2e-custom-provider.sh",
    "scripts/test-e2e-full-stack.sh",
    # Release, race, compiler, and live-observability test fixtures use
    # synthetic DEFENSECLAW_* names as sentinels or opt-in test controls.
    # They are not supported runtime configuration and must not inflate the
    # product environment-variable registry.
    "internal/netguard/netguard_v8_test.go",
    "internal/observability/family_builder_static_test.go",
    "internal/observability/integration/galileo_canonical_trace_test.go",
    "internal/gateway/local_observability_golden_test.go",
    "cli/tests/test_cmd_setup_trusted_paths.py",
    "cli/tests/test_observability_v8_activation.py",
    "cli/tests/test_render_telemetry_go.py",
    "cli/tests/test_upgrade_release_smoke_contract.py",
    "scripts/test-upgrade-release.sh",
    # Test-only parent/child subprocess sentinels used by Go helper
    # processes; they are not operator configuration and must not be
    # published as such.
    "internal/gateway/connector/otlp_token_test.go",
    "internal/observability/redaction/key_store_windows_test.go",
    # Docs-site policy-creator quick-start: an illustrative apply.ts
    # snippet mentions DEFENSECLAW_LOG as an example client-side toggle;
    # it is sample documentation, not a var DefenseClaw reads.
    "docs-site/components/policy-creator/quick-start/apply.ts",
)

# Match DEFENSECLAW_FOO and MIGRATION_DEFENSECLAW_HOME. The trailing
# negative-lookahead avoids matching things like
# DEFENSECLAW_SOMETHING_${var} which are template fragments.
_ENV_TOKEN = re.compile(r"\b(MIGRATION_)?DEFENSECLAW_[A-Z][A-Z0-9_]*\b")

# Tokens that look like env vars but are actually CONSTANT NAMES or
# HEADER NAMES in code (the registry uses the runtime env-var names, not
# the symbolic constants the codebase wraps them in). Excluding these
# avoids false positives without weakening coverage.
_NON_ENVVAR_TOKENS = frozenset(
    {
        # Correlation header constants (X-DefenseClaw-* uppercased).
        # Defined in extensions/defenseclaw/src/correlation-headers.ts.
        # The HEADER_DEFENSECLAW_* symbols are TypeScript constants
        # whose VALUES are HTTP headers (e.g. "X-DefenseClaw-Run-Id"),
        # not env vars. We don't want them in the env-var registry.
        "HEADER_DEFENSECLAW_AGENT_ID",
        "HEADER_DEFENSECLAW_AGENT_INSTANCE_ID",
        "HEADER_DEFENSECLAW_AGENT_NAME",
        "HEADER_DEFENSECLAW_POLICY_ID",
        "HEADER_DEFENSECLAW_RUN_ID",
        "HEADER_DEFENSECLAW_SESSION_ID",
        "HEADER_DEFENSECLAW_SIDECAR_INSTANCE_ID",
        "HEADER_DEFENSECLAW_TRACE_ID",
        "HEADER_DEFENSECLAW_CLIENT",
        # Public constant names exported by the JS correlation module.
        "DEFENSECLAW_CORRELATION_HEADER_NAMES",
    }
)

# Private environment-variable families whose concrete names are created at
# runtime and therefore cannot be represented as exact registry entries. Keep
# this name+path mapping exact: a new dynamic family or a new consumer must be
# reviewed rather than disappearing behind the old generic trailing-underscore
# exemption.
_DYNAMIC_ENVVAR_PREFIX_PATHS: dict[str, frozenset[str]] = {
    "DEFENSECLAW_CLAWHUB_ARG_": frozenset({"cli/defenseclaw/commands/cmd_skill.py"}),
    "DEFENSECLAW_FAIL_MODE_": frozenset({"internal/cli/hook.go"}),
    "DEFENSECLAW_LOCAL_": frozenset({"internal/cli/daemon.go"}),
    "DEFENSECLAW_MIGRATED_": frozenset(
        {
            "cli/defenseclaw/observability/v8_migration.py",
            "cli/tests/test_observability_v8_migration.py",
        }
    ),
    "DEFENSECLAW_OTEL_": frozenset(
        {
            "cli/defenseclaw/observability/v8_migration.py",
            "docs/OBSERVABILITY.md",
            "docs/OTEL.md",
            "docs-site/content/docs/observability/index.mdx",
            "internal/config/config.go",
            "internal/config/config_test.go",
        }
    ),
    "DEFENSECLAW_TEST_LLM_KEY_": frozenset({"internal/gateway/passthrough_hydration_test.go"}),
}


def _is_skipped_path(rel: Path) -> bool:
    parts = set(rel.parts)
    if parts & _SKIP_DIRS:
        return True
    return False


def _is_allowlisted_path(rel: Path) -> bool:
    rel_posix = rel.as_posix()
    return any(rel_posix.endswith(a) for a in _ALLOWLIST_PATHS)


def _is_scannable_source(path: Path) -> bool:
    if path.suffix.lower() in _SCAN_EXTS or path.name in _SCAN_FILENAMES:
        return True
    if path.suffix:
        return False
    try:
        with path.open("rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


def _is_allowlisted_dynamic_prefix(token: str, rel: Path) -> bool:
    paths = _DYNAMIC_ENVVAR_PREFIX_PATHS.get(token)
    return paths is not None and rel.as_posix() in paths


def _extract_envvar_references(
    repo_root: Path,
    *,
    apply_dynamic_prefix_allowlist: bool = True,
) -> dict[str, list[str]]:
    """Walk the repo and collect every distinct ``DEFENSECLAW_*`` token
    referenced from non-allow-listed source files.

    Returns ``{name: [file:line, ...]}``.
    """
    refs: dict[str, list[str]] = {}
    for root, dirs, files in os.walk(repo_root):
        # Prune skipped directories in-place so os.walk doesn't recurse.
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in files:
            full = Path(root) / fn
            if not _is_scannable_source(full):
                continue
            try:
                rel = full.relative_to(repo_root)
            except ValueError:
                continue
            if _is_skipped_path(rel):
                continue
            if _is_allowlisted_path(rel):
                continue
            try:
                with open(full, encoding="utf-8", errors="replace") as fh:
                    for lineno, line in enumerate(fh, start=1):
                        for match in _ENV_TOKEN.finditer(line):
                            token = match.group(0)
                            # Filter constant names that LOOK like env
                            # vars but aren't.
                            if token in _NON_ENVVAR_TOKENS:
                                continue
                            if apply_dynamic_prefix_allowlist and _is_allowlisted_dynamic_prefix(token, rel):
                                continue
                            refs.setdefault(token, []).append(f"{rel.as_posix()}:{lineno}")
            except OSError:
                continue
    return refs


class CodebaseCoverageTests(unittest.TestCase):
    """Every DEFENSECLAW_* reference must be declared in the registry."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry()
        cls.declared = cls.registry.names()
        cls.refs = _extract_envvar_references(_REPO_ROOT)

    def test_no_undeclared_envvar_references(self) -> None:
        referenced = set(self.refs.keys())
        undeclared = sorted(referenced - self.declared)
        if not undeclared:
            return
        msg_lines = [
            "Found DEFENSECLAW_* references in the codebase that are not declared in internal/envvars/registry.json:",
            "",
        ]
        for name in undeclared:
            sample = self.refs[name][:3]
            msg_lines.append(f"  {name}")
            for loc in sample:
                msg_lines.append(f"    - {loc}")
        msg_lines += [
            "",
            "Either:",
            "  1) Add an entry to internal/envvars/registry.json (use the "
            "test_fixture category for real test-only controls), or",
            "  2) Add the path to _ALLOWLIST_PATHS only if the file "
            "is a registry / doc / generator that documents env vars rather "
            "than reading them.",
        ]
        self.fail("\n".join(msg_lines))

    def test_test_only_entries_are_explicitly_scoped(self) -> None:
        expected = {
            "DEFENSECLAW_TEST_COMMAND",
            "DEFENSECLAW_TEST_EXE",
            "DEFENSECLAW_TEST_MARKER",
            "DEFENSECLAW_WINDOWS_PROCESS_HELPER",
        }
        for name in expected:
            with self.subTest(name=name):
                entry = self.registry.get(name)
                self.assertIsNotNone(entry)
                assert entry is not None
                self.assertEqual(entry.category, "test_fixture")
                self.assertEqual(entry.security_impact, "none")
                self.assertFalse(entry.surface_in_doctor)

    def test_dynamic_prefix_allowlist_matches_exact_call_sites(self) -> None:
        raw_refs = _extract_envvar_references(
            _REPO_ROOT,
            apply_dynamic_prefix_allowlist=False,
        )
        for prefix, expected_paths in _DYNAMIC_ENVVAR_PREFIX_PATHS.items():
            with self.subTest(prefix=prefix):
                actual_paths = {location.rsplit(":", 1)[0] for location in raw_refs.get(prefix, [])}
                self.assertEqual(actual_paths, expected_paths)

    def test_no_orphan_registry_entries(self) -> None:
        """Informational: warn (but don't fail) on registry entries that
        nothing in the codebase references.

        We intentionally don't fail here — some entries are legitimately
        documentation-only (test placeholders, future-use vars). But we
        want a heads-up so the registry doesn't grow stale.
        """
        referenced = set(self.refs.keys())
        orphans = sorted(self.declared - referenced)
        if orphans:
            # Print but don't fail. The CI gate is the
            # ``no_undeclared`` test above.
            import sys

            print(
                "\n[info] Registry entries without any non-allow-listed codebase references:",
                file=sys.stderr,
            )
            for name in orphans:
                print(f"  {name}", file=sys.stderr)


class CoverageExtractionTests(unittest.TestCase):
    def test_extensionless_shebang_script_is_scanned(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "bridge"
            script.write_text(
                '#!/usr/bin/env sh\necho "$DEFENSECLAW_EXTENSIONLESS_FIXTURE"\n',
                encoding="utf-8",
            )
            refs = _extract_envvar_references(root)

        self.assertEqual(
            refs["DEFENSECLAW_EXTENSIONLESS_FIXTURE"],
            ["bridge:2"],
        )

    def test_unknown_dynamic_prefix_is_not_silently_ignored(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "fixture.py"
            source.write_text("name = 'DEFENSECLAW_UNKNOWN_'\n", encoding="utf-8")
            refs = _extract_envvar_references(root)

        self.assertEqual(refs["DEFENSECLAW_UNKNOWN_"], ["fixture.py:1"])


class RegistryAndDocsInSyncTests(unittest.TestCase):
    """Run the canonical generator check for the bundle and both docs."""

    def test_docs_in_sync_with_registry(self) -> None:
        import subprocess
        import sys

        script = _REPO_ROOT / "scripts" / "gen_envvars_docs.py"
        self.assertTrue(script.is_file(), "scripts/gen_envvars_docs.py missing")
        result = subprocess.run(
            [sys.executable, str(script), "--check"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            self.fail(
                f"env-var generated artifacts are out of date. Regenerate with "
                f"`python scripts/gen_envvars_docs.py`.\nstderr:\n{result.stderr}"
            )


if __name__ == "__main__":
    unittest.main()
