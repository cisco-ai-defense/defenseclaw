# PR 365 Follow-Up: Python CLI / Policy

Branch: `codex/pr365-python-cli-policy`

Changed files:
- `cli/defenseclaw/commands/cmd_mcp.py`
- `cli/defenseclaw/commands/cmd_doctor.py`
- `cli/defenseclaw/commands/cmd_plugin.py`
- `cli/defenseclaw/commands/cmd_skill.py`
- `cli/defenseclaw/commands/cmd_setup.py`
- `cli/defenseclaw/enforce/policy.py`
- `cli/defenseclaw/enforce/admission.py`
- `cli/tests/test_admission.py`
- `cli/tests/test_cmd_doctor.py`
- `cli/tests/test_cmd_mcp.py`
- `cli/tests/test_cmd_plugin.py`
- `cli/tests/test_cmd_setup_fu_phase2.py`
- `cli/tests/test_cmd_skill.py`
- `cli/tests/test_plugin_skill_per_connector.py`
- `.audit/pr365-followups/session-a.md`

Implemented:
- `mcp scan --all` now uses the plural connector resolver before any singular active-connector fallback, so a zero-connector config exits with the existing setup guidance instead of scanning phantom `openclaw`.
- Doctor connector residue warnings now point directly to `defenseclaw-gateway connector teardown --connector <name>` and no longer describe `doctor --fix` as invoking teardown.
- Python connector-scoped policy reads now resolve install/file actions with most-specific-wins semantics.
- Asset admission now checks connector-scoped deny, connector-scoped allow, global deny, then global allow.
- Bare `plugin allow` now uses `active_connector()` for runtime candidate lookup instead of reading `guardrail.connector or "openclaw"`.
- `skill quarantine --connector X` records connector-scoped quarantine and source path rows.
- `skill scan --connector X` honors connector-scoped allow/block checks and `--action` writes connector-scoped enforcement rows.
- `setup guardrail --connector X` writes targeted mode, block message, rule pack, and HILT fields to an existing connector override.

Tests run:
- `python3 -m py_compile cli/defenseclaw/enforce/policy.py cli/defenseclaw/enforce/admission.py cli/defenseclaw/commands/cmd_mcp.py cli/defenseclaw/commands/cmd_doctor.py cli/defenseclaw/commands/cmd_plugin.py cli/defenseclaw/commands/cmd_skill.py cli/defenseclaw/commands/cmd_setup.py cli/tests/test_admission.py cli/tests/test_cmd_mcp.py cli/tests/test_cmd_doctor.py cli/tests/test_cmd_plugin.py cli/tests/test_cmd_skill.py cli/tests/test_plugin_skill_per_connector.py cli/tests/test_cmd_setup_fu_phase2.py`
- `uv run pytest -q cli/tests/test_admission.py cli/tests/test_plugin_skill_per_connector.py cli/tests/test_cmd_mcp.py cli/tests/test_cmd_doctor.py cli/tests/test_cmd_plugin.py cli/tests/test_cmd_skill.py cli/tests/test_cmd_setup_fu_phase2.py` -> 473 passed.
- `uv run pytest -q cli/tests/test_cmd_mcp.py cli/tests/test_cmd_doctor.py cli/tests/test_cmd_doctor_connector.py cli/tests/test_admission.py cli/tests/test_cmd_skill.py cli/tests/test_cmd_plugin.py cli/tests/test_plugin_skill_per_connector.py cli/tests/test_cmd_setup_multi_connector.py cli/tests/test_cmd_setup_fu_phase2.py cli/tests/test_guardrail.py` -> 687 passed.

Unresolved questions:
- None.

Risk:
- Low. Changes are scoped to Python CLI/policy paths and are covered by targeted connector-scope regressions.
