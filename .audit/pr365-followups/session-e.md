# PR #365 Follow-up Session E

## Changed Files

- `cli/defenseclaw/tui/app.py`
- `cli/defenseclaw/tui/panels/setup.py`
- `cli/defenseclaw/tui/services/setup_state.py`
- `cli/defenseclaw/tui/services/overview_state.py`
- `cli/defenseclaw/tui/services/catalog_state.py`
- `cli/tests/tui/test_app_shell.py`
- `cli/tests/tui/test_setup_panel.py`
- `cli/tests/tui/test_overview_panel.py`
- `cli/tests/tui/test_catalog_panels.py`
- `docs/CLI.md`
- `docs/INSTALL.md`
- `docs/CONNECTOR-MATRIX.md`
- `docs/CONFIG_FILES.md`
- `docs-site/content/docs/setup/mcp-scanner.mdx`
- `CHANGELOG.md`
- `cli/defenseclaw/inventory/ai_signatures.json`
- `internal/inventory/ai_signatures.json`
- `cli/tests/test_ai_signatures.py`
- `.audit/pr365-followups/session-e.md`

## Tests Run

- `uv run pytest -q cli/tests/tui/test_setup_panel.py cli/tests/tui/test_overview_panel.py cli/tests/tui/test_catalog_panels.py cli/tests/tui/test_app_shell.py`
  - Result: 268 passed, 5 pytest unraisable asyncio subprocess cleanup warnings.
- `uv run pytest -q cli/tests/tui/test_app_shell.py cli/tests/tui/test_setup_panel.py cli/tests/tui/test_overview_panel.py cli/tests/tui/test_catalog_panels.py cli/tests/test_ai_signatures.py cli/tests/test_claw_inventory.py`
  - Result: 441 passed, 5 pytest unraisable asyncio subprocess cleanup warnings.
- `uv run pytest -q cli/tests/test_cmd_mcp.py cli/tests/test_connector_paths.py`
  - Result: 136 passed.

## Unresolved Questions

- Whether Antigravity direct CLI markdown skills under `~/.gemini/antigravity-cli/skills/` should ever become write targets remains deferred to the maintainer decision in `docs/development/antigravity-mcp-contract.md`.
- Whether DefenseClaw should install/disable Antigravity plugins through `agy plugin` remains deferred; this session kept plugins discovery/scan-only.

## Risks

- Setup connector filtering now narrows the readiness rows and shows scope, but it does not remap config-editor row indexes to hide non-selected connector override groups. That avoids cursor/edit instability but leaves the full config editor visible.
- The historical site page for the dedicated Antigravity connector is outside this session's allowed file list and still needs a future pass if it is part of PR #365's published docs set.

## Docs Intentionally Left Untouched

- `RELEASE_NOTES_0.3.0.md` was left untouched because PR #365 follow-up work is not part of the old 0.3.0 release note set.
- `docs-site/content/docs/connectors/antigravity.mdx` and generated site data were left untouched because they were outside the allowed file list for this wave.
