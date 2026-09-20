# Plugin scanner development

This file documents repository ownership for the plugin scanner. Current
operator commands are maintained in the
[published CLI reference](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/cli/).

| Area | Source |
| --- | --- |
| CLI registration, target resolution, install, and policy actions | [`../cli/defenseclaw/commands/cmd_plugin.py`](../cli/defenseclaw/commands/cmd_plugin.py) |
| Python scanner wrapper | [`../cli/defenseclaw/scanner/plugin.py`](../cli/defenseclaw/scanner/plugin.py) |
| Python scanner implementation | [`../cli/defenseclaw/scanner/plugin_scanner/`](../cli/defenseclaw/scanner/plugin_scanner/) |
| Go subprocess wrapper and normalized result mapping | [`../internal/scanner/plugin.go`](../internal/scanner/plugin.go) |
| Scanner policies | [`../policies/scanners/plugin-scanner/`](../policies/scanners/plugin-scanner/) |
| Minimal Go example | [`../plugins/examples/custom-scanner/`](../plugins/examples/custom-scanner/) |

The Go wrapper invokes either a configured standalone
`defenseclaw-plugin-scanner` binary or `defenseclaw plugin scan --json`, then
maps non-suppressed findings into the shared scanner model. The Python wrapper
runs the repository scanner implementation in process. Changes to JSON output,
policy/profile options, suppression, or exit behavior must update both wrappers
and their tests.

The example package is intentionally only a compilable scaffold; it prints a
message and does not implement a scanner protocol.
