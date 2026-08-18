# DefenseClaw yara-python compatibility adapter

This package is selected only for DefenseClaw's native Windows payload. It
keeps the packaged MCP Scanner on a small, deterministic YARA-X-backed API
surface instead of loading host-provided YARA binaries.

The adapter delegates compilation and matching to VirusTotal's YARA-X and
implements only the MCP Scanner surface: `compile(sources=...)`, `Rules.match`,
`Match.rule`, `Match.namespace`, `Match.tags`, `Match.meta`, and `Error`.
It is not a general replacement for `yara-python`.
