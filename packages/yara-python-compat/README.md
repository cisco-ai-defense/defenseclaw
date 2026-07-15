# DefenseClaw yara-python compatibility adapter

This package is selected only for the native Windows CPython 3.14 payload.
VirusTotal does not publish a CPython 3.14 Windows wheel for `yara-python`,
while the pinned Cisco AI MCP Scanner 4.3.0 imports a narrow part of that API.

The adapter delegates compilation and matching to VirusTotal's YARA-X and
implements only the MCP Scanner surface: `compile(sources=...)`, `Rules.match`,
`Match.rule`, `Match.namespace`, `Match.tags`, `Match.meta`, and `Error`.
It is not a general replacement for `yara-python`.
