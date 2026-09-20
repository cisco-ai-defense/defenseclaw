# v7 golden event fixtures

This directory preserves frozen schema-v7 event envelopes. They are
compatibility fixtures, not current config-v8 telemetry authoring sources.
Current telemetry ownership is documented in
[`schemas/README.md`](../../../../../schemas/README.md).

The top-level JSON files are the connector-agnostic historical corpus.
Connector-named subdirectories exist for every connector returned by the E2E
`connectorMatrix`.

The active layout contract is
[`test/e2e/v7_golden_per_connector_layout_test.go`](../../../v7_golden_per_connector_layout_test.go).
It requires each connector directory to contain a valid
`verdict-blocked.golden.json` with `event_type: verdict`. It intentionally
checks layout and JSON shape only; it does not replay every retained envelope
through the current runtime.

Update a fixture only when changing the compatibility test that consumes it.
Do not regenerate these v7 snapshots as a side effect of a v8 telemetry change.
