# Spec 007 — Event-history sink-policy projection alignment

## Problem

Managed-enterprise inspection can override the configured observability
redaction profile for one request. The local log pipeline applies that override
before calling the mandatory SQLite event-history writer, but the writer
currently validates the projection only against the statically configured
profile. A legitimate `none` or `sensitive` override is therefore rejected as
`projection_rejected`, preventing the runtime event from being persisted and
from reaching optional destinations.

## Design

The observability redaction package owns one resolver that applies a validated
request-scoped sink policy to an immutable configured profile:

- `default` retains the configured profile.
- `raw` selects the built-in `none` profile.
- `redact` selects the built-in `sensitive` profile.
- Invalid policies or profiles fail closed.

Both the local log pipeline and the event-history writer use this resolver.
The writer continues to prove that the submitted projection belongs to its
exact graph-bound engine, correlation key, detector catalog, and resolved
profile before persisting it. Runtime generation and graph-digest checks remain
unchanged.

## Verification

A real-pipeline integration test uses the production SQLite writer with each
sink-policy mode and verifies the expected profile and projected bytes are
persisted exactly once. Existing writer integrity, pipeline, audit, race, vet,
and build checks cover adjacent behavior.
