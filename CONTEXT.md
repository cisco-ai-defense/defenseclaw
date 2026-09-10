# CONTEXT.md — Running Change Summaries

> Running branch context. Add compact summary entries — do not use as a changelog.

## Entries

### 2026-09-10 — Align event-history sink-policy projection validation

#### Summary

Fixed managed-enterprise runtime events being rejected by mandatory SQLite
when a per-inspection redaction directive selected a profile different from the
compiled local default. Projection creation and trusted persistence validation
now share one fail-closed profile resolver.

#### Key areas

- `internal/observability/redaction/`: shared immutable profile resolution.
- `internal/observability/pipeline/`: producer and projection-failure handling.
- `internal/audit/`: graph-bound SQLite projection validation.
- `docs/specs/007-event-history-sink-policy/`: design and verification record.

#### Decisions / invariants

- `default` retains the configured profile; `raw` selects `none`; `redact`
  selects `sensitive`.
- The writer still verifies the exact engine, key, catalog, profile
  fingerprint, and canonical record correspondence.
- Invalid policies and profiles remain fail-closed; compiled plans remain
  immutable and request isolation is unchanged.

#### Verification

- Reproduced the pre-fix `local_write_failed` with the production SQLite writer.
- Affected package tests and vet passed.
- Full Go build and vet passed.
- Focused race coverage passed for the resolver and real SQLite persistence.
