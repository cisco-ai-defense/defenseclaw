# Tasks

- [x] Reproduce the failure with the real SQLite event-history writer.
- [x] Implement shared sink-policy profile resolution.
- [x] Align pipeline and writer validation, including projection-failure health
  records.
- [x] Verify focused and adjacent Go packages.
- [x] Record completion and verification in this spec.

## Verification result

- The real SQLite regression failed before the fix for both `raw` and `redact`
  with `local_write_failed`, while `default` passed.
- All three modes persist exactly once with their expected projected bytes
  after the fix.
- Affected package tests and vet pass.
- Full Go build and vet pass.
- Focused race tests pass for the shared resolver and real SQLite regression.
