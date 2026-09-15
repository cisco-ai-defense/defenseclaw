# Implementation plan

1. Add real SQLite integration coverage reproducing request-scoped projection
   rejection.
2. Centralize sink-policy profile resolution in the observability redaction
   package.
3. Use the shared resolver in both the pipeline and event-history writer.
4. Run focused tests, race tests, vet, and build checks; record the result.

## Top-level doc impact

- readme: already-correct
- architecture: already-correct
- adr-readme: not-applicable
- specs-readme: already-correct
- cp-dp-schema-workbench: not-applicable
- rationale: No component, schema, storage ownership, or cross-service contract changes.
