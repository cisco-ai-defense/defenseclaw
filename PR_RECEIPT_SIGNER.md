# feat: add optional Ed25519-signed decision receipts

## Summary

Adds an optional receipt-signing component to the DefenseClaw gateway. When enabled (`receipts.enabled: true`), every audit event produces a hash-chained, Ed25519-signed decision receipt that is independently verifiable offline. Receipt hashes are also stamped back onto the `audit_events` SQLite table so existing queries and dashboards can correlate audit rows with their cryptographic proof.

**This is a strictly additive change.** Receipt signing is off by default; all existing behavior is preserved. Zero new external Go dependencies.

Closes #115.

## What this adds

### New package: `internal/receipt/`

| File | Purpose |
|------|---------|
| `receipt.go` | `Receipt` struct and `Config` type |
| `signer.go` | Ed25519 signing, JCS canonicalization (RFC 8785), SHA-256 chain hashing, file output |
| `signer_test.go` | 8 tests: key gen, signature verification, chain integrity, tamper detection, JCS determinism, file output, concurrent safety |

### Modified: `internal/audit/logger.go`

- `SetReceiptSigner(*receipt.Signer)` method (same pattern as `SetSinks`, `SetStructuredEmitter`)
- `emitReceipt()` helper: signs events after existing fan-out, stamps `receipt_hash` back onto the SQLite row
- `snapshot()` updated to include the receipt signer (4th return value)

### Modified: `internal/audit/store.go`

- `ReceiptHash` field on `Event` struct
- `SetReceiptHash(eventID, hash)` method for post-signing correlation
- **Migration 11**: adds `receipt_hash TEXT` column to `audit_events`

### Modified: `internal/config/config.go`

- `ReceiptConfig` type and `Receipts` field on `Config`

### Modified: `internal/cli/root.go`

- `initReceipts()` function (same lifecycle pattern as `initOTelProvider`, `initAuditSinks`)

### New: `docs/receipts.md`

User-facing documentation: what receipts are, how to enable, how to verify, format standard, security considerations.

## Enabling receipts

```yaml
receipts:
  enabled: true
  output_dir: ./defenseclaw-receipts
  # key_path: /path/to/ed25519-seed.key  # optional; raw 32-byte seed, 64-char hex seed, or 64-byte Go key
```

Or via environment: `DEFENSECLAW_RECEIPTS_ENABLED=true`

## How it composes with SQLite

Receipt signing augments, not replaces, SQLite ACID. The relationship:

| Layer | What it proves | Where it lives |
|-------|---------------|----------------|
| SQLite ACID | Row was written atomically | `audit_events` table (existing) |
| Receipt signature | Row content has not been altered since signing | Receipt JSON file (new) |
| `receipt_hash` column | Which audit row maps to which receipt | `audit_events.receipt_hash` (new, migration 11) |

An operator can query `SELECT * FROM audit_events WHERE receipt_hash IS NOT NULL` to see which events have cryptographic proof. An external auditor can verify the receipt chain without accessing the SQLite database at all.

## Design decisions

1. **Follows the existing Logger fan-out pattern.** Installed via setter, snapshotted under the existing RWMutex. No new locking primitives.
2. **Non-blocking.** Receipt signing errors log to stderr but do not block the audit pipeline.
3. **Receipt canonicalization.** Signed over deterministic canonical JSON for the emitted receipt schema subset so verifiers can reconstruct the exact signable bytes.
4. **Cross-verifiable target.** Format is designed to align with `draft-farley-acta-signed-receipts`; the PR includes a persisted receipt verification test so downstream verifier fixtures have a concrete target shape.
5. **Forward-compatible schema.** Optional fields (`delegation_chain_root`, `co_signature`) can be populated in future versions without breaking existing verifiers.

## Testing

```bash
go test ./internal/receipt/... -v     # 8 tests, all pass
go test ./internal/audit/... -v       # existing audit tests, all pass
go build ./...                        # clean build, zero warnings
```

## Receipt example

```json
{
  "receipt_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "tool_name": "claw:write_file",
  "decision": "deny",
  "policy_id": "defenseclaw-production",
  "timestamp": "2026-04-17T12:34:56.789Z",
  "previous_receipt_hash": "sha256:8f3a9c2d...",
  "signature": "ed25519:7b4a...",
  "public_key": "ed25519:cafebabe..."
}
```

## Verification

```bash
npx @veritasacta/verify defenseclaw-receipts/*.json
# Exit 0 = valid, 1 = tampered, 2 = malformed
```
