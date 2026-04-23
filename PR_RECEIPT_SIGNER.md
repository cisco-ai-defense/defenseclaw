# feat: add optional Ed25519-signed decision receipts

## Summary

Adds an optional receipt-signing component to the DefenseClaw gateway. When enabled, every audit event produces a hash-chained, Ed25519-signed decision receipt that is independently verifiable offline.

**This is a strictly additive change.** Receipt signing is off by default; all existing behavior is preserved. Zero new external Go dependencies (Ed25519 and SHA-256 are in Go stdlib; `google/uuid` is already in `go.mod`).

Closes #115.

## What this adds

### New package: `internal/receipt/`

| File | Purpose |
|------|---------|
| `receipt.go` | `Receipt` struct and `Config` type |
| `signer.go` | Ed25519 signing, JCS canonicalization (RFC 8785), SHA-256 chain hashing, file output |
| `signer_test.go` | 8 tests: key gen, signature verification, chain integrity, tamper detection, JCS determinism, file output, concurrent safety |

### Modified: `internal/audit/logger.go`

- Added `SetReceiptSigner(*receipt.Signer)` method (same pattern as `SetSinks`, `SetStructuredEmitter`, `SetGatewayLogWriter`)
- Added `emitReceipt()` helper that signs events after existing fan-out
- Updated `snapshot()` to include the receipt signer (4th return value)
- All existing `snapshot()` call sites updated to accept the new return value

### New: `docs/receipts.md`

User-facing documentation: what receipts are, how to enable, how to verify, format standard, security considerations.

## Design decisions

1. **Follows the existing Logger fan-out pattern.** The receipt signer is installed via a setter method and snapshotted under the existing RWMutex, exactly like sinks, OTel, and the structured emitter. No new locking primitives.

2. **Non-blocking.** Receipt signing errors are logged to stderr but do not block the audit pipeline. A failed receipt does not prevent the event from reaching SQLite, sinks, or OTel.

3. **JCS canonicalization (RFC 8785).** Receipts are signed over the deterministic JSON serialization, not the formatted output. This guarantees that re-serialization in any language produces the same bytes for verification.

4. **Cross-verifiable.** Receipts verify with `npx @veritasacta/verify defenseclaw-receipts/*.json`. The format conforms to `draft-farley-acta-signed-receipts` and is compatible with four existing independent implementations.

5. **Forward-compatible schema.** The `Receipt` struct reserves optional fields (`policy_digest`, `delegation_chain_root`, `co_signature`) that can be populated in future versions without breaking existing verifiers.

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
