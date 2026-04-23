# Decision Receipts

DefenseClaw can optionally produce **signed decision receipts** for every gateway decision (allow, deny, block, quarantine). Each receipt is a small JSON file containing:

- What tool or resource the decision applies to
- What the decision was
- Which policy produced it
- When it happened
- A cryptographic signature proving the receipt has not been tampered with
- A hash chain linking every receipt to its predecessor

Receipts are independently verifiable offline. No vendor API, no network, no trust assumption beyond the signing key.

## Why

SQLite ACID compliance proves "this row was written atomically." A signed receipt proves "this specific decision was made by this specific gateway under this specific policy at this specific moment, and no one has altered it since."

The difference matters when a downstream auditor, regulator, or partner needs to verify your audit trail six months later without trusting your infrastructure.

## Enabling receipts

Add to your DefenseClaw configuration:

```yaml
receipts:
  enabled: true
  output_dir: ./defenseclaw-receipts
  # key_path: /path/to/ed25519-seed.key  # optional; ephemeral key if omitted
```

Or set environment variables:

```bash
export DEFENSECLAW_RECEIPTS_ENABLED=true
export DEFENSECLAW_RECEIPTS_OUTPUT_DIR=./defenseclaw-receipts
```

When enabled, receipt JSON files accumulate in the output directory alongside normal operation. The gateway's performance is not measurably affected (Ed25519 signing is sub-microsecond).

## Receipt format

Each receipt is a JSON file:

```json
{
  "receipt_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "tool_name": "claw:write_file",
  "decision": "deny",
  "policy_id": "defenseclaw-production",
  "timestamp": "2026-04-17T12:34:56.789Z",
  "previous_receipt_hash": "sha256:8f3a9c2d...",
  "agent_id": "agent-openclaw-1",
  "session_id": "sess-abc123",
  "reason": "malicious content detected by Inspect Engine",
  "signature": "ed25519:7b4a...",
  "public_key": "ed25519:cafebabe..."
}
```

### Hash chain

Every receipt includes `previous_receipt_hash`, which is the SHA-256 hash of the previous receipt's canonical (RFC 8785 JCS) form. This creates a tamper-evident chain: modifying, inserting, deleting, or reordering any receipt breaks every downstream hash.

The first receipt in a session has an empty `previous_receipt_hash` (genesis receipt).

### Signature

The `signature` field is an Ed25519 signature over the JCS-canonical form of the receipt payload (all fields except `signature` and `public_key`). The `public_key` field contains the hex-encoded Ed25519 public key for verification.

## Verifying receipts

### Using the reference CLI

```bash
npx @veritasacta/verify defenseclaw-receipts/*.json
```

Exit codes:
- `0` = all receipts valid, chain intact
- `1` = signature or chain verification failed (tamper detected)
- `2` = malformed receipt

### Manual verification (any language)

1. Parse the receipt JSON.
2. Remove the `signature` and `public_key` fields.
3. Serialize the remaining fields using JCS (RFC 8785) canonical form.
4. Verify the Ed25519 signature over the canonical bytes using the public key.
5. For chain verification: serialize the *full* receipt (including signature and public_key) using JCS, compute SHA-256, and confirm it matches the next receipt's `previous_receipt_hash`.

## Format standard

The receipt format conforms to [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) (IETF Internet-Draft). Four independent implementations emit the same format:

- **protect-mcp** (TypeScript, MCP hosts)
- **protect-mcp-adk** (Python, Google ADK)
- **sb-runtime** (Rust, OS sandbox)
- **APS governance hook** (Python, CrewAI / LangChain)

DefenseClaw receipts are cross-verifiable with receipts from any of these implementations using the same `@veritasacta/verify` CLI.

## Security considerations

- **Key management**: In production, provide a persistent Ed25519 key via `key_path`. Ephemeral keys (the default) are suitable for development but produce receipts that cannot be verified after a gateway restart.
- **Output directory**: Protect the receipt output directory with appropriate filesystem permissions. Receipts contain decision metadata (tool names, policy IDs, timestamps) that may be sensitive.
- **Clock accuracy**: Receipt timestamps come from the system clock. NTP synchronization is recommended for cross-system correlation.

## Future extensions

The receipt schema is designed for forward compatibility. The following fields are reserved for future use and can be added without breaking existing verifiers:

- `policy_digest`: SHA-256 hash of the policy content at evaluation time
- `delegation_chain_root`: hash of the agent's authority delegation chain
- `co_signature`: optional secondary signature from the agent's delegation-bearing key
