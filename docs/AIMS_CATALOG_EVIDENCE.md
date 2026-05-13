# Runtime catalog and decision evidence enrichment

This PR ports two AIMS ideas into DefenseClaw without changing default enforcement semantics:

1. A runtime resource catalog that maps tool/action targets to authoritative metadata such as owner, sensitivity domain, PII fields, allowed agents/scopes, and human-approval requirements.
2. A normalized decision-evidence envelope that lets native UIs, audit logs, and Galileo Agent Control reason about the same runtime decision record.

## Enablement

The catalog is optional. With no environment variables set, DefenseClaw behaves as before.

```bash
export DEFENSECLAW_RUNTIME_CATALOG_FILE=/path/to/runtime-catalog.json
# or
export DEFENSECLAW_RUNTIME_CATALOG_URL=https://catalog.example.internal

# Optional: emit evidence even when no catalog is configured.
export DEFENSECLAW_DECISION_EVIDENCE=1
```

Static catalog JSON supports either a top-level array or a wrapper object:

```json
{
  "resources": [
    {
      "resource_id": "database:customers",
      "owner": "data-team",
      "sensitivity_domain": "customer_pii",
      "pii_fields": ["email", "phone", "ssn"],
      "allowed_agents": ["incident-triage-agent"],
      "allowed_scopes": ["read", "query"],
      "requires_approval": false
    }
  ]
}
```

The HTTP catalog path follows the AIMS pattern:

```http
GET /metadata_catalog?resource_type=database&resource_path=customers
```

## Runtime effects

For tool inspections, DefenseClaw infers the resource from common tool arguments such as `resource_id`, `resource_type`/`resource_path`, `query`, `table`, `url`, `bucket`/`key`, or `path`. When catalog metadata is available, the gateway:

- attaches a `runtime_catalog` block to Galileo Agent Control tool evaluation context;
- exposes a compact `evidence` block in `/api/v1/inspect/tool` responses;
- appends the same evidence JSON to the audit details string as `decision_evidence=...`.

The local verdict remains driven by the existing scanners, OPA, Cisco Inspect, and Agent Control response. Catalog metadata is enrichment only in this PR.
