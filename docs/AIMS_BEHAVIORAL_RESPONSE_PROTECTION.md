# Behavioral risk and response protection

This PR ports two AIMS runtime-protection ideas into DefenseClaw as opt-in controls:

1. in-memory behavioral risk scoring for agent/tool actions;
2. response masking, truncation, and canary injection for post-tool outputs.

Both controls are disabled by default and can be enabled independently.

## Behavioral risk scoring

```bash
export DEFENSECLAW_BEHAVIORAL_RISK_ENABLE=1
export DEFENSECLAW_BEHAVIORAL_BASELINE_RPM=60
# Default action is alert. Set to block only for deployments ready to enforce.
export DEFENSECLAW_BEHAVIORAL_RISK_ACTION=block
```

The analyzer tracks five sliding windows: 1 second, 1 minute, 10 minutes, 1 hour, and 24 hours. It scores request bursts relative to a configured p99 RPM baseline, and adds risk for cross-domain access and a schema-probe → bulk-read → external-post sequence.

When enabled, DefenseClaw adds `behavioral:risk:<score>` findings to tool-inspection verdicts and promotes low-risk allows to alerts when the score crosses the alert threshold. Blocking is opt-in through `DEFENSECLAW_BEHAVIORAL_RISK_ACTION=block`.

## Response protection

```bash
export DEFENSECLAW_RESPONSE_PROTECTION_ENABLE=1
export DEFENSECLAW_RESPONSE_PROTECTION_FIELDS=email,phone,ssn,salary,dob,address,national_id
export DEFENSECLAW_RESPONSE_PROTECTION_MAX_ROWS=500
export DEFENSECLAW_RESPONSE_PROTECTION_MAX_BYTES=1048576
export DEFENSECLAW_RESPONSE_PROTECTION_CANARY_RATE=0
```

For `/api/v1/inspect/tool-response`, the gateway masks configured fields, caps returned rows/bytes, and can inject a deterministic canary record when the canary rate is `1` for demos/tests. The response verdict includes:

- `response_protection` evidence with masked fields, truncation, canary, row, and byte counts;
- `protected_output` containing the transformed tool output for hook callers that choose to pass the filtered value back to the agent;
- findings such as `response-protection:masked`, `response-protection:truncated`, and `response-protection:canary`.

This keeps the runtime story additive: Galileo controls the action, behavioral scoring detects drift, and response protection limits exfiltration when tools return sensitive data.
