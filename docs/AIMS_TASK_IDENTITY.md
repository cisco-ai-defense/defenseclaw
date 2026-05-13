# Task-scoped agent identity

This PR ports the AIMS task-token idea into DefenseClaw as an optional runtime authority layer.

A task token binds a runtime action to:

- parent agent ID;
- task ID and task type;
- allowed resource IDs or prefixes;
- scopes;
- expiry;
- token ID for revocation/audit correlation.

The implementation is HS256 JWT-compatible and uses only the Go standard library. It is off by default.

## Enablement

```bash
export DEFENSECLAW_TASK_TOKEN_ENABLE=1
export DEFENSECLAW_TASK_TOKEN_SECRET='<at-least-16-bytes-from-secret-manager>'
export DEFENSECLAW_TASK_TOKEN_ISSUER=defenseclaw
```

Callers can pass the token as either:

```http
X-DefenseClaw-Task-Token: <token>
```

or:

```http
Authorization: Bearer <token>
```

## Runtime effects

When enabled and a valid token is present, the gateway stores the task claims on request context before `AgentRegistry.Resolve`. The task's parent agent ID becomes the logical agent identity for that request, while the task ID, task type, token ID, allowed resources, and scopes are retained on the `AgentIdentity` value.

The same claims are added to Galileo Agent Control context as:

- `task_id`
- `task_type`
- `task_parent_agent_id`
- `task_token_id`
- `task_allowed_resources`
- `task_scopes`
- `task_auto_revoke`

Invalid tokens are recorded as `task_identity_error` in Agent Control context. This keeps the PR additive and non-breaking; a follow-up can wire fail-closed enforcement for deployments that require it.
