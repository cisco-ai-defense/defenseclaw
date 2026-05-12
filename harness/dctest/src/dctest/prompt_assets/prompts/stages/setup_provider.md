# Stage: setup_provider

You are about to switch DefenseClaw to a specific LLM provider for the current cell. The harness has computed a plan for you; your job is to execute the plan, observe each command, and confirm the switch succeeded.

## Provider to apply

- provider_id: `{provider_id}` (`{provider_vendor}` / `{provider_model}`)
- endpoint: `{provider_endpoint}`
- role: `{role}`
- judge_provider_id: `{judge_provider_id}`

## Required env vars (must be set by the operator BEFORE invocation)

```
{required_env}
```

If any are missing, set `verdict: "blocked"` and stop.

## Plan to execute (verbatim, in order)

```bash
{shell_lines}
```

After running the plan, confirm:

1. `defenseclaw status` reports the correct provider and model.
2. For vLLM / Ollama: `curl -sf {provider_endpoint}/models` returns 200.
3. For mixed role: `defenseclaw guardrail status` shows the guardrail-side provider; `defenseclaw config show` shows the judge-side provider matches `{judge_provider_id}` if not null.

Write the verdict to `{verdict_path}`. Note: this stage's "case" is the provider switch itself.
