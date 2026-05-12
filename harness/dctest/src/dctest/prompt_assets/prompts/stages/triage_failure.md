# Stage: triage_failure

A case verdict came back as `fail` or `blocked`. Investigate the failure and write a triage note. You are not authorized to "fix" anything by re-running commands with different arguments; your job is to understand and report.

## What I should know about you

You can read any file under the run directory. You may invoke read-only inspection commands (`defenseclaw status`, `defenseclaw-gateway status`, `defenseclaw audit export --limit 10`, `git log`, etc.) but you must not mutate config or restart services.

## What to produce

Write a markdown note to `{triage_path}` with these sections:

```markdown
# Triage — `{case_id}` in `{cell_id}`

## Symptom
<one-sentence description of what the verdict says>

## Likely cause
<your best hypothesis with citations to stdout/stderr lines>

## Repro
<minimal sequence of commands to reproduce, copy-pasteable>

## Severity
- blocking-required-cell | flaky | environmental | needs-product-fix

## Next step
<one of: re-run case after operator intervention; file product issue; mark expected-failure in case YAML; needs-human>
```

Be specific. "Probably a config issue" is not a triage note. "stderr line 12 shows `failed to read config.yaml: permission denied`; `ls -l ~/.defenseclaw/config.yaml` shows mode 600 owned by root, but dctest is running as $USER" is a triage note.
