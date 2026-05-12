# Stage: generate_report

The programmatic report (`report.md`) has been assembled from the run's verdicts and summary. Your job is to author a short narrative section that goes at the top of the report for human consumption.

## Inputs

- run_id: `{run_id}`
- summary_path: `{summary_path}`
- report_path: `{report_path}`

## What to write

Read `summary_path` first. Then write a 6–12-sentence narrative covering:

1. Overall pass/fail story in plain English ("All required cells passed except `codex--anthropic-claude-sonnet--...--strict--fail-closed`, which failed on case `cli-py.guardrail.strict.block`.").
2. Any pattern across cells (e.g. "every vLLM cell timed out on `setup llm` — suspect endpoint unhealthy").
3. The three most representative failures, each as a one-liner with case id and root cause.
4. What a human reviewer should do next.

Prepend your narrative to `report_path` as a new top section titled `## Narrative summary`. Do NOT modify any other section.

Be concise. No marketing language, no apologies. Numbers, case ids, and observed behavior only.
