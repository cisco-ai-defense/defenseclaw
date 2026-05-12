# Stage: classify_evidence

The harness has already executed the case command and captured stdout, stderr, and exit code. Your job is to read the evidence and write a verdict.

## Context

- run_id: `{run_id}`
- cell_id: `{cell_id}` — `{cell_label}`
- case_id: `{case_id}`
- case_title: `{case_title}`

## Command that ran

```bash
{case_command}
```

expectations:

```json
{case_expected}
```

## Captured outputs (read these before deciding)

- stdout: `{stdout_path}`
- stderr: `{stderr_path}`
- exit_code: `{exit_code}`
- timed_out: `{timed_out}`
{followup_evidence_block}
## Notes for you (from the case YAML)

{notes_for_agent}

## What to do

1. Read both stdout and stderr fully. Do not summarize from a partial read.
2. Check that the exit code matches expectations.
3. Check that every `expected_substrings` entry appears in stdout OR stderr (unless the case specifies a stricter constraint in the notes).
4. Check that no `must_not_contain` substring appears.
5. If the case is a JSON-producing command, validate the JSON is well-formed before reasoning about field contents.
6. If any "Followup evidence" entry is marked `[ATTN]`, treat its summary as part of the verdict input. Read the referenced `artifact:` file before concluding.
7. Write the verdict JSON to `{verdict_path}` exactly. The schema is in the preamble. Be concise but specific in `reasoning`.

If you cannot decide, set `verdict: "needs-human"` with a clear "I cannot decide because ..." note. Do not guess.

When followup evidence is present, prefer concrete grounded statements over interpretive ones. Quote the artifact path you relied on so the report can audit your verdict.
