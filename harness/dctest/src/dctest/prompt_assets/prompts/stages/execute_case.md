# Stage: execute_case

You are about to drive a single DefenseClaw test case end-to-end. The harness will run the case command for you via the local executor, but you are responsible for any pre-flight (provider switch, connector install, env var setup) and for writing the verdict.

## Context

- run_id: `{run_id}`
- cell_id: `{cell_id}` — `{cell_label}`
- case_id: `{case_id}`
- case_title: `{case_title}`
- case_surface: `{case_surface}`
- target_worktree: `{target_worktree}`

## Cell parameters

- connector: `{connector}`
- provider: `{provider_id}` (`{provider_vendor}` / `{provider_model}`, endpoint `{provider_endpoint}`)
- role: `{role}`
- opa_profile: `{opa_profile}`
- pack_profile: `{pack_profile}`
- fail_mode: `{fail_mode}`
- scan_type: `{scan_type}`

## Command to execute

```bash
{case_command}
```

env overrides:

```json
{case_env}
```

expectations:

```json
{case_expected}
```

## What to do

1. Make sure the cell parameters are already applied. If not (e.g. provider was not switched, connector not installed), run the appropriate `defenseclaw setup ...` commands first. Capture their output.
2. Run the command above. Capture stdout/stderr (the harness will also do this).
3. Inspect output for the case's `expected_substrings` and `must_not_contain`. Compare `exit_code`.
4. For lifecycle surfaces: take a `dctest snapshot create` before and after; diff.
5. Write a verdict JSON object to `{case_dir}/verdict.json` following the schema in the preamble.

Do not run any command outside what this prompt or the case command requires.
