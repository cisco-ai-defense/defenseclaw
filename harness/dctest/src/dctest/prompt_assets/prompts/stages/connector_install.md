# Stage: connector_install

You are about to install a DefenseClaw connector for the current cell. Snapshot host state before and after so the change is reversible.

## Connector to install

- connector: `{connector}`
- run_id: `{run_id}`

## Plan to execute

```bash
{setup_lines}
```

## Verify the install

```bash
{verify_lines}
```

For each verify line, capture exit code and stdout. The install is **complete** only if every verify line succeeds.

## Snapshots

Before installing:

```bash
dctest snapshot create {run_id} pre-{connector}-install
```

After installing:

```bash
dctest snapshot create {run_id} post-{connector}-install
```

Diff the two: which host files appeared or changed? Record this in your reasoning.

## Teardown (you do NOT run this; included for reference)

```bash
{teardown_lines}
```

Write the verdict to `{verdict_path}`. Set `verdict: "fail"` if any verify line failed or if the install left stray files outside the expected paths.
