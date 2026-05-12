# Per-PR workflow

The recommended dctest workflow when reviewing a DefenseClaw PR.

## 0. Get the PR branch

```bash
gh pr checkout <pr-number>
# OR: git worktree add -b review/pr-<n> ../defenseclaw-pr<n> origin/pull/<n>/head
```

## 1. Intake

```bash
cd harness/dctest
source .venv/bin/activate
dctest intake --worktree-path ../.. --slug pr-<n>-<yyyy-mm-dd>
```

## 2. Decide the matrix scope

Three preset scopes, in order of increasing thoroughness:

- **smoke** — one provider × one connector × `cli/` cases. ~1 minute.
- **medium** — required connectors × default provider × skills + connectors + gateway-api + stories. ~30 minutes.
- **long** — full required matrix, all surfaces, all error paths. ~3 hours.

Pick by looking at what the PR touches. CLI-only PRs ⇒ smoke. Scanner / guardrail / connector changes ⇒ medium. Lifecycle / install / migrations changes ⇒ long with explicit `--surface lifecycle` runs.

## 3. Doctor

```bash
dctest doctor --selection runs/pr-<n>-<date>/selection.yaml
```

If anything reports `no`:

- missing `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` ⇒ export it.
- missing `vllm` / `ollama` endpoints ⇒ either start them or filter them out (see [matrix-recipes.md](./matrix-recipes.md)).
- missing `defenseclaw-gateway` ⇒ `make install` in the worktree root.

## 4. Run

```bash
dctest run pr-<n>-<date> --selection runs/pr-<n>-<date>/selection.yaml --backend claude
```

For lifecycle cases, **use a dedicated VM or `docker run -it ... bash` sandbox**. Lifecycle cases delete `~/.defenseclaw`, restart sidecars, etc. They will always snapshot first, but you really don't want them touching your daily-driver shell.

## 5. Score and report

```bash
dctest score pr-<n>-<date>
dctest report pr-<n>-<date>
cat runs/pr-<n>-<date>/report.md
```

If `dctest score` returns non-zero:

- exit 1 → at least one required cell failed. Open the report's "Failures" section and triage each one. Use `dctest run ... --no-skip --cases <failing-id>` to re-run a single failing case after fixing the issue.
- exit 2 → at least one case requires human review. Open the "Needs human review" section, evaluate the evidence, and either re-run with the verdict written manually (`echo '{"verdict":"pass","reasoning":"..."}' > runs/.../verdict.json` then `dctest collect`) or escalate.

## 6. Roll back lifecycle damage

```bash
dctest snapshot restore pr-<n>-<date> pre-init
dctest snapshot restore pr-<n>-<date> pre-uninstall
# repeat as needed
```

## 7. Append to the PR

Paste the top of `report.md` into the PR review comment, link to the run id, and attach (or upload) the `runs/pr-<n>-<date>/` directory as a workflow artifact if you ran in CI.
