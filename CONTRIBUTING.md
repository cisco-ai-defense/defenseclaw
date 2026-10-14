# Contributing to DefenseClaw

Thank you for contributing. Project interactions are governed by
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Before opening an issue

Search the
[existing issues](https://github.com/cisco-ai-defense/defenseclaw/issues) and
include a clear problem statement, reproduction steps, affected platform and
version, relevant logs with secrets removed, and a minimal test case when
possible.

Do not file suspected vulnerabilities in a public issue. Follow the private
reporting process in [`SECURITY.md`](SECURITY.md).

## Development contract

The checked-in toolchain requirements are Python `>=3.10,<3.14`
([`pyproject.toml`](pyproject.toml)) and Go `1.26.4` ([`go.mod`](go.mod)).
Project CI uses Node.js 24 for TypeScript components. Run `make help` before
using state-changing source targets.

Common contributor checks are:

```bash
make build
make test
make ts-test
make rego-test
make check
make lint
```

`make test` runs the Python CLI suite and race-enabled gateway/E2E Go packages.
`make ts-test` and `make rego-test` are separate. `make check` runs the v7 audit,
error-code and schema gates, plus the observability v8 hard-cut, Grafana
dashboard, provider coverage, LLM catalog, and guardrail catalog gates.
Use focused tests while iterating, then run the checks relevant to every area
you changed. Local source targets use one locked, test-ready `.venv`; the
`make build`, `make all`, `make test`, `make check`, and `make py-lint` targets
do not require choosing between production and development Python environments.

Source activation is different from release installation. `make build` may
create or update the repository-local `.venv`, but it does not publish checkout
artifacts or mutate managed installation state. `make all` deliberately
activates the current checkout for local development. Direct install targets and
`scripts/install-dev.sh` enforce checkout ownership and are not an operator
upgrade path.

## Pull requests

- Keep each change focused and explain the problem, solution, risk, and
  verification evidence.
- Add or update tests for changed behavior.
- Update the canonical
  [documentation website](https://cisco-ai-defense.github.io/defenseclaw/docs/)
  when operator behavior changes. Repository Markdown should contain only
  contributor, implementation, package-local, generated-schema, fixture, or
  clearly historical material.
- Complete the pull-request template, including linked issues for deferred
  follow-up work.
- Do not commit credentials, private customer data, generated build outputs, or
  local runtime state.

The repository-specific testing map is in [`docs/TESTING.md`](docs/TESTING.md).


## Design rules and the contributor checklist

The repository ships a skill, `.claude/skills/defenseclaw-develop/`, that
records DefenseClaw's design rules as a tiered checklist: MUST (blocks merge),
SHOULD (expected, skipping needs a one-line reason) and MAY. It covers
configuration, policy, identity, deployment modes, external requirements,
sandboxes, testing, performance, observability, docs, security, packaging and
pull-request hygiene. Humans can read `SKILL.md` as a short design guide. Claude Code loads
skills from `.claude/skills`; agents that read `AGENTS.md` or `.agents/skills`
find the same files through a symlink (see [`AGENTS.md`](AGENTS.md)).

Before you write code:

1. Read `.claude/skills/defenseclaw-develop/SKILL.md` and classify your change
   with its routing table.
2. Read only the checklist sections for the areas you touch
   (`reference/checklist.md`, the one place requirement IDs are defined).
3. Paste `reference/pr-block.md` into your pull request and tick it as you go
   (the PR template already contains it).
4. Ask a maintainer first if your change hits a trigger on the stop-and-ask
   list in `SKILL.md`.

Adding or changing an agent connector has its own skill,
`.claude/skills/defenseclaw-add-connector/`. TUI work uses
`.claude/skills/defenseclaw-tui/`. Run `make skill-check` to confirm the skill
still matches the code; if your change alters an architecture rule, update the
skill in the same pull request (`reference/maintenance.md`).
