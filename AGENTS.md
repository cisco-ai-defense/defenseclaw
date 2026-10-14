# DefenseClaw: guidance for AI coding agents

Read the skill before you change code. Source code and tests are authoritative;
if a skill or doc disagrees with them, trust the code and say so in your PR.

## Skills (in `.claude/skills/`)

| Work | Skill |
| --- | --- |
| Any change except a new or changed agent connector | `defenseclaw-develop` |
| Adding or changing a connector (hook, plugin, proxy, ACP route) | `defenseclaw-add-connector` |
| TUI panels, modals, Setup wizards | `defenseclaw-tui` |

Start with `.claude/skills/defenseclaw-develop/SKILL.md`. It has the design
principles, a routing table, the stop-and-ask triggers and the tiered
MUST/SHOULD/MAY checklist in `reference/checklist.md`.

## Rules that apply to every change

- Put the block from `reference/pr-block.md` in the PR description
  before your first commit, and tick it as you go.
- Stop and ask a maintainer before building anything on the stop-and-ask list in
  `.claude/skills/defenseclaw-develop/SKILL.md`.
- Every feature is switchable off and costs nothing when off. Hooks run on every
  agent tool call: keep that path to one bounded local call.
- Never install an external requirement silently; detect, explain, document it.
- Remove dead and legacy code you touch. Keep a compatibility shim only for a
  supported upgrade and say until when.

## Gates

Run the checks in `docs/TESTING.md` ("Before a PR"): `make lint`, `make test`,
`make ts-test`, `make rego-test`, `make check`. `make skill-check` verifies the
skill still matches the repository.

Stage explicit paths only. Never commit credentials, build outputs or scratch
files, and never hand-edit generated files; run their generator.
