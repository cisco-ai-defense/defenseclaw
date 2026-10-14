# Keeping the skill current

The skill is only useful while every path, make target and symbol it cites still exists and every rule still matches the code. Source code and tests are authoritative. When they disagree with the skill, fix the skill.

## Citation conventions

| Write in backticks | Meaning | Checked as |
| --- | --- | --- |
| A repo-relative path | A repo file or directory | Exists in the repo |
| `make` followed by a target name | A make target (more than one may follow) | Defined in `Makefile` |
| `@sym:` followed by a name | A symbol (function, type, constant, key) | `git grep` finds it outside the skill |
| A command that contains repo paths | A command to run | Every repo path in it exists |

Do not cite line numbers or commit SHAs. Placeholders (`<pkg>`, `*`, `...`) are skipped by the check. Paths that exist only at runtime (`~/.defenseclaw/...`) are skipped.

## Size limits

| File | Limit |
| --- | --- |
| `SKILL.md` | 200 lines |
| `reference/checklist.md` (the ID registry) | 340 lines |
| Every other file in `reference/` | 300 lines |

Agents load these files. When a file nears its limit, move detail into the linked repo docs instead of growing the skill, or split a reference by area. Keep the description frontmatter to three sentences.

## Update map

When a change of this kind merges, the same PR updates the listed place.

| Kind of change | Update |
| --- | --- |
| New or changed architecture rule or principle | `SKILL.md` principles and the requirement in `reference/checklist.md` |
| New area, new tier rule, new ID scheme | `SKILL.md` tier legend and routing table, `reference/checklist.md` |
| New make target or gate that contributors must run | The matching requirement in `reference/checklist.md`; `docs/TESTING.md` |
| Renamed or moved file, symbol or target that the skill cites | The citation (the freshness check names it) |
| New config mechanism (schema location, writer, migration chain, version) | CFG and PKG sections |
| New deployment mode or profile | DEP section and the principle that mentions modes |
| New external requirement class or detection pattern | REQ and SBX sections |
| New hot path (a new hook, endpoint or exporter) | PERF section |
| New generated artifact or drift gate | The area section that owns it, and DOC if it is a doc output |
| New workflow or required CI check | TST and SEC sections |
| New skill for a sub-domain | The `SKILL.md` routing table and "When to use" |
| Retired feature or removed shim | Delete its requirement; keep none that cite removed code |

A requirement without a check command and an evidence path is incomplete. Do not add one.

## PR checklist line

Every PR description carries this line from the PR description block:

`Does this change an architecture rule, so the skill must be updated? no / yes, updated`

A reviewer answers "yes" when the diff changes any row of the update map. The reviewer asks for the skill edit in the same PR, not a follow-up.

## Freshness check

Run from the repo root:

```bash
make skill-check
python3 .claude/skills/defenseclaw-develop/scripts/check_skill_fresh.py
```

The script needs only Python 3.10 or newer and git. It makes no network calls and finishes in about a second. Exit code 0 means no drift, 1 means drift (the list names each file, line and reason), 2 means the script could not run (not a repo root, missing skill directory).

What it checks:

| Check | Fails when |
| --- | --- |
| Paths | A cited repo path does not exist |
| Make targets | A cited target is not defined in `Makefile` |
| Symbols | A `@sym:` symbol is not found by `git grep` outside the skill |
| Size | `SKILL.md` is over 200 lines, the checklist over 340 or another reference over 300 |
| IDs | A requirement ID is cited but not defined in `reference/checklist.md`, or is defined twice, or a reference file defines one |
| Test patterns | A `go test -run` alternative matches no test function in the named packages |
| Frontmatter | `name` is not `defenseclaw-develop` or `description` is missing |
| Routing | A file in `reference/` is not linked from `SKILL.md` |

It does not judge whether a rule is still correct. The quarterly sweep does that.

How to fix a failure: find the new name with `git log --follow -- <old path>` or `git grep -n '<symbol>'`, update the citation, and re-read the requirement that cites it. If the thing was removed, delete or rewrite the requirement.

`make check` runs the script through `make skill-check`. CI runs `make check` for skill-only PRs because of the `.claude/skills/defenseclaw-develop/` rule in `scripts/ci_changes.py`.

## Quarterly sweep

A maintainer runs this once per quarter and before each minor release. Allow about an hour.

1. Run the freshness check and fix every failure.
2. Read `CONTRIBUTING.md`, `docs/TESTING.md` and `.github/pull_request_template.md`. Update any requirement whose command or gate they changed.
3. List the make targets with `grep -n '^\.PHONY' Makefile` and the workflows in `.github/workflows`. Add a requirement for any new gate that a contributor can fail locally. Remove citations of retired ones.
4. Re-check each principle against the code: open the evidence paths of one requirement per area and confirm the rule still holds. Rewrite or delete rules that no longer hold.
5. Search the last quarter of merged PRs for fixes that repeated a class of defect (silent fallback, closed list missed, mirror drift, hot-path cost). Add a requirement or sharpen an existing one for each class.
6. Check the stop-and-ask list against the current sensitive areas (signing, formats, identity, defaults). Add or remove triggers.
7. Confirm sizes with `wc -l .claude/skills/defenseclaw-develop/SKILL.md .claude/skills/defenseclaw-develop/reference/*.md`.
8. Confirm `.agents/skills/defenseclaw-develop` is a symlink to the `.claude` copy and no second copy exists.
9. Open one PR with the sweep results. Describe each removed or changed rule and why. Update the "Last full sweep" line in `SKILL.md` with the date and the main commit you swept; start the next sweep's PR search from that commit.

## Adding a requirement

1. Pick the area and the tier. MUST only when a missing item breaks a gate, a security property, an upgrade path or an operator.
2. Take the next number in the area in `reference/checklist.md`, the only place IDs are defined. Reference files carry detail rows without IDs. Never renumber; a deleted ID is retired, not reused.
3. Write the rule, the failure it prevents, a check command and one to three evidence paths, in at most three lines.
4. Run the freshness check and confirm the checklist still fits in 340 lines. The freshness check also fails on an ID that is used but not defined in the checklist.
