# 99 — Sub-agent invocation contract

Every panel/screen/widget plan is dispatched to its own sub-agent. This file
defines the **exact** prompt template the parent uses, the model, the scope,
and the deliverables.

---

## 0. Model

> **Requested model:** `claude-opus-4-7-thinking-xhigh` (Claude Opus 4.7 with
> extended thinking, "x-high" effort).

The parent agent must select this model for every sub-agent. If the user's
Cursor environment surfaces a different slug for the same model (e.g.
`claude-opus-4.7-thinking-xhigh`, `opus-4.7-thinking-xhigh`), use that
slug — the bare requirement is "Claude Opus 4.7 with extended thinking at
the highest effort tier available".

> Note for the parent agent dispatching from within Cursor: if the in-IDE
> sub-agent model picker does not list a Claude Opus 4.7 variant, **stop
> and tell the user** rather than substituting a smaller model. Sub-agents
> on a weaker model are not authorized to land these plans because the
> property-test and snapshot-debug layers reliably exceed shorter context
> budgets.

---

## 1. Hard scope rules

A sub-agent assigned plan `panels/07-policy.md` may:

* **Read** every file under `cli/defenseclaw/tui/` and `cli/tests/tui/`.
* **Write** only the test files listed in the "File layout" section of its
  plan (typically `test_<surface>_model.py`,
  `test_<surface>_app.py`,
  `test_<surface>_snapshot.py`,
  `test_<surface>_invariants.py`).
* **Edit** the production file **only** to fix:
  * A clear bug the test plan calls out as "known defect, file before fixing".
  * Type annotations or constants needed for the test (in that case, no
    behavior change, additive only).

A sub-agent **must not**:

* Touch another plan's test files (e.g. the Policy sub-agent must not edit
  `test_alerts_*.py`).
* Touch `conftest.py` or `helpers/` except to **add** new helpers; if a
  helper would be useful to multiple plans, the sub-agent files an issue
  with the proposed helper API and waits — the parent merges helper PRs
  serially.
* Touch `pyproject.toml`, `Makefile`, or any CI workflow.
* Add a new third-party dependency. Use what the foundation provides.

---

## 2. Prompt template

```text
You are a code-testing sub-agent. Your model is claude-opus-4-7-thinking-xhigh.

Read these files first, in this order:
  1. docs/testing/tui/README.md
  2. docs/testing/tui/00-framework-foundation.md
  3. docs/testing/tui/99-sub-agent-contract.md
  4. docs/testing/tui/<PLAN PATH>            <-- your assigned plan
  5. Every production file your plan lists under "Files under test"

Then implement every test described in your plan under
`cli/tests/tui/`. Obey the hard scope rules in §1 of the sub-agent
contract. When done, run the full quality gate (§4 of the README) and
report:

  * Files added (paths)
  * Lines of test code added
  * Coverage % for each module under test
  * Number of snapshots checked in
  * Any "known defects" you filed as follow-up issues
  * `pytest -q cli/tests/tui` final output (exit code 0 required)

Do NOT proceed to implementation if the framework canary
(`cli/tests/tui/test_framework_canary.py`) is failing. Stop and report.
```

---

## 3. Parent-agent rotation

The parent rotates through the plans in this order to minimize merge
conflicts in `conftest.py` and the shared helpers:

1. Foundation canary green (parent).
2. Widgets group first (small surface, low coupling):
   * 28 hint bar, 29 action menu, 30 toasts, 31 metrics/strip.
3. Independent panels next (no cross-panel state):
   * 11 tools, 03 skills, 04 mcps, 05 plugins, 12 ai-discovery,
     13 registries, 09 audit, 08 logs, 02 alerts, 10 activity, 06 inventory.
4. Heavy panels with sub-tabs and modals:
   * 07 policy, 14 setup.
5. Modal screens:
   * 16 command palette, 17 panel jumper, 18 mode picker, 21 command preview,
     22 consequence family, 23 mcp set form, 24 setup resource editor,
     25 config diff, 26 detail/judge history.
6. Policy creator modals last (most state):
   * 19 quick start, 20 playground, 27 creator command palette.
7. Cross-cutting:
   * 01 overview (it composes the metrics widget tested earlier),
     15 first-run (touches setup-state but read-only),
     32 app-shell bindings (last — only after all panels are tested).

Run no more than **two** sub-agents in parallel. Higher parallelism creates
merge conflicts in `helpers/builders.py` and `__snapshots__/`.

---

## 4. Acceptance review checklist (parent agent uses on each PR)

For each landed sub-agent PR:

* [ ] PR description quotes the plan's "Deliverables" list verbatim.
* [ ] Every checkbox in the plan's "Coverage matrix" is ticked with the
      specific test name that satisfies it.
* [ ] `pytest cli/tests/tui -q` is green locally and in CI.
* [ ] `pytest cli/tests/tui --snapshot-update` produces zero new diffs
      on a clean second run.
* [ ] Coverage on the target module ≥ 90 % (or justified).
* [ ] No production code changed outside the plan's allow-list.
* [ ] No `conftest.py`/`helpers/` edits made without a separate review.
* [ ] At least one L5 invariant test exists for the surface.
* [ ] No `pytest.skip` or `xfail` without a justification comment that
      links to a filed issue.
* [ ] Hint bar text is asserted after every L2 interaction.
* [ ] Snapshot file count ≥ 3 (one per QA size) for each scene listed in
      the plan's "Snapshot scenes" section.

---

## 5. Failure modes & rollback

If a sub-agent's PR breaks `make cli-test` on `main`:

1. **Revert** that PR first.
2. File an issue referencing the plan and the specific assertion that
   failed.
3. Re-dispatch a sub-agent (same model) with the failure attached and a
   note that they must reproduce the failure locally before resubmitting.

If two sub-agents fight over `__snapshots__/`:

* Whoever lands first wins. The second sub-agent must rebase, re-run
  `--snapshot-update`, and visually diff every modified golden before
  pushing again.

---

## 6. Coverage rollup target

After every plan lands, the global coverage of `defenseclaw.tui` should be
**≥ 92 %** statement coverage on a clean run of:

```bash
uv run pytest cli/tests/tui \
  --cov=defenseclaw.tui \
  --cov-report=term-missing \
  --cov-report=html:coverage-html-tui
```

If aggregate coverage stays below 90 % after all plans land, dispatch a
"gap-fill" sub-agent with the same template and the missing files listed
in its prompt.
