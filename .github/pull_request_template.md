<!--
Every future action item must have a GitHub issue before it appears in this PR
body. List linked issues under "Open Issues / Follow-ups". If there are no
follow-ups, write "None".
-->

## Problem

<!-- What user, operator, security, reliability, or maintenance problem does this PR solve? -->

## Current Situation

<!-- What exists today? Include relevant constraints, failing behavior, prior work, or base-branch context. -->

## Solution

<!-- Describe the implementation. For complex work, add focused subsections. -->

## Architecture Diagram

<!-- Include a diagram when it clarifies security posture, data flow, policy behavior, or reviewer risk. Write "N/A" if not useful. -->

## What Changed (Where & How)

| File | Summary |
| --- | --- |
| <!-- path --> | <!-- change summary --> |

## Breaking Changes

<!-- Describe behavior/default/config/API/operator workflow changes. Write "None" if not applicable. -->

## Open Issues / Follow-ups

<!-- Every future action item here must link to a GitHub issue, e.g. "- #123 - follow-up summary". Write "None" if not applicable. -->

## Test Plan

<!-- Include exact commands and observed results. -->

## Contributor checklist (defenseclaw-develop)
<!-- Requirements: .claude/skills/defenseclaw-develop/reference/checklist.md. For a docs-only or typo change write "Areas touched: DOC" and n.a. on the rest. -->
Areas touched: <codes from CFG POL ID DEP REQ SBX SCN TST PERF OBS DOC SEC PKG PR>
- [ ] Every MUST for these areas is met. MUST items that do not apply, each with a reason: M-___ (reason) / none
- [ ] SHOULD items skipped, each with a one-line reason: S-___ (reason) / none
- [ ] Off switch per mode: OSS `<key>` / standalone and MDM `enterprise.<key>: off` / Secure Client unreachable. Off-path test: <test name>. Cost when off: <none / measured>
- [ ] New external requirement: none / <name>, tier Required / Recommended / Optional; detected in doctor, in docs-site, missing case tested, never installed silently
- [ ] Applies as one atomic unit with rollback; no out-of-band step: yes / n.a.
- [ ] Every layer of the change is in this PR (schema, mirrors, migration, docs, tests per mode, packaging, audit): yes / n.a. with a reason
- [ ] Hot-path impact (hooks, gateway, SQLite): none / <measurement>
- [ ] Size delta (binaries, wheel, packages): <before -> after> / none
- [ ] Observability: audit action / error code / telemetry / redaction profile: <what> / n.a.
- [ ] Dead or legacy code removed: <what and why> / kept for <upgrade path> until <version> / none found
- [ ] Stop-and-ask trigger hit: no / yes, discussed in #<issue>
- [ ] Does this change an architecture rule, so the skill must be updated? no / yes, updated
- Commands run and results: <make lint ..., make test ..., area checks ...>
