# Upstream connector monitor

A small GitHub Actions script watches **Codex and Claude Code only**. It reads
merged upstream changes and compares them with DefenseClaw main. Neither agent
is installed or run; downloaded code is never executed. Python uses only stdlib.

## Flow

1. Restore a cursor per connector. The daily workflow selects up to 100 unseen
   upstream-main merges, oldest first; bootstrap takes the latest bounded batch.
2. Read the complete changed-file inventory, including renames and deletions.
   Hook-related paths **or edited hook references** select relevant files, even
   outside known schemas. Fetch up to ten relevant files at the merge's first
   parent and merge SHA. Several PRs are never conflated into one delta.
3. Read the latest local hook contract and selected actual connector source from
   DefenseClaw main. Small deterministic checks detect changed `tool_use_id`
   types, newly rejected deny responses in named Codex schemas, and exact,
   unqualified Claude changelog statements retiring a registered path. Other
   relevant edits require human review.
4. AI compares the delta with eight explicit requirements in
   [connectors.json](connectors.json): discovery, registration, delivery, payload,
   decision, failure, execution and correlation. Local/upstream quotes are checked
   against supplied text. Grounded triage needs before/after evidence, applicability
   and counterevidence; routine results require complete relevant-file coverage.
   AI cannot prove a break or certify safety. Raw output stays runner-local.
5. A main-only publisher optionally creates one generic daily digest issue, then
   persists progress. Unavailable AI warns but permits static progress; invalid
   analysis stays pending. Failed delivery
   prevents that candidate checkpoint being committed. Retry deduplication checks
   bot markers in the latest 100 bot issues; email is not exactly-once delivery.

Zero matches means **no tracked dependency identified**, never "connector safe".
OS-specific paths, managed policy, launchers, ordering, timeouts and arbitrary
source semantics are review topics, not independently verified platform bindings.
Examples, omission from docs and changed defaults are not proof of retirement.
Claude's private runtime and external unversioned docs are not monitored here.

## Enablement and email

Monitor and publication default off. After merge, run `Connector Delta Monitor` on
main with `notify=false` to smoke-test collection and checkpoint restoration.
Set `CONNECTOR_DELTA_MONITOR_ENABLED=true` for the daily 06:23 UTC run. Publication
also needs `CONNECTOR_DELTA_NOTIFICATIONS_ENABLED=true`; manual runs additionally
require `notify=true`. Disabled publication queues no later emails.

Hook-related changes enter the same generic digest whether analysis finds a
conflict or not; unrelated PRs stay informational in the local report instead of
creating inbox noise. Digests contain public upstream PR metadata, never impact
classifications. New issues mention the five contributors once; same-day retries
append new entries without new mentions. GitHub email depends on settings/access;
this is not SMTP or a private channel. Public checkpoints identify processed
merges, not risk. Legacy or extra fields are rejected before upload/publication.

Conflict classifications, evidence and model output stay in the owner-readable
`private-report.json`, never uploaded or included in notices/logs. On hosted CI
this file is ephemeral; reproduce a PR locally to inspect it. There is no durable
private report archive or private email delivery in this version.
AI is a second layer after file selection and static checks. CI keeps it off until
SRE provisions access; local use accepts `CONNECTOR_DELTA_AI_ENDPOINT`,
`CONNECTOR_DELTA_AI_API_KEY` and `CONNECTOR_DELTA_MODEL` in the process environment.
Supported routes are Anthropic, Azure Foundry Claude, Azure OpenAI chat completions
and Bedrock. Azure endpoints must match the vendor host/path allowlist; redirects
are refused. Optional `CONNECTOR_DELTA_REASONING_EFFORT` controls reasoning effort.
Selected snippets/deltas leave the host; no model tools or execution are granted.

State is a main-only Actions artifact retained 90 days. Missing state after prior
runs fails visibly. The scanner reads at most 300 recently updated closed PRs and
1,000 files per PR; a cursor outside that window requires manual recovery.
No background service, installation, model cache, generic parser or outbox exists.

## Local tests and a single-PR replay

```sh
python3 -m unittest cli.tests.test_connector_delta -v
CONNECTOR_DELTA_AI_ENABLED=false python3 scripts/connector_delta_monitor.py analyze --pr codex 44349 --output /tmp/connector-replay
```

Replay pins current DefenseClaw main, just like production; the private report
records its commit. Inspect `private-report.json` locally; never
upload it publicly. Replay output cannot publish or advance production state.
No live model calls are needed by tests. Selected regression examples are not a
population accuracy benchmark or live-client certification.
