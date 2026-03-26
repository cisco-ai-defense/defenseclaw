# DefenseClaw Splunk Local Work Log

Status: Active  
Date opened: 2026-03-26

| Date | Work item | Outcome |
| --- | --- | --- |
| 2026-03-26 | Reviewed the unified local Splunk install goal across `defenseclaw` and `splunk-claw-bridge`. | Confirmed that the customer-facing story should be one `DefenseClaw` workflow rather than a separate bridge-repo workflow. |
| 2026-03-26 | Froze the local bundled bridge requirements for `DefenseClaw`. | Added a canonical requirements baseline, decision log, work log, and execution plan for this workstream inside the `DefenseClaw` repo. |
| 2026-03-26 | Started the Phase 1 implementation slice. | Prepared the bundled-bridge bootstrap command changes, tests, and customer-doc updates needed to move the local Splunk workflow under `DefenseClaw`. |
| 2026-03-26 | Reconfirmed the product boundary for Splunk and O11y. | Recorded that O11y remains opt-in, and that the Splunk-only customer path still needs traces and metrics to remain visible when O11y is not enabled. |
| 2026-03-26 | Ran the first real setup bootstrap attempt against a clean home. | Found that `setup splunk-local` still depended on prior init state, and added a requirement plus implementation work to bootstrap config and the audit store automatically. |
