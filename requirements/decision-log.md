# DefenseClaw Splunk Local Decision Log

Status: Active  
Date opened: 2026-03-26

| ID | Date | Status | Decision | Rationale |
| --- | --- | --- | --- | --- |
| DDEC-001 | 2026-03-26 | Accepted | `DefenseClaw` is the only customer-facing repo for the local Splunk workflow. | The intended Cisco story is one product experience, not a two-repo customer journey. |
| DDEC-002 | 2026-03-26 | Accepted | The local bridge runtime shall be bundled into `DefenseClaw` for the customer path. | The user explicitly chose to eliminate the second-repo dependency from the normal install flow. |
| DDEC-003 | 2026-03-26 | Accepted | `defenseclaw setup splunk-local --non-interactive` shall bootstrap the bundled local bridge by default. | The default local command should do the customer-facing work without extra flags or manual setup. |
| DDEC-004 | 2026-03-26 | Accepted | The bundled local bridge contract, including the HEC token, shall be persisted in `DefenseClaw` config for the local path. | The normal case should not require manual token export or shell-state management. |
| DDEC-005 | 2026-03-26 | Accepted | O11y remains an explicit opt-in integration rather than a prerequisite for local Splunk enablement. | The customer must be able to complete the local Splunk path without provisioning OTLP/O11y. |
| DDEC-006 | 2026-03-26 | Accepted | If O11y is not enabled, runtime traces and metrics still need a Splunk-visible fallback path. | The Splunk-only customer story is incomplete if traces and metrics disappear when OTLP/O11y is off. |
| DDEC-007 | 2026-03-26 | Accepted | `setup splunk-local` must work on a clean DefenseClaw home without a separate prior `init` command. | The one-command customer story fails if local Splunk setup still depends on pre-created config and audit state. |
