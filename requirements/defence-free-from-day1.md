# DefenseClaw Free-From-Day-1 Requirement

Status: Active  
Date opened: 2026-04-02

## Goal

Make the bundled DefenseClaw local Splunk experience start directly in
**Splunk Free** mode instead of entering a temporary 60-day Trial period.

## Requirements

| ID | Status | Requirement | Rationale |
| --- | --- | --- | --- |
| DFR-001 | Locked | The bundled local Splunk profile shall start in Splunk Free mode from day 1. | This avoids turning the more permissive Trial behavior into the effective default local experience. |
| DFR-002 | Locked | The implementation shall not modify Splunk's global licensing model or make Trial permanent. | The DefenseClaw local bundle should be opinionated without redefining broader Splunk licensing behavior. |
| DFR-003 | Locked | The bundle shall not depend on local Splunk users, roles, or printed credentials for the default Free-mode path. | Splunk Free disables users and roles, so the customer flow must not rely on Enterprise-style auth behavior. |
| DFR-004 | Locked | The bundled CLI and docs shall describe the local runtime as Free-from-day-1 and no-login by default. | The operator story must match the actual runtime behavior. |
| DFR-005 | Locked | If a user needs Enterprise capabilities later, they must install a real Enterprise license. | The local bundle should remain low-friction but honest about the license boundary. |

## Validation

- bundled profile starts successfully with `SPLUNK_LICENSE_URI=Free`
- local licenser state shows `Free` active
- bridge startup and DefenseClaw setup no longer return or print Splunk credentials
- local HEC ingest still works
