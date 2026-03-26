# Unified Splunk Local Install Execution Plan

Status: Active  
Date: 2026-03-26  
Repository: `defenseclaw`

## Execution Goals

- bundle the local Splunk bridge runtime into `DefenseClaw`
- make `DefenseClaw` own local bridge enablement and teardown
- remove the normal-case manual local HEC token export step
- validate the bundled local path end to end

## Phase Order

### Phase 0: Requirements And Logging

- canonical requirement
- decision log
- work log
- execution plan

### Phase 1: Bundled Bridge Bootstrap

- add bundled bridge runtime assets
- extend `setup splunk-local`
- allow `setup splunk-local` to bootstrap clean local DefenseClaw state
- persist returned local bridge contract
- add focused tests

### Phase 2: End-To-End Validation

- start bundled bridge through `DefenseClaw`
- validate local Splunk reachability
- validate stored bridge contract

### Phase 3: Splunk-Only Signal Coverage

- define the Splunk fallback representation for traces and metrics when O11y is off
- implement producer-side export for the required runtime usage and latency signals
- verify that the Splunk-only path still powers the intended dashboards

### Phase 4: Product Doc Realignment

- update README
- update QUICKSTART
- update install guidance

## Guardrails

- no implementation slice is complete without local validation for that slice
- manual bridge mode may remain for debugging, but not as the preferred customer flow
- preserve the existing OTLP/O11y opt-in path while ensuring the Splunk-only path still surfaces the required traces and metrics when O11y is off
- any later bundle refresh process should be explicitly documented rather than implicit
