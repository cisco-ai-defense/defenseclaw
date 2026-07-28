// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

// Shared judge response fixtures used by the generated-v8 trace, metric, and
// log tests. Legacy EventJudge shape assertions were removed with the direct
// gateway JSONL producer.
const allFalseInjectionJSON = `{
  "Instruction Manipulation": {"reasoning": "ok", "label": false},
  "Context Manipulation": {"reasoning": "ok", "label": false},
  "Obfuscation": {"reasoning": "ok", "label": false},
  "Semantic Manipulation": {"reasoning": "ok", "label": false},
  "Token Exploitation": {"reasoning": "ok", "label": false}
}`

const allCleanPIIJSON = `{
  "Email Address": {"detection_result": false, "entities": []},
  "IP Address": {"detection_result": false, "entities": []},
  "Phone Number": {"detection_result": false, "entities": []},
  "Driver's License Number": {"detection_result": false, "entities": []},
  "Passport Number": {"detection_result": false, "entities": []},
  "Social Security Number": {"detection_result": false, "entities": []},
  "Username": {"detection_result": false, "entities": []},
  "Password": {"detection_result": false, "entities": []}
}`

const allFalseToolJSON = `{
  "Instruction Manipulation": {"reasoning": "ok", "label": false},
  "Context Manipulation": {"reasoning": "ok", "label": false},
  "Obfuscation": {"reasoning": "ok", "label": false},
  "Data Exfiltration": {"reasoning": "ok", "label": false},
  "Destructive Commands": {"reasoning": "ok", "label": false}
}`

const allFalseExfilJSON = `{
  "Sensitive File Access": {"reasoning": "ok", "label": false},
  "Exfiltration Channel": {"reasoning": "ok", "label": false}
}`
