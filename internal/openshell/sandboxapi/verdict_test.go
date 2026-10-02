// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
package sandboxapi

import "testing"

func TestVerdictRuleLabel(t *testing.T) {
	for in, want := range map[string]string{
		"DefenseClaw policy blocked this action (rule SEC-AWS-KEY: AWS access key). Do not retry it in another form.":     "SEC-AWS-KEY (AWS access key)",
		"DefenseClaw policy blocked this action (rules CMD-1: Destructive command, CMD-2). Do not retry it.":              "CMD-1 (Destructive command)",
		"DefenseClaw policy blocked this action (rule C2-X: webhook.site (known exfil)). Do not retry it.":                "C2-X (webhook.site (known exfil))",
		"DefenseClaw policy needs your confirmation for this action (rule CMD-1).":                                        "CMD-1",
		"DefenseClaw blocked this action under your organization's policy (rule R1: T). Do not retry it in another form.": "R1 (T)",
		"DefenseClaw policy blocked this action. Do not retry it in another form.":                                        "",
		"Allowed but flagged by DefenseClaw rule E2E-A: Alert marker. The action was allowed.":                            "E2E-A (Alert marker)",
		"Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. Try another approach.":               "E2E-SANDBOX-MARKER (E2E sandbox marker command)",
		"Blocked by DefenseClaw policy. Try another approach.":                                                            "",
		"tool Write is on the block list": "tool Write is on the block list",
	} {
		if got := VerdictRuleLabel(in); got != want {
			t.Errorf("VerdictRuleLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
