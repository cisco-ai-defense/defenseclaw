// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2140: the decision on an action must not depend on how fast the host
// is. The dispatch had its own 50 ms deadline, so when a loaded host stalled
// the gateway the semantic rules left were skipped and a CRITICAL command
// rule only alerted: `pwsh -Command echo marker > C:/x.txt` ran under Codex
// on Windows. Here a rule checked before the marker rule stalls.
func TestTrustedActionDecisionDoesNotDependOnWallClock(t *testing.T) {
	const connector = "dispatch-budget-test"
	installRedirectReductionRules(t, connector,
		redirectReductionRule("TEST-SLOW", "a^", `f.commands.exists(c, 'dc-slow' in c.argv)`),
		redirectReductionRule(
			"TEST-MARKER-BLOCK",
			redirectReductionMarker,
			`f.commands.exists(c, '`+redirectReductionMarker+`' in c.argv)`,
		),
	)
	generation := snapshotRulePackGeneration(connector)
	rules := generation.semanticRules
	if len(rules) != 2 || rules[0].rule.ID != "TEST-SLOW" {
		t.Fatalf("semantic rules = %d, first %q", len(rules), rules[0].rule.ID)
	}
	rules[0].owner.prerequisite = func(actionfacts.Facts) bool {
		time.Sleep(80 * time.Millisecond)
		return false
	}

	command := "echo " + redirectReductionMarker
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: actionfacts.Input{
			Tool:        "shell",
			Command:     command,
			CWD:         "/home/alice/project",
			ActiveHome:  "/home/alice",
			DialectHint: actionfacts.DialectPOSIX,
		},
		LegacyText:         command,
		Connector:          connector,
		EnforcementCapable: true,
	})
	finding := findingWithID(findings, "TEST-MARKER-BLOCK")
	if finding == nil || !finding.contributesToEnforcement() {
		t.Fatalf("marker rule did not block; findings=%v", FindingStrings(findings))
	}
}
