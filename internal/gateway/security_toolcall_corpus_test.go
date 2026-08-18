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
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

type toolCallCorpusCase struct {
	ID               string              `json:"id"`
	RuleID           string              `json:"rule_id"`
	Tool             string              `json:"tool,omitempty"`
	Command          string              `json:"command,omitempty"`
	Argv             []string            `json:"argv,omitempty"`
	Args             json.RawMessage     `json:"args,omitempty"`
	ArgsRaw          string              `json:"args_raw,omitempty"`
	LegacyText       string              `json:"legacy_text,omitempty"`
	Dialect          actionfacts.Dialect `json:"dialect,omitempty"`
	CWD              string              `json:"cwd,omitempty"`
	ActiveHome       string              `json:"active_home,omitempty"`
	ActiveAgentFiles []string            `json:"active_agent_files,omitempty"`
	IsAttack         bool                `json:"is_attack"`
	ExpectRoute      string              `json:"expect_route"` // none | semantic | fallback
	DetectionOnly    bool                `json:"detection_only,omitempty"`
	NoOtherFinding   bool                `json:"no_other_finding,omitempty"`
}

// TestSecuritySuiteToolCall is the compact TP/FP corpus for the trusted
// structured-action lane. Parser grammar edge cases stay with ActionFacts;
// focused dispatcher tests keep special fallback and mixed-action invariants.
func TestSecuritySuiteToolCall(t *testing.T) {
	const connector = "security-toolcall-corpus"
	installDefaultProfileConnector(t, connector)

	cases := readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl")
	if len(cases) == 0 {
		t.Fatal("tool-call corpus empty")
	}
	seen := make(map[string]struct{}, len(cases))
	attacks := 0
	benign := 0
	zeroNoiseBenign := 0
	detectionOnlyAttacks := 0
	truePositive := 0
	trueNegative := 0
	falsePositive := 0
	falseNegative := 0

	for _, test := range cases {
		test := test
		t.Run(test.ID, func(t *testing.T) {
			if strings.TrimSpace(test.ID) == "" || strings.TrimSpace(test.RuleID) == "" {
				t.Fatal("id and rule_id are required")
			}
			if _, exists := seen[test.ID]; exists {
				t.Fatalf("duplicate corpus id %q", test.ID)
			}
			seen[test.ID] = struct{}{}
			switch test.ExpectRoute {
			case "none":
				benign++
				if test.NoOtherFinding {
					zeroNoiseBenign++
				}
				if test.IsAttack {
					t.Fatal("attack case cannot expect no owner finding")
				}
			case "semantic", "fallback":
				attacks++
				if !test.IsAttack {
					t.Fatal("benign case cannot expect an owner finding")
				}
				if test.DetectionOnly {
					detectionOnlyAttacks++
				}
			default:
				t.Fatalf("unsupported expect_route %q", test.ExpectRoute)
			}

			tool := strings.TrimSpace(test.Tool)
			if tool == "" {
				tool = "shell"
			}
			cwd := test.CWD
			if cwd == "" {
				cwd = "/repo"
			}
			activeHome := test.ActiveHome
			if activeHome == "" {
				activeHome = "/home/alice"
			}
			legacyText := test.LegacyText
			if legacyText == "" {
				legacyText = test.Command
			}
			input := actionfacts.Input{
				Tool:             tool,
				Args:             append(json.RawMessage(nil), test.Args...),
				Command:          test.Command,
				Argv:             append([]string(nil), test.Argv...),
				CWD:              cwd,
				ActiveHome:       activeHome,
				ActiveAgentFiles: append([]string(nil), test.ActiveAgentFiles...),
				DialectHint:      test.Dialect,
			}
			if test.ArgsRaw != "" {
				input.Args = json.RawMessage(test.ArgsRaw)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:              input,
				LegacyText:         legacyText,
				Connector:          connector,
				EnforcementCapable: true,
			})

			owner := semanticOwnerForRule(test.RuleID)
			count := 0
			var canonical *RuleFinding
			for index := range findings {
				for _, claimedID := range owner.claimedIDs(true) {
					if findings[index].RuleID != claimedID {
						continue
					}
					count++
					if findings[index].RuleID == test.RuleID {
						canonical = &findings[index]
					}
					break
				}
			}
			actualTargetFinding := count > 0
			switch {
			case test.IsAttack && actualTargetFinding:
				truePositive++
			case test.IsAttack:
				falseNegative++
			case actualTargetFinding:
				falsePositive++
			default:
				trueNegative++
			}

			if test.ExpectRoute == "none" {
				if count != 0 {
					t.Fatalf(
						"owner finding count=%d, want 0: %v facts=%+v",
						count,
						FindingStrings(findings),
						actionfacts.Analyze(input),
					)
				}
				if test.NoOtherFinding && len(findings) != 0 {
					t.Fatalf("unexpected finding noise: %v", FindingStrings(findings))
				}
				return
			}
			if count != 1 || canonical == nil {
				t.Fatalf(
					"canonical owner finding count=%d match=%v: %v facts=%+v",
					count,
					canonical,
					FindingStrings(findings),
					actionfacts.Analyze(input),
				)
			}
			if gotDetectionOnly := !canonical.contributesToEnforcement(); gotDetectionOnly != test.DetectionOnly {
				t.Fatalf(
					"detection_only=%t, want %t: %+v",
					gotDetectionOnly,
					test.DetectionOnly,
					*canonical,
				)
			}
			gotRoute := "semantic"
			if canonical.Evidence != "" {
				gotRoute = "fallback"
			}
			if gotRoute != test.ExpectRoute {
				t.Fatalf(
					"route=%s, want %s: %+v facts=%+v",
					gotRoute,
					test.ExpectRoute,
					*canonical,
					actionfacts.Analyze(input),
				)
			}
			if test.NoOtherFinding && len(findings) != 1 {
				t.Fatalf("finding noise count=%d: %v", len(findings), FindingStrings(findings))
			}
		})
	}

	if attacks == 0 || benign == 0 {
		t.Fatalf("corpus must contain both TP and FP guards: attacks=%d benign=%d", attacks, benign)
	}
	precision := corpusRatio(truePositive, truePositive+falsePositive)
	recall := corpusRatio(truePositive, truePositive+falseNegative)
	f1 := 0.0
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	t.Logf(
		"trusted target-owner corpus: TP=%d TN=%d FP=%d FN=%d precision=%.3f recall=%.3f F1=%.3f",
		truePositive, trueNegative, falsePositive, falseNegative,
		precision, recall, f1,
	)
	t.Logf(
		"scope: %d enforcement-eligible attacks, %d detection-only attacks; %d/%d benign cases require zero findings; curated regression cases, not a production-rate estimate",
		attacks-detectionOnlyAttacks,
		detectionOnlyAttacks,
		zeroNoiseBenign,
		benign,
	)
	if falsePositive != 0 || falseNegative != 0 {
		t.Fatalf(
			"tool-call corpus regression: FP=%d FN=%d",
			falsePositive,
			falseNegative,
		)
	}
}
