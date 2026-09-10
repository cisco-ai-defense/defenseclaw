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
	"path/filepath"
	"slices"
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
	ProfilePosture   string              `json:"profile_posture,omitempty"`
	ProfileRuleIDs   map[string]string   `json:"profile_rule_ids,omitempty"`
}

const toolCallCorpusStrictOnlyPosture = "strict_only"

var toolCallCorpusProfiles = []string{"default", "permissive", "strict"}

func toolCallCorpusActionFactsInput(test toolCallCorpusCase) actionfacts.Input {
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
	return input
}

// TestSecuritySuiteToolCall is the compact TP/FP corpus for the trusted
// structured-action lane. Parser grammar edge cases stay with ActionFacts;
// focused dispatcher tests keep special fallback and mixed-action invariants.
func TestSecuritySuiteToolCall(t *testing.T) {
	const connector = "security-toolcall-corpus"
	cases := readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl")
	if len(cases) == 0 {
		t.Fatal("tool-call corpus empty")
	}
	seen := make(map[string]struct{}, len(cases))
	for _, test := range cases {
		if strings.TrimSpace(test.ID) == "" || strings.TrimSpace(test.RuleID) == "" {
			t.Fatal("id and rule_id are required")
		}
		if _, exists := seen[test.ID]; exists {
			t.Fatalf("duplicate corpus id %q", test.ID)
		}
		seen[test.ID] = struct{}{}
		switch test.ExpectRoute {
		case "none":
			if test.IsAttack {
				t.Fatalf("case %q: attack case cannot have a universally absent owner finding", test.ID)
			}
		case "semantic", "fallback":
			if !test.IsAttack {
				t.Fatalf("case %q: benign case cannot expect an owner finding", test.ID)
			}
		default:
			t.Fatalf("case %q: unsupported expect_route %q", test.ID, test.ExpectRoute)
		}
		if test.ProfilePosture != "" && test.ProfilePosture != toolCallCorpusStrictOnlyPosture {
			t.Fatalf("case %q: unsupported profile_posture %q", test.ID, test.ProfilePosture)
		}
		for profile, ruleID := range test.ProfileRuleIDs {
			if !slices.Contains(toolCallCorpusProfiles, profile) || strings.TrimSpace(ruleID) == "" {
				t.Fatalf("case %q: invalid profile rule override %q=%q", test.ID, profile, ruleID)
			}
		}
	}

	for _, profile := range toolCallCorpusProfiles {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, connector, profile)
			runToolCallCorpusProfile(t, connector, profile, cases)
		})
	}
}

func runToolCallCorpusProfile(t *testing.T, connector, profile string, cases []toolCallCorpusCase) {
	t.Helper()
	var detection, enforcement toolCallStateConfusionMatrix
	attacks := 0
	benign := 0
	attackDetections := 0
	attackEnforcementEligible := 0
	benignDetections := 0

	for _, test := range cases {
		test := test
		t.Run(test.ID, func(t *testing.T) {
			expectRoute := test.ExpectRoute
			expectDetectionOnly := test.DetectionOnly
			expectedRuleID := test.RuleID
			if profileRuleID := test.ProfileRuleIDs[profile]; profileRuleID != "" {
				expectedRuleID = profileRuleID
			}
			strictOnlySuppressed := test.ProfilePosture == toolCallCorpusStrictOnlyPosture && profile != "strict"
			if strictOnlySuppressed {
				expectRoute = "none"
				expectDetectionOnly = false
			}

			legacyText := test.LegacyText
			if legacyText == "" {
				legacyText = test.Command
			}
			input := toolCallCorpusActionFactsInput(test)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:              input,
				LegacyText:         legacyText,
				Connector:          connector,
				EnforcementCapable: true,
			})

			owner := semanticOwnerForRule(expectedRuleID)
			count := 0
			var canonical *RuleFinding
			for index := range findings {
				for _, claimedID := range owner.claimedIDs(true) {
					if findings[index].RuleID != claimedID {
						continue
					}
					count++
					if findings[index].RuleID == expectedRuleID {
						canonical = &findings[index]
					}
					break
				}
			}

			actualDetection := count > 0
			actualEnforcement := canonical != nil && canonical.contributesToEnforcement()
			expectedDetection := expectRoute != "none"
			expectedEnforcement := expectedDetection && !expectDetectionOnly
			detection.observe(expectedDetection, actualDetection)
			enforcement.observe(expectedEnforcement, actualEnforcement)
			if test.IsAttack {
				attacks++
				if actualDetection {
					attackDetections++
				}
				if actualEnforcement {
					attackEnforcementEligible++
				}
			} else {
				benign++
				if actualDetection {
					benignDetections++
				}
			}

			if expectRoute == "none" {
				if count != 0 {
					t.Fatalf(
						"profile=%s owner finding count=%d, want 0: %v facts=%+v",
						profile, count, FindingStrings(findings), actionfacts.Analyze(input),
					)
				}
				if (test.NoOtherFinding || strictOnlySuppressed) && len(findings) != 0 {
					t.Fatalf("profile=%s unexpected finding noise: %v", profile, FindingStrings(findings))
				}
				return
			}
			if count != 1 || canonical == nil {
				t.Fatalf(
					"profile=%s canonical owner finding count=%d match=%v: %v facts=%+v",
					profile, count, canonical, FindingStrings(findings), actionfacts.Analyze(input),
				)
			}
			if gotDetectionOnly := !canonical.contributesToEnforcement(); gotDetectionOnly != expectDetectionOnly {
				t.Fatalf(
					"profile=%s detection_only=%t, want %t: %+v",
					profile, gotDetectionOnly, expectDetectionOnly, *canonical,
				)
			}
			gotRoute := "semantic"
			if canonical.Evidence != "" {
				gotRoute = "fallback"
			}
			if gotRoute != expectRoute {
				t.Fatalf(
					"profile=%s route=%s, want %s: %+v facts=%+v",
					profile, gotRoute, expectRoute, *canonical, actionfacts.Analyze(input),
				)
			}
			if test.NoOtherFinding && len(findings) != 1 {
				t.Fatalf("profile=%s finding noise count=%d: %v", profile, len(findings), FindingStrings(findings))
			}
		})
	}

	detectionPrecision, detectionRecall, detectionF1 := detection.metrics()
	enforcementPrecision, enforcementRecall, enforcementF1 := enforcement.metrics()
	t.Logf(
		"profile=%s posture detection: TP=%d TN=%d FP=%d FN=%d precision=%.3f recall=%.3f F1=%.3f",
		profile, detection.truePositive, detection.trueNegative, detection.falsePositive, detection.falseNegative,
		detectionPrecision, detectionRecall, detectionF1,
	)
	t.Logf(
		"profile=%s posture enforcement eligibility: TP=%d TN=%d FP=%d FN=%d precision=%.3f recall=%.3f F1=%.3f",
		profile, enforcement.truePositive, enforcement.trueNegative, enforcement.falsePositive, enforcement.falseNegative,
		enforcementPrecision, enforcementRecall, enforcementF1,
	)
	t.Logf(
		"profile=%s source-label coverage: malicious=%d detected=%d enforcement_eligible=%d; benign=%d detected=%d FPR=%.3f; curated regression, not a production-rate estimate",
		profile, attacks, attackDetections, attackEnforcementEligible,
		benign, benignDetections, corpusRatio(benignDetections, benign),
	)
	if detection.falsePositive != 0 || detection.falseNegative != 0 ||
		enforcement.falsePositive != 0 || enforcement.falseNegative != 0 {
		t.Fatalf(
			"profile=%s tool-call posture regression: detection FP=%d FN=%d; enforcement FP=%d FN=%d",
			profile, detection.falsePositive, detection.falseNegative,
			enforcement.falsePositive, enforcement.falseNegative,
		)
	}
}

func installToolCallCorpusProfileConnector(t *testing.T, connector, profile string) {
	t.Helper()
	ruleCategoriesMu.Lock()
	savedCategories, hadCategories := connectorRuleCategories[connector]
	savedGeneration, hadGeneration := connectorRuleGenerations[connector]
	ruleCategoriesMu.Unlock()
	t.Cleanup(func() {
		ruleCategoriesMu.Lock()
		defer ruleCategoriesMu.Unlock()
		if hadCategories {
			connectorRuleCategories[connector] = savedCategories
		} else {
			delete(connectorRuleCategories, connector)
		}
		if hadGeneration {
			connectorRuleGenerations[connector] = savedGeneration
		} else {
			delete(connectorRuleGenerations, connector)
		}
	})

	pack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), profile))
	if err := ApplyConnectorRulePackOverrides(connector, pack); err != nil {
		t.Fatal(err)
	}
}
