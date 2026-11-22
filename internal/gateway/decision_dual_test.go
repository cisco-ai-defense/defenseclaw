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
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// The 1.0.10 decision, frozen as the oracle of decide.Builtin(): the
// special cases decision.go and shell_protected_file_profile.go had at
// a64bfdb931 (profileClassFloor, the unknown tier of the evaluation limit,
// managedClosesOnUnverifiedPath), copied here so the equivalence test keeps
// proving the table after the special cases are deleted.

func legacy1010ClassFloor(findings []RuleFinding, secureClient bool, strict func() bool) string {
	floor := guardrailActionAllow
	if secureClient {
		return floor
	}
	var tierRead, strictTier bool
	for _, finding := range findings {
		if !finding.contributesToEnforcement() {
			continue
		}
		selfProtection := selfProtectionRules[canonicalTrustedRuleID(finding.RuleID)]
		if selfProtection && strict != nil {
			if !tierRead {
				strictTier, tierRead = strict(), true
			}
			if strictTier {
				floor = guardrailActionBlock
			}
		}
		if finding.evaluationFault {
			floor = guardrailActionBlock
		} else if finding.shellProtectedFile || selfProtection {
			floor = strongerGuardrailAction(floor, guardrailActionAlert)
		}
	}
	return floor
}

func legacy1010WithoutLimit(findings []RuleFinding) ([]RuleFinding, bool) {
	isLimit := func(finding RuleFinding) bool {
		return finding.contributesToEnforcement() && profileMappedLimitFinding(finding)
	}
	if !slices.ContainsFunc(findings, isLimit) {
		return findings, false
	}
	return slices.DeleteFunc(slices.Clone(findings), isLimit), true
}

// legacy1010HighestSeverity is HighestSeverity at a64bfdb931: each
// finding's own label.
func legacy1010HighestSeverity(findings []RuleFinding) string {
	best, bestRank := "NONE", 0
	for _, f := range findings {
		if r := severityRank[f.Severity]; r > bestRank {
			best, bestRank = f.Severity, r
		}
	}
	return best
}

func legacy1010ActionForFindings(findings []RuleFinding, actionFor func(severity string) string) string {
	action := guardrailActionAllow
	if enforceable := enforceableRuleFindings(findings); len(enforceable) > 0 {
		action = actionFor(legacy1010HighestSeverity(enforceable))
	}
	if alerts := alertOnlyRuleFindings(findings); len(alerts) > 0 {
		candidate := actionFor(legacy1010HighestSeverity(alerts))
		if candidate == guardrailActionBlock || candidate == guardrailActionConfirm {
			candidate = guardrailActionAlert
		}
		action = strongerGuardrailAction(action, candidate)
	}
	return action
}

func legacy1010ProfileUnknown(findings []RuleFinding, secureClient bool, strict func() bool, unknown func() string,
	actionFor func(severity string) string,
) string {
	if !secureClient {
		if rest, limited := legacy1010WithoutLimit(findings); limited {
			if floor := unknown(); floor != "" {
				return strongerGuardrailAction(floor, strongerGuardrailAction(
					legacy1010ClassFloor(rest, false, strict), legacy1010ActionForFindings(rest, actionFor)))
			}
		}
	}
	return strongerGuardrailAction(legacy1010ClassFloor(findings, secureClient, strict),
		legacy1010ActionForFindings(findings, actionFor))
}

func legacy1010ManagedCloses(managed bool, findings []RuleFinding) bool {
	if !managed {
		return false
	}
	for _, finding := range enforceableRuleFindings(findings) {
		if finding.RuleID == windowsPathUnverifiedRuleID {
			return true
		}
	}
	return false
}

// TestDecideMatchesTheFrozen1010Decision runs every combination of up to
// three findings from a pool of the classes the 1.0.10 special cases read,
// on both surfaces, in every tier, deployment, Secure Client state and
// cascade unknown setting, through the frozen 1.0.10 decision and through
// decide.Decide with decide.Builtin(): 0 differences.
// ownerTruncatedCell is the owner-ruled cell of a call with an enforcing
// bound finding (2026-11-21, GAP-0851, GAP-0962): the bound alone is
// MEDIUM and the truncated row gives the action on every surface (an alert
// in default and permissive, a block in strict, guardrail.cascade.unknown
// when set). The 1.0.10 content surface mapped the bound's CRITICAL by the
// levels (a block in every pack), and strict mapped it by the levels. ok is
// false for a call the cell does not change (no enforcing bound, the
// Secure Client integration, the managed unverified-path close).
func ownerTruncatedCell(findings []RuleFinding, content, secure, packStrict bool, override string, strict func() bool,
	actionFor func(severity string) string,
) (string, bool) {
	if secure {
		return "", false
	}
	rest, limited := legacy1010WithoutLimit(findings)
	if !limited {
		return "", false
	}
	cell := override
	if cell == "" {
		cell = guardrailActionAlert
		if packStrict {
			cell = guardrailActionBlock
		}
	}
	base := legacy1010ActionForFindings(rest, actionFor)
	if !content {
		base = strongerGuardrailAction(legacy1010ClassFloor(rest, false, strict), base)
	}
	return strongerGuardrailAction(cell, base), true
}

func TestDecideMatchesTheFrozen1010Decision(t *testing.T) {
	var pool []RuleFinding
	for _, sev := range []string{"LOW", "MEDIUM", "HIGH", "CRITICAL", "high"} {
		for _, enf := range []decide.Proof{enforcingProof, advisoryProof, recordProof} {
			pool = append(pool,
				RuleFinding{RuleID: "CMD-TEST", Severity: sev, Proof: enf},
				RuleFinding{RuleID: evaluationLimitRuleID, Severity: sev, Proof: enf},
				RuleFinding{RuleID: "tamper.detector_state_write", Severity: sev, Proof: enf},
				RuleFinding{RuleID: windowsPathUnverifiedRuleID, Severity: sev, Proof: enf},
			)
		}
		pool = append(pool,
			RuleFinding{RuleID: parseFailureRuleID, Severity: sev},
			RuleFinding{RuleID: evaluationLimitRuleID, Severity: sev, omittedOperand: true},
			RuleFinding{RuleID: "CMD-TEST", Severity: sev, evaluationFault: true},
			RuleFinding{RuleID: evaluationLimitRuleID, Severity: sev, evaluationFault: true},
			RuleFinding{RuleID: "PERSISTENCE.SSH_AUTHORIZED_KEYS_COMMAND", Severity: sev, shellProtectedFile: true},
			RuleFinding{RuleID: "PATH-SSH-DIR", Severity: sev, shellProtectedFile: true, Proof: advisoryProof},
			RuleFinding{RuleID: "persistence.shell_profile_write", Severity: sev, shellProtectedFile: true},
		)
	}
	var sets [][]RuleFinding
	sets = append(sets, nil)
	for i := range pool {
		sets = append(sets, []RuleFinding{pool[i]})
		for j := i + 1; j < len(pool); j += 3 {
			sets = append(sets, []RuleFinding{pool[i], pool[j]})
			for k := j + 1; k < len(pool); k += 17 {
				sets = append(sets, []RuleFinding{pool[i], pool[j], pool[k]})
			}
		}
	}
	type levelsCase struct {
		block, alert int
		confirm      bool
		hilt         int
	}
	levelCases := []levelsCase{
		{severityCritical, severityMedium, false, severityHigh},
		{severityMedium, severityLow, false, severityHigh},
		{severityCritical, severityHigh, false, severityHigh},
		{severityCritical, severityMedium, true, severityHigh},
		{severityHigh, severityHigh, true, severityMedium},
	}
	diffs, runs := 0, 0
	for _, findings := range sets {
		for _, lc := range levelCases {
			actionFor := func(severity string) string {
				return guardrailActionForRank(guardrailSeverityRank(severity), lc.block, lc.alert, lc.confirm, lc.hilt)
			}
			for _, content := range []bool{false, true} {
				for _, managed := range []bool{false, true} {
					for _, secure := range []bool{false, true} {
						for _, hookStrict := range []bool{false, true} {
							for _, packStrict := range []bool{false, true} {
								for _, override := range []string{"", "alert", "confirm", "block"} {
									var want string
									owner, ownerRuled := ownerTruncatedCell(findings, content, secure, packStrict, override,
										func() bool { return hookStrict }, actionFor)
									switch {
									case legacy1010ManagedCloses(managed, findings):
										want = guardrailActionBlock
									case ownerRuled:
										want = owner
									case content:
										want = legacy1010ActionForFindings(findings, actionFor)
									default:
										want = legacy1010ProfileUnknown(findings, secure,
											func() bool { return hookStrict },
											func() string {
												if override != "" {
													return override
												}
												if packStrict {
													return ""
												}
												return guardrailActionAlert
											}, actionFor)
									}
									in := decide.Input{
										Findings: decideFindings(findings), SecureClient: secure,
										Levels: decideLevels(lc.block, lc.alert, lc.confirm, lc.hilt),
										Tier: func() decide.Tier {
											if hookStrict {
												return decide.TierStrict
											}
											return decide.TierDefault
										},
										PackTier: func() decide.Tier {
											if packStrict {
												return decide.TierStrict
											}
											return decide.TierPermissive
										},
										Unknown: func() (decide.Action, bool) {
											return decide.ParseAction(override), override != ""
										},
									}
									if managed {
										in.Deployment = decide.Managed
									}
									if content {
										in.Surface = decide.SurfaceContent
									}
									got := decideAction(decide.Decide(in).Action)
									runs++
									if got != want {
										diffs++
										if diffs <= 20 {
											t.Errorf("findings %s content=%v managed=%v secure=%v hookStrict=%v packStrict=%v unknown=%q levels=%+v: decide %s, 1.0.10 %s",
												describeDualFindings(findings), content, managed, secure, hookStrict, packStrict, override, lc, got, want)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if diffs > 0 {
		t.Fatalf("%d of %d decisions differ from 1.0.10", diffs, runs)
	}
	t.Logf("%d decisions, 0 differences", runs)
}

func describeDualFindings(findings []RuleFinding) string {
	parts := make([]string, len(findings))
	for i, f := range findings {
		parts[i] = fmt.Sprintf("{%s %s proof=%s fault=%v omitted=%v spf=%v}", f.RuleID, f.Severity, f.Proof,
			f.evaluationFault, f.omittedOperand, f.shellProtectedFile)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// The characterization recorder (DET111 step 1). With DET111_S1_REC=<file>,
// each distinct (route, connector, deployment, Secure Client, surface,
// tier, pack tier, cascade unknown, levels, findings) -> (action,
// severity) row of a gateway test decision is appended to the file once
// (JSON lines). Collisions (one proof key, two actions) are read from the
// file offline. (The dual run that compared these rows with the 1.0.10
// path, DET111_S1_DUAL, ran at b900f4e77b; the frozen oracle above keeps
// the table equal to it.)
func init() {
	path := os.Getenv("DET111_S1_REC")
	if path == "" {
		return
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		panic(err)
	}
	var mu sync.Mutex
	seen := map[string]bool{}
	decideRecordHook = func(route, connector string, in decide.Input, got decide.Output) {
		row := dualRow(route, connector, in, got)
		key, _ := json.Marshal(row)
		mu.Lock()
		defer mu.Unlock()
		if seen[string(key)] {
			return
		}
		seen[string(key)] = true
		_, _ = out.Write(append(key, '\n'))
	}
}

type dualFinding struct {
	Rule    string `json:"rule"`
	Proof   string `json:"proof"`
	Sev     string `json:"sev"`
	Ceiling uint8  `json:"ceiling,omitempty"`
}

type dualRecord struct {
	Route      string        `json:"route"`
	Connector  string        `json:"connector"`
	Deployment string        `json:"deployment"`
	Secure     bool          `json:"secure_client,omitempty"`
	Surface    uint8         `json:"surface,omitempty"`
	Tier       string        `json:"tier"`
	PackTier   string        `json:"pack_tier"`
	Unknown    string        `json:"unknown,omitempty"`
	Levels     string        `json:"levels"`
	Findings   []dualFinding `json:"findings"`
	Decide     string        `json:"decide"`
	Severity   string        `json:"severity"`
}

func dualRow(route, connector string, in decide.Input, got decide.Output) dualRecord {
	row := dualRecord{
		Route: route, Connector: connector, Deployment: in.Deployment.String(), Secure: in.SecureClient,
		Surface: uint8(in.Surface), Decide: decideAction(got.Action),
		Severity: got.Severity.String(),
		Levels:   fmt.Sprintf("%v/%v/%v@%v", in.Levels.Block, in.Levels.Alert, in.Levels.Confirm, in.Levels.ConfirmAt),
	}
	if in.Tier != nil {
		row.Tier = in.Tier().String()
	}
	row.PackTier = row.Tier
	if in.PackTier != nil {
		row.PackTier = in.PackTier().String()
	}
	if in.Unknown != nil {
		if u, ok := in.Unknown(); ok {
			row.Unknown = u.String()
		}
	}
	for _, f := range in.Findings {
		row.Findings = append(row.Findings, dualFinding{Rule: canonicalTrustedRuleID(f.RuleID), Proof: f.Proof.String(), Sev: f.Severity.String()})
	}
	sort.Slice(row.Findings, func(i, j int) bool {
		a, b := row.Findings[i], row.Findings[j]
		return a.Rule+a.Proof+a.Sev < b.Rule+b.Proof+b.Sev
	})
	return row
}
