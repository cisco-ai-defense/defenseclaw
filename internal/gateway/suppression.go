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
	"strconv"
	"strings"
)

// SuppressionResult records a suppressed finding for audit logging.
type SuppressionResult struct {
	SuppressionID string `json:"suppression_id"`
	FindingID     string `json:"finding_id"`
	Entity        string `json:"entity,omitempty"`
	Reason        string `json:"reason"`
}

// StripContentForJudge applies pre-judge strip rules to remove metadata
// patterns that are known to cause false positives. The judgeType parameter
// is matched against each rule's applies_to list (e.g., "pii", "injection").
func StripContentForJudge(content, judgeType string, supp *CompiledSuppressions) string {
	if supp == nil {
		return content
	}
	for _, strip := range supp.PreJudgeStrips {
		if !stripApplies(strip.AppliesTo, judgeType) {
			continue
		}
		content = strip.Pattern.ReplaceAllString(content, "")
	}
	return content
}

// FilterJudgeFindings applies finding suppressions and returns the surviving
// finding IDs plus a list of suppressions that fired (for audit logging).
// The entities map is keyed by finding ID with a list of detected entities.
func FilterJudgeFindings(findingIDs []string, entities map[string][]string, tool string, supp *CompiledSuppressions) (surviving []string, suppressed []SuppressionResult) {
	if supp == nil {
		return findingIDs, nil
	}

	toolSuppressed := make(map[string]string)
	for _, ts := range supp.ToolSuppressions {
		if ts.ToolPattern.MatchString(tool) {
			for _, fid := range ts.SuppressFindings {
				toolSuppressed[fid] = ts.Reason
			}
		}
	}

	for _, fid := range findingIDs {
		if reason, ok := toolSuppressed[fid]; ok {
			suppressed = append(suppressed, SuppressionResult{
				SuppressionID: "tool-suppression",
				FindingID:     fid,
				Reason:        reason,
			})
			continue
		}

		entityList := entities[fid]
		if len(entityList) == 0 {
			surviving = append(surviving, fid)
			continue
		}

		allSuppressed := true
		for _, entity := range entityList {
			if !isEntitySuppressed(fid, entity, supp, &suppressed) {
				allSuppressed = false
			}
		}
		if !allSuppressed {
			surviving = append(surviving, fid)
		}
	}

	return surviving, suppressed
}

// FilterRuleFindings applies finding suppressions to RuleFinding results.
func FilterRuleFindings(findings []RuleFinding, tool string, supp *CompiledSuppressions) (surviving []RuleFinding, suppressed []SuppressionResult) {
	if supp == nil {
		return findings, nil
	}

	toolSuppressed := make(map[string]string)
	for _, ts := range supp.ToolSuppressions {
		if ts.ToolPattern.MatchString(tool) {
			for _, fid := range ts.SuppressFindings {
				toolSuppressed[fid] = ts.Reason
			}
		}
	}

	for _, f := range findings {
		if reason, ok := toolSuppressed[f.RuleID]; ok {
			suppressed = append(suppressed, SuppressionResult{
				SuppressionID: "tool-suppression",
				FindingID:     f.RuleID,
				Entity:        f.Evidence,
				Reason:        reason,
			})
			continue
		}

		entitySuppressed := false
		for _, fs := range supp.FindingSuppressions {
			if fs.FindingPattern != f.RuleID {
				continue
			}
			if fs.EntityPattern.MatchString(f.Evidence) && checkCondition(fs.Condition, f.Evidence) {
				suppressed = append(suppressed, SuppressionResult{
					SuppressionID: fs.ID,
					FindingID:     f.RuleID,
					Entity:        f.Evidence,
					Reason:        fs.Reason,
				})
				entitySuppressed = true
				break
			}
		}

		if !entitySuppressed {
			surviving = append(surviving, f)
		}
	}

	return surviving, suppressed
}

func isEntitySuppressed(findingID, entity string, supp *CompiledSuppressions, results *[]SuppressionResult) bool {
	for _, fs := range supp.FindingSuppressions {
		if fs.FindingPattern != findingID {
			continue
		}
		if fs.EntityPattern.MatchString(entity) && checkCondition(fs.Condition, entity) {
			*results = append(*results, SuppressionResult{
				SuppressionID: fs.ID,
				FindingID:     findingID,
				Entity:        entity,
				Reason:        fs.Reason,
			})
			return true
		}
	}
	return false
}

func checkCondition(condition, value string) bool {
	if condition == "" {
		return true
	}
	switch condition {
	case "is_epoch":
		return isEpochTimestamp(value)
	default:
		return false
	}
}

func isEpochTimestamp(s string) bool {
	s = strings.TrimSpace(s)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return false
	}
	return n >= 1_000_000_000 && n <= 2_100_000_000
}

// applyJudgeSuppressionsToVerdict applies finding suppressions to a ScanVerdict.
// Returns the verdict with suppressed findings removed, or an allow verdict
// if all findings are suppressed.
func applyJudgeSuppressionsToVerdict(v *ScanVerdict, tool string, supp *CompiledSuppressions) *ScanVerdict {
	if v == nil || supp == nil || v.Action == "allow" {
		return v
	}

	surviving, _ := FilterJudgeFindings(v.Findings, nil, tool, supp)

	if len(surviving) == 0 {
		return allowVerdict(v.Scanner)
	}

	result := *v
	result.Findings = surviving
	return &result
}

func stripApplies(appliesTo []string, judgeType string) bool {
	if len(appliesTo) == 0 {
		return true
	}
	for _, a := range appliesTo {
		if a == judgeType {
			return true
		}
	}
	return false
}
