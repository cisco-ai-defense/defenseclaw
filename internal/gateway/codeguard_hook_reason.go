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
	"fmt"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// CodeGuard verdicts on the files a hook event names (a file Claude Code
// changed, the files changed before Stop). The reason used to read
// "CodeGuard found 1 finding(s) in Claude Code FileChanged file": the agent
// display path redacted it whole, so the user read "DefenseClaw observed a
// MEDIUM Claude Code hook finding: <redacted len=60 sha=...>" (GAP-1954).
// codeGuardHookReason builds the reason only from ship-authored text (a
// fixed place and the built-in rules' IDs and titles), and
// trustedCodeGuardHookReason lets exactly that shape through.

// codeGuardHookReasonMaxRules is how many rules a reason names.
const codeGuardHookReasonMaxRules = 3

// The places a CodeGuard hook reason names. trustedCodeGuardHookReason
// accepts only these.
const (
	codeGuardPlaceClaudeFile         = "a file Claude Code changed"
	codeGuardPlaceClaudeInstructions = "an instructions file Claude Code loaded"
	codeGuardPlaceClaudeSettings     = "a Claude Code settings file"
	codeGuardPlaceClaudeChanged      = "the files Claude Code changed"
	codeGuardPlaceCodexChanged       = "the files Codex changed"
)

var codeGuardHookReasonPlaces = []string{
	codeGuardPlaceClaudeFile,
	codeGuardPlaceClaudeInstructions,
	codeGuardPlaceClaudeSettings,
	codeGuardPlaceClaudeChanged,
	codeGuardPlaceCodexChanged,
}

// claudeCodeCodeGuardEventPlace is the place of the file a Claude Code
// event names (scanClaudeCodeEventFile).
func claudeCodeCodeGuardEventPlace(event string) string {
	switch event {
	case "InstructionsLoaded":
		return codeGuardPlaceClaudeInstructions
	case "ConfigChange":
		return codeGuardPlaceClaudeSettings
	}
	return codeGuardPlaceClaudeFile
}

// codeGuardHookReason is "CodeGuard found N finding(s) in <place>", followed
// by the built-in rules among ruleIDs: "(rule CG-PATH-001: Potential path
// traversal)". A custom rule is counted but not named: its metadata is not
// ship-authored.
func codeGuardHookReason(place string, ruleIDs []string) string {
	noun := "findings"
	if len(ruleIDs) == 1 {
		noun = "finding"
	}
	reason := fmt.Sprintf("CodeGuard found %d %s in %s", len(ruleIDs), noun, place)
	var labels []string
	for _, id := range ruleIDs {
		label, ok := codeGuardBuiltinLabel(id)
		if !ok || slices.Contains(labels, label) {
			continue
		}
		labels = append(labels, label)
		if len(labels) == codeGuardHookReasonMaxRules {
			break
		}
	}
	switch len(labels) {
	case 0:
		return reason
	case 1:
		return reason + " (rule " + labels[0] + ")"
	}
	return reason + " (rules " + strings.Join(labels, ", ") + ")"
}

// codeGuardBuiltinLabel is "ID: Title" of a built-in CodeGuard rule.
func codeGuardBuiltinLabel(id string) (string, bool) {
	id = strings.TrimSpace(id)
	for _, rule := range scanner.BuiltinRulesMeta() {
		if strings.EqualFold(rule.ID, id) {
			return rule.ID + ": " + strings.TrimSpace(rule.Title), true
		}
	}
	return "", false
}

// trustedCodeGuardHookReason reports whether reason is exactly a
// codeGuardHookReason: a count, a known place and built-in rule labels.
func trustedCodeGuardHookReason(reason string) bool {
	rest, ok := strings.CutPrefix(reason, "CodeGuard found ")
	if !ok {
		return false
	}
	count, rest, ok := strings.Cut(rest, " ")
	if !ok || count == "" || len(count) > 3 || strings.Trim(count, "0123456789") != "" {
		return false
	}
	if rest, ok = cutAnyPrefix(rest, "findings in ", "finding in "); !ok {
		return false
	}
	if rest, ok = cutAnyPrefix(rest, codeGuardHookReasonPlaces...); !ok {
		return false
	}
	if rest == "" {
		return true
	}
	body, ok := strings.CutPrefix(rest, " (")
	if !ok {
		return false
	}
	if body, ok = strings.CutSuffix(body, ")"); !ok {
		return false
	}
	if body, ok = cutAnyPrefix(body, "rules ", "rule "); !ok {
		return false
	}
	labels := make([]string, 0, len(scanner.BuiltinRulesMeta()))
	for _, rule := range scanner.BuiltinRulesMeta() {
		labels = append(labels, rule.ID+": "+strings.TrimSpace(rule.Title))
	}
	for n := 0; n < codeGuardHookReasonMaxRules; n++ {
		if body, ok = cutAnyPrefix(body, labels...); !ok {
			return false
		}
		if body == "" {
			return true
		}
		if body, ok = strings.CutPrefix(body, ", "); !ok {
			return false
		}
	}
	return false
}

// cutAnyPrefix cuts the longest of prefixes from s.
func cutAnyPrefix(s string, prefixes ...string) (string, bool) {
	best := -1
	for i, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) && (best < 0 || len(prefix) > len(prefixes[best])) {
			best = i
		}
	}
	if best < 0 {
		return s, false
	}
	return s[len(prefixes[best]):], true
}
