// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Owner decision 2026-11-13 (GAP-0045): in the default pack a lone MEDIUM
// "needs review" finding of the opt-in tool judge is audit only (recorded, no
// alert). Strict keeps today's mapping: its block_at is MEDIUM, so the finding
// blocks there. A rule finding on the same call keeps today's behaviour, and
// HIGH judge verdicts are unchanged.

const (
	reviewOnlyJudgeMedium = `{"findings": [{"category": "Sensitive Data Access", "signal_strength": "needs_review", "reasoning": "r"}]}`
	reviewOnlyJudgeTwo    = `{"findings": [` +
		`{"category": "Sensitive Data Access", "signal_strength": "needs_review", "reasoning": "r"},` +
		`{"category": "Security Control Change", "signal_strength": "needs_review", "reasoning": "r"}]}`
	reviewOnlyJudgeSignal = `{"findings": [{"category": "Obfuscation", "signal_strength": "signal", "reasoning": "r"}]}`
)

func TestToolJudgeMarksALoneReviewFinding(t *testing.T) {
	for _, tc := range []struct {
		name, answer string
		sev          string
		reviewOnly   bool
	}{
		{"one needs_review", reviewOnlyJudgeMedium, "MEDIUM", true},
		{"two needs_review", reviewOnlyJudgeTwo, "MEDIUM", false},
		{"one actionable signal", reviewOnlyJudgeSignal, "MEDIUM", false},
		{"HIGH", escalationJudgeHigh, "HIGH", false},
		{"clean", escalationJudgeClean, "NONE", false},
	} {
		v := toolInjectionToVerdict(parseJudgeJSON(tc.answer))
		if v.reviewOnly != tc.reviewOnly || (tc.sev != "NONE" && v.Severity != tc.sev) {
			t.Errorf("%s: severity=%s reviewOnly=%v, want %s %v", tc.name, v.Severity, v.reviewOnly, tc.sev, tc.reviewOnly)
		}
	}
}

func TestJudgeReviewOnlyAuditOnlyInTheDefaultPack(t *testing.T) {
	lone := toolInjectionToVerdict(parseJudgeJSON(reviewOnlyJudgeMedium))
	cfgFor := func(pack string) *config.Config {
		cfg := config.DefaultConfig()
		cfg.DataDir = t.TempDir()
		cfg.Guardrail.RulePack = pack
		cfg.Guardrail.RulePackDir = ""
		return cfg
	}
	for _, tc := range []struct {
		name      string
		cfg       *config.Config
		flagged   bool
		v         *ScanVerdict
		wantAllow bool
	}{
		{"default lone", cfgFor("default"), false, lone, true},
		{"default lone + rule finding", cfgFor("default"), true, lone, false},
		{"strict lone", cfgFor("strict"), false, lone, false},
		{"permissive lone", cfgFor("permissive"), false, lone, true},
		{"default HIGH", cfgFor("default"), false, toolInjectionToVerdict(parseJudgeJSON(escalationJudgeHigh)), false},
		{"default two review findings", cfgFor("default"), false, toolInjectionToVerdict(parseJudgeJSON(reviewOnlyJudgeTwo)), false},
	} {
		lane := judgeReviewOnlyAudit(tc.cfg, "claudecode", tc.flagged, hookJudgeLaneVerdict(tc.cfg, "claudecode", "tool_call", tc.v))
		if lane == nil {
			t.Fatalf("%s: nil lane verdict", tc.name)
		}
		if allowed := lane.Action == guardrailActionAllow; allowed != tc.wantAllow {
			t.Errorf("%s: action=%s, want allow=%v", tc.name, lane.Action, tc.wantAllow)
		}
		if len(lane.Findings) == 0 {
			t.Errorf("%s: the judge finding must stay on the verdict so it is recorded", tc.name)
		}
	}
}

// End to end on the Claude Code hook, default and strict packs: a lone MEDIUM,
// a MEDIUM on a call a rule flagged (an unprovable CRITICAL pattern finding),
// and a HIGH.
func TestHookJudgeLoneReviewFindingByPack(t *testing.T) {
	const plain = "ls -la ./fixtures/reports"
	flagged := pythonWrapped("cat ~/.ssh/id_rsa")
	for _, tc := range []struct {
		pack, answer, command string
		want                  string // raw_action
	}{
		{"default", reviewOnlyJudgeMedium, plain, guardrailActionAllow},
		{"default", reviewOnlyJudgeMedium, flagged, guardrailActionAlert},
		{"default", escalationJudgeHigh, plain, guardrailActionAlert},
		{"strict", reviewOnlyJudgeMedium, plain, guardrailActionBlock}, // strict block_at MEDIUM, unchanged
		{"strict", reviewOnlyJudgeMedium, flagged, ""},                 // today's strict answer for the rule finding: checked below
		{"strict", escalationJudgeHigh, plain, guardrailActionBlock},
	} {
		name := tc.pack + "/" + map[string]string{reviewOnlyJudgeMedium: "lone-medium", escalationJudgeHigh: "high"}[tc.answer]
		if tc.command == flagged {
			name += "+rule"
		}
		t.Run(name, func(t *testing.T) {
			judge := &mockLLMProvider{response: &ChatResponse{Choices: []ChatChoice{{Message: &ChatMessage{Content: tc.answer}}}}}
			a := escalationHookServerWith(t, judge, tc.pack, nil)
			resp := escalationPreToolUse(t, a, tc.command)
			if len(judge.captured) != 1 {
				t.Fatalf("judge calls=%d, want 1", len(judge.captured))
			}
			hasJudge := false
			for _, f := range resp.Findings {
				hasJudge = hasJudge || strings.HasPrefix(f, "llm-judge:")
			}
			if !hasJudge {
				t.Fatalf("findings %v: the judge finding must be recorded", resp.Findings)
			}
			if tc.want == "" {
				// The rule finding keeps the call at least alerted, as before.
				if resp.RawAction == guardrailActionAllow {
					t.Fatalf("raw_action=allow on a rule-flagged call: %+v", resp)
				}
				return
			}
			if resp.RawAction != tc.want {
				t.Fatalf("raw_action=%q findings=%v, want %q", resp.RawAction, resp.Findings, tc.want)
			}
		})
	}
}

// Review findings (Opus, b276bf3ece): a decision-model HIGH floor over a lone
// judge review finding keeps its alert, and a low rule finding on the call
// keeps the judge MEDIUM an alert.
func TestJudgeReviewOnlyAuditKeepsMergedAndFlaggedVerdicts(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	lone := toolInjectionToVerdict(parseJudgeJSON(reviewOnlyJudgeMedium))
	floor := &ScanVerdict{Action: "block", Severity: "HIGH", Findings: []string{decisionModelFindingID}, Scanner: decisionModelScanner}
	merged := strongerDecisionVerdict(lone, floor)
	if merged.reviewOnly {
		t.Fatal("the decision-model floor must clear the review-only mark")
	}
	stale := *merged
	stale.reviewOnly = true // a merge that copied the mark
	for name, v := range map[string]*ScanVerdict{"merged": merged, "stale mark": &stale} {
		lane := judgeReviewOnlyAudit(cfg, "claudecode", false, hookJudgeLaneVerdict(cfg, "claudecode", "tool_call", v))
		if lane.Action != guardrailActionAlert {
			t.Errorf("%s: HIGH decision-model floor over a lone review finding gave %s, want alert", name, lane.Action)
		}
	}
	low := &ToolInspectVerdict{Action: "allow", Severity: "LOW",
		DetailedFindings: []RuleFinding{{RuleID: "R-LOW", Severity: "LOW"}}}
	lane := judgeReviewOnlyAudit(cfg, "claudecode", rulesFlagged(low), hookJudgeLaneVerdict(cfg, "claudecode", "tool_call", lone))
	if lane.Action != guardrailActionAlert {
		t.Fatalf("a LOW rule finding plus a lone judge MEDIUM gave %s, want today's alert", lane.Action)
	}
}
