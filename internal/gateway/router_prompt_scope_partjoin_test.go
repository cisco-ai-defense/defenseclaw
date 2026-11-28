// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// scanInboundPrompt records the session's task scope from the joined-parts
// verdict (s7/partjoin's sessionPromptLocalVerdict), not from the raw stream
// text alone (s7/intent's ObserveSessionPromptScope): a block-array message
// whose parts the local scan blocks only once they are joined is not a task.
// The rows reuse the partjoin corpus splits, so the raw block JSON alone does
// not block and the order of the two steps decides the outcome.
func TestScanInboundPromptScopeReadsTheJoinedPartsVerdict(t *testing.T) {
	newPartJoinInspector(t, "regex_only")
	store, logger := testStoreAndLogger(t)
	r := NewEventRouter(nil, store, logger, false)
	judge := &LLMJudge{cfg: &config.JudgeConfig{Enabled: true, Timeout: 1}}
	r.SetJudge(judge)
	g := r.policyGeneration()
	rules, patterns := ruleGenerationOf(g, ""), localPatternsOf(g)
	blocks := func(v *ScanVerdict) bool {
		return v != nil && normalizedGuardrailAction(v.Action) == guardrailActionBlock
	}

	for _, tc := range partJoinCases {
		for _, n := range []int{2, 3} {
			content := string(mustJSON(t, partJoinBlocks("text", partJoinSplit(t, tc.row, tc.rule, n))))
			if blocks(scanLocalPatternsWithActivation("prompt", content, rules, patterns)) {
				t.Errorf("%s %d parts: control: the raw block JSON alone blocks, so the row does not pin the order", tc.row, n)
			}
			if !blocks(sessionPromptLocalVerdict(content, rules, patterns)) {
				t.Fatalf("%s %d parts: the joined-parts verdict does not block", tc.row, n)
			}
			sessionID := fmt.Sprintf("agent:main:pj-scope-%s-%d", tc.rule, n)
			r.scanInboundPrompt(sessionID, "", "gpt-5.5", content)
			if !judge.sessionTaskCleared(judgeSessionKey(openClawJudgeContext(sessionID))) {
				t.Errorf("%s %d parts: a prompt whose joined parts the local scan blocks was recorded as the session task", tc.row, n)
			}
		}
	}

	// Control: a benign block array is still the session's task.
	benign := string(mustJSON(t, partJoinBlocks("text", []string{"summarize the README", " of this repository"})))
	if blocks(sessionPromptLocalVerdict(benign, rules, patterns)) {
		t.Fatal("control: the benign block array blocks")
	}
	const benignSession = "agent:main:pj-scope-benign"
	r.scanInboundPrompt(benignSession, "", "gpt-5.5", benign)
	if judge.sessionTaskCleared(judgeSessionKey(openClawJudgeContext(benignSession))) {
		t.Error("control: a benign block-array prompt was not recorded as the session task")
	}
}
