// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import "fmt"

// CodeJudgeFailing names an LLM judge whose recent calls all failed, or that
// could not start.
const CodeJudgeFailing = "judge_failing"

// JudgeHealth is the LLM judge state the gateway publishes in /health
// (guardrail.details). A judge that stops answering silently downgrades
// detection to the static rules; only /health and the journal said so
// (GAP-0626 on Linux and macOS, GAP-1026 on Windows).
type JudgeHealth struct {
	State       string `json:"judge_state"`
	Unavailable string `json:"judge_unavailable_reason"`
	Recent      int    `json:"judge_recent_calls"`
	Failed      int    `json:"judge_failed_calls"`
	LastError   string `json:"judge_last_error"`
	LastFailure string `json:"judge_last_failure_at"`
}

// Warning is the judge_failing message for a failing or unavailable judge;
// ok is false for any other state.
func (j JudgeHealth) Warning() (message string, ok bool) {
	switch j.State {
	case "failing":
		return fmt.Sprintf("the LLM judge failed its last %d calls (last at %s: %s); the rule packs still apply, but the judge's checks do not until it recovers: check the judge's provider credentials and network",
			j.Failed, j.LastFailure, j.LastError), true
	case "unavailable":
		return "the LLM judge is unavailable (" + j.Unavailable + "); the rule packs still apply, but the judge's checks do not: check the judge settings and its provider credentials", true
	}
	return "", false
}
