// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "context"

// The ONE test helper that reads the judge's private per-session target
// history (judgeTargets, judge_packet.go). Tests read it through this file
// only, so a move of that state has one place to port. Session intent and
// recent calls are in the intent store (intentstore.Process.Peek).

// sessionTargetsForTest lists the paths a judge's session history holds.
func sessionTargetsForTest(ctx context.Context, j *LLMJudge) map[string]bool {
	entry := func() judgeTargetSession {
		t := j.judgeTargets()
		t.mu.Lock()
		defer t.mu.Unlock()
		return t.sessions[judgeSessionKey(ctx)]
	}()
	out := map[string]bool{}
	for path := range entry.targets {
		out[path] = true
	}
	return out
}
