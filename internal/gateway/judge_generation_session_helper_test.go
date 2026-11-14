// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "context"

// The ONE test helper that reads the judge's private per-session state
// (toolContext). Tests seed and read session state through it only, so a
// move of that state (feat/substrate's intentstore) has one place to port.

// carrySessionForTest copies sessionID's context from one judge to another by
// value, as a rebuilt judge does when it keeps a live session (s7/intent's
// inheritToolJudgeContext copies the entry and its event slice).
func carrySessionForTest(ctx context.Context, from, to *LLMJudge) {
	key := judgeSessionKey(ctx)
	from.toolContextMu.Lock()
	entry := from.toolContext[key]
	entry.events = append([]toolJudgeContextEvent(nil), entry.events...)
	from.toolContextMu.Unlock()
	to.toolContextMu.Lock()
	if to.toolContext == nil {
		to.toolContext = make(map[string]toolJudgeSessionContext)
	}
	to.toolContext[key] = entry
	to.toolContextMu.Unlock()
}

// sessionTargetsForTest lists the paths a judge's session history holds.
func sessionTargetsForTest(ctx context.Context, j *LLMJudge) map[string]bool {
	j.toolContextMu.Lock()
	defer j.toolContextMu.Unlock()
	out := map[string]bool{}
	for path := range j.toolContext[judgeSessionKey(ctx)].targets {
		out[path] = true
	}
	return out
}
