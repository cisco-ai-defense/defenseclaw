// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"testing"
)

// rel-1-0-3 GAP-0244: the process-local hook caches a flood fills are bounded.
// A long single-session flood of distinct tool calls (PreToolUse only, the
// worst case: no PostToolUse ever pops a pending invocation) leaves each cache
// at or under its bound, and a second flood in another session does not raise
// it past the bound.
func TestHookFloodCachesStayBoundedAcrossFloods(t *testing.T) {
	api := &APIServer{}
	sizes := func() map[string]int {
		api.llmPromptMu.Lock()
		defer api.llmPromptMu.Unlock()
		return map[string]int{
			"hookPhaseStates":              len(api.hookPhaseStates),
			"hookPhaseStateOrder":          len(api.hookPhaseStateOrder),
			"hookLifecycleTransitions":     len(api.hookLifecycleTransitions),
			"hookLifecycleTransitionOrder": len(api.hookLifecycleTransitionOrder),
			"hookToolInvocations":          len(api.hookToolInvocations),
			"hookToolInvocationOrder":      len(api.hookToolInvocationOrder),
		}
	}
	flood := func(round int) map[string]int {
		session := fmt.Sprintf("s-flood-%d", round)
		for i := range hookPromptCacheMaxEntries + hookPromptCacheMaxEntries/2 {
			api.emitClaudeCodeHookLLMEvent(t.Context(),
				claudePreToolUseForOperationTest(session, fmt.Sprintf("toolu_%d_%06d", round, i)), nil, nil)
		}
		return sizes()
	}
	first := flood(1)
	for name, size := range first {
		if size > hookPromptCacheMaxEntries {
			t.Errorf("after the first flood %s holds %d entries, bound %d", name, size, hookPromptCacheMaxEntries)
		}
	}
	second := flood(2)
	for name, size := range second {
		if size > hookPromptCacheMaxEntries {
			t.Errorf("after the second flood %s holds %d entries (first flood %d, bound %d)",
				name, size, first[name], hookPromptCacheMaxEntries)
		}
	}
}
