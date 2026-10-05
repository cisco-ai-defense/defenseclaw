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
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"
)

// A Claude Code tool call that needs the user's approval reaches the hook
// twice: PreToolUse, then PermissionRequest with the same tool input. Both
// are evaluated, since each can enforce, but emitting the findings of both
// turned one call into two identical alerts (GAP-1955). A PermissionRequest
// that follows a PreToolUse with the same session, tool, input and verdict
// reuses that PreToolUse's evaluation instead of emitting its findings again.

const (
	claudeCodePreActionEvalWindow     = 2 * time.Minute
	claudeCodePreActionEvalMaxEntries = 512
)

type claudeCodePreActionEval struct {
	eval hookEvaluationContext
	seen time.Time
}

// claudeCodePreActionEvalCache holds the evaluation of each recent
// PreToolUse with findings until its PermissionRequest takes it.
type claudeCodePreActionEvalCache struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]claudeCodePreActionEval
}

func (c *claudeCodePreActionEvalCache) remember(key [sha256.Size]byte, eval hookEvaluationContext, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[[sha256.Size]byte]claudeCodePreActionEval)
	}
	for k, entry := range c.entries {
		if now.Sub(entry.seen) >= claudeCodePreActionEvalWindow {
			delete(c.entries, k)
		}
	}
	if len(c.entries) >= claudeCodePreActionEvalMaxEntries {
		return
	}
	c.entries[key] = claudeCodePreActionEval{eval: eval, seen: now}
}

func (c *claudeCodePreActionEvalCache) take(key [sha256.Size]byte, now time.Time) (hookEvaluationContext, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return hookEvaluationContext{}, false
	}
	delete(c.entries, key)
	if now.Sub(entry.seen) >= claudeCodePreActionEvalWindow {
		return hookEvaluationContext{}, false
	}
	return entry.eval, true
}

// claudeCodePreActionEvalKey keys a PreToolUse or PermissionRequest
// evaluation with findings; ok is false for any other one.
func claudeCodePreActionEvalKey(req claudeCodeHookRequest, verdict *ToolInspectVerdict) (key [sha256.Size]byte, ok bool) {
	if req.HookEventName != "PreToolUse" && req.HookEventName != "PermissionRequest" {
		return key, false
	}
	if verdict == nil || len(verdict.DetailedFindings) == 0 || strings.TrimSpace(req.SessionID) == "" {
		return key, false
	}
	findings := append([]string(nil), verdict.Findings...)
	sort.Strings(findings)
	input, err := json.Marshal(struct {
		SessionID, Tool, Args, Action, Severity string
		Findings                                []string
	}{
		SessionID: req.SessionID,
		Tool:      claudeCodeToolName(req),
		Args:      string(claudeCodeToolArgs(req)),
		Action:    verdict.Action,
		Severity:  verdict.Severity,
		Findings:  findings,
	})
	if err != nil {
		return key, false
	}
	return sha256.Sum256(input), true
}

// emitClaudeCodeHookRuleFindings is emitHookRuleFindings for a Claude Code
// event, emitting the findings of a tool call once across its PreToolUse
// and PermissionRequest.
func (a *APIServer) emitClaudeCodeHookRuleFindings(
	ctx context.Context,
	req claudeCodeHookRequest,
	verdict *ToolInspectVerdict,
	latency time.Duration,
) hookEvaluationContext {
	key, keyed := claudeCodePreActionEvalKey(req, verdict)
	if keyed && req.HookEventName == "PermissionRequest" {
		if eval, ok := a.claudeCodePreActionEvals.take(key, time.Now()); ok {
			return eval
		}
	}
	eval := a.emitHookRuleFindings(ctx, "claudecode", req.HookEventName, verdict,
		hookTargetTypeForEvent(req.HookEventName), latency)
	if keyed && req.HookEventName == "PreToolUse" && eval.EvaluationID != "" {
		a.claudeCodePreActionEvals.remember(key, eval, time.Now())
	}
	return eval
}
