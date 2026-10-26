// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const (
	copilotPermissionJoinTTL = 8 * time.Second
	copilotPermissionJoinMax = 4096
)

// A native Copilot permissionRequest sometimes omits the call arguments and
// call id. Only one recent, audited, allowed preToolUse in the same verified
// caller/session/directory can name the call such a callback is for. The
// join keeps that call (tool and arguments), never its decision: the
// callback is bound to the call and decided again, now, like any call, so
// the write targets as they resolve now, the live policy and the live
// sandbox floor all apply.
type copilotPermissionJoin struct {
	mu      sync.Mutex
	entries map[string]copilotPermissionEntry
}

type copilotPermissionEntry struct {
	tool      string
	args      json.RawMessage
	at        time.Time
	ambiguous bool
	// calls are the calls of an allowed parallel toolCalls envelope. Its
	// argumentless callbacks cannot say which call each is for, so each is
	// bound to every call of the envelope its tool can stand for and
	// decided again on all of them (the most restrictive verdict answers);
	// uses callbacks consume the entry (GAP-1831).
	calls []copilotargs.NativeCall
	uses  int
}

func copilotPermissionKey(ctx context.Context, req agentHookRequest) string {
	scope := copilotDedupeScope(ctx)
	if scope == "" || req.SessionID == "" || req.CWD == "" {
		return ""
	}
	return scope + "\x00" + req.SessionID + "\x00" + req.CWD
}

// record keeps the call of an audited preToolUse when allowed is true. Any
// other preToolUse in the same scope within the lifetime, allowed or not,
// leaves the next callback ambiguous.
func (j *copilotPermissionJoin) record(ctx context.Context, req agentHookRequest, allowed bool) {
	if req.ConnectorName != "copilot" || req.HookEventName != "preToolUse" ||
		req.HookSurface == connector.CopilotHookSurfaceVSCodeLocal {
		return
	}
	key := copilotPermissionKey(ctx, req)
	if key == "" {
		return
	}
	now := time.Now()
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.entries == nil {
		j.entries = make(map[string]copilotPermissionEntry)
	}
	if prior, exists := j.entries[key]; exists && now.Sub(prior.at) <= copilotPermissionJoinTTL {
		prior.ambiguous = true
		prior.at = now
		j.entries[key] = prior
		return
	}
	if len(j.entries) >= copilotPermissionJoinMax {
		for key, entry := range j.entries {
			if now.Sub(entry.at) > copilotPermissionJoinTTL {
				delete(j.entries, key)
			}
		}
		if len(j.entries) >= copilotPermissionJoinMax {
			return
		}
	}
	if raw, _ := req.Payload["toolCalls"].([]any); len(raw) > 1 {
		calls := copilotNativeToolCalls(req)
		if !allowed || len(calls) < 2 {
			return
		}
		j.entries[key] = copilotPermissionEntry{calls: append([]copilotargs.NativeCall(nil), calls...), uses: len(calls), at: now}
		return
	}
	if !allowed || req.ToolCallUnparsed || req.ToolArgsProjectionUncertain || req.ToolName == "" || len(req.ToolArgs) == 0 {
		return
	}
	j.entries[key] = copilotPermissionEntry{tool: req.ToolName, args: append(json.RawMessage(nil), req.ToolArgs...), at: now}
}

// match returns the call of the one prior preToolUse this argumentless
// callback stands for. It binds only a callback whose raw body is one
// unambiguous JSON value: a decoder keeps the last of duplicate keys, so a
// duplicate toolInput, toolName or hookName could pair a protected call with
// an empty decoded map. An argumentless callback is unparsed by design (no
// write evidence), so req.ToolCallUnparsed alone cannot refuse it; any other
// parser refusal (req.toolCallShapeUnparsed) does. Every callback consumes
// the prior call, bound or not, so no later callback can reuse it.
func (j *copilotPermissionJoin) match(ctx context.Context, req agentHookRequest, raw []byte) (string, json.RawMessage, bool) {
	calls, ok := j.bind(ctx, req, raw)
	if !ok {
		return "", nil, false
	}
	return calls[0].Name, calls[0].Args, true
}

// bind is match for every call the callback is bound to: the one call of a
// single preToolUse, or the calls of a parallel envelope the callback's tool
// can stand for (each envelope callback takes one of its uses).
func (j *copilotPermissionJoin) bind(ctx context.Context, req agentHookRequest, raw []byte) ([]copilotargs.NativeCall, bool) {
	if req.ConnectorName != "copilot" || req.HookEventName != "permissionRequest" ||
		req.HookSurface == connector.CopilotHookSurfaceVSCodeLocal {
		return nil, false
	}
	key := copilotPermissionKey(ctx, req)
	if key == "" {
		return nil, false
	}
	j.mu.Lock()
	entry, exists := j.entries[key]
	if exists && time.Since(entry.at) > copilotPermissionJoinTTL {
		delete(j.entries, key)
		exists = false
	}
	if exists {
		// This callback consumes the one prior call (or one use of an
		// envelope) even if its tool or argument shape differs. Another
		// callback cannot bind to it.
		if entry.uses > 1 {
			kept := entry
			kept.uses--
			j.entries[key] = kept
		} else {
			delete(j.entries, key)
		}
	}
	j.mu.Unlock()
	if !exists || entry.ambiguous || req.toolCallShapeUnparsed ||
		!hookToolCallJSONUnambiguous(req.ConnectorName, raw) ||
		!copilotEmptyPermissionArgs(req.Payload) {
		return nil, false
	}
	if len(entry.calls) > 0 {
		var bound []copilotargs.NativeCall
		for _, call := range entry.calls {
			if copilotPermissionToolMatches(call.Name, req.ToolName) {
				bound = append(bound, copilotargs.NativeCall{Name: call.Name, Args: append(json.RawMessage(nil), call.Args...)})
			}
		}
		return bound, len(bound) > 0
	}
	if !copilotPermissionToolMatches(entry.tool, req.ToolName) {
		return nil, false
	}
	return []copilotargs.NativeCall{{Name: entry.tool, Args: append(json.RawMessage(nil), entry.args...)}}, true
}

func copilotPermissionToolMatches(pre, permission string) bool {
	return pre == permission || pre == "apply_patch" && permission == "edit"
}

func copilotEmptyPermissionArgs(payload map[string]any) bool {
	if payload == nil || payload["hookName"] != "permissionRequest" {
		return false
	}
	for _, name := range []string{"toolCalls", "tool_name", "tool_input", "tool_args", "hook_event_name"} {
		if _, present := payload[name]; present {
			return false
		}
	}
	// Both argument fields, even empty or null, leave which one the agent
	// reads to the agent.
	_, hasInput := payload["toolInput"]
	_, hasArgs := payload["toolArgs"]
	if hasInput && hasArgs {
		return false
	}
	for _, name := range []string{"toolInput", "toolArgs"} {
		value, present := payload[name]
		if !present || value == nil {
			continue
		}
		args, ok := value.(map[string]any)
		if !ok || len(args) != 0 {
			return false
		}
	}
	return strings.TrimSpace(firstString(payload, "toolName")) != ""
}
