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
	at        time.Time
	ambiguous bool
	// calls are the calls of one allowed preToolUse (one, or those of a
	// parallel toolCalls envelope) that one callback tool can stand for.
	// An argumentless callback cannot say which of them it is for, so it is
	// bound to all of them and decided again on each (the most restrictive
	// verdict answers); uses callbacks consume the entry (GAP-1831).
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

// copilotPermissionCallbackTool is the tool name of the permissionRequest
// a call's callback carries: apply_patch and create calls ask as edit.
// Entries are kept per callback tool, because a callback can stand only for
// a call of its own tool: a call of another tool (a read, or a shell command
// the agent approves itself) never gets this callback, so it can neither be
// bound to it nor make it ambiguous (GAP-1924). A create callback carries
// its own arguments; keyed with the patches of its envelope it takes its
// own use instead of the one an argumentless patch callback needs
// (GAP-1961).
func copilotPermissionCallbackTool(tool string) string {
	tool = strings.TrimSpace(tool)
	if tool == "apply_patch" || tool == "create" {
		return "edit"
	}
	return tool
}

// copilotPermissionCallsNeedTheJoin reports whether an argumentless
// callback can stand for one of the calls: every call but a create or edit,
// whose callbacks always carry their own arguments.
func copilotPermissionCallsNeedTheJoin(calls []copilotargs.NativeCall) bool {
	for _, call := range calls {
		if name := strings.TrimSpace(call.Name); name != "create" && name != "edit" {
			return true
		}
	}
	return false
}

func copilotPermissionToolKey(scope, tool string) string {
	return scope + "\x00" + copilotPermissionCallbackTool(tool)
}

// record keeps the calls of an audited preToolUse when allowed is true, one
// entry per callback tool. Any other preToolUse in the same scope within
// the lifetime, allowed or not, leaves the next callback of the same tool
// ambiguous; a preToolUse whose calls cannot be read leaves every callback
// of the scope ambiguous.
func (j *copilotPermissionJoin) record(ctx context.Context, req agentHookRequest, allowed bool) {
	if req.ConnectorName != "copilot" || req.HookEventName != "preToolUse" ||
		req.HookSurface == connector.CopilotHookSurfaceVSCodeLocal {
		return
	}
	scope := copilotPermissionKey(ctx, req)
	if scope == "" {
		return
	}
	var calls []copilotargs.NativeCall
	readable := true
	if raw, _ := req.Payload["toolCalls"].([]any); len(raw) > 1 {
		calls = copilotNativeToolCalls(req)
		readable = len(calls) >= 2
	} else if req.ToolCallUnparsed || strings.TrimSpace(req.ToolName) == "" {
		readable = false
	} else {
		calls = []copilotargs.NativeCall{{Name: req.ToolName, Args: req.ToolArgs}}
		allowed = allowed && !req.ToolArgsProjectionUncertain && len(req.ToolArgs) > 0
	}
	now := time.Now()
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.entries == nil {
		j.entries = make(map[string]copilotPermissionEntry)
	}
	if !readable {
		for key, prior := range j.entries {
			if strings.HasPrefix(key, scope+"\x00") && now.Sub(prior.at) <= copilotPermissionJoinTTL {
				prior.ambiguous = true
				prior.at = now
				j.entries[key] = prior
			}
		}
		return
	}
	byKey := make(map[string][]copilotargs.NativeCall)
	var keys []string
	for _, call := range calls {
		key := copilotPermissionToolKey(scope, call.Name)
		if _, seen := byKey[key]; !seen {
			keys = append(keys, key)
		}
		byKey[key] = append(byKey[key], copilotargs.NativeCall{Name: call.Name, Args: append(json.RawMessage(nil), call.Args...)})
	}
	for _, key := range keys {
		if prior, exists := j.entries[key]; exists && now.Sub(prior.at) <= copilotPermissionJoinTTL {
			prior.ambiguous = true
			prior.at = now
			j.entries[key] = prior
			continue
		}
		// A call whose own callback carries its arguments (create and edit
		// ask with {file_path, diff}) never needs the join, so it is not
		// kept: when its callback does not arrive, it cannot make the next
		// patch's argumentless callback ambiguous (GAP-2012). It still makes
		// a live entry of its tool ambiguous (above), and inside an envelope
		// with a patch it still counts as a use (GAP-1961).
		if !allowed || !copilotPermissionCallsNeedTheJoin(byKey[key]) {
			continue
		}
		if len(j.entries) >= copilotPermissionJoinMax {
			for old, entry := range j.entries {
				if now.Sub(entry.at) > copilotPermissionJoinTTL {
					delete(j.entries, old)
				}
			}
			if len(j.entries) >= copilotPermissionJoinMax {
				continue
			}
		}
		j.entries[key] = copilotPermissionEntry{calls: byKey[key], uses: len(byKey[key]), at: now}
	}
}

// match returns the call of the one prior preToolUse this argumentless
// callback stands for. It binds only a callback whose raw body is one
// unambiguous JSON value: a decoder keeps the last of duplicate keys, so a
// duplicate toolInput, toolName or hookName could pair a protected call with
// an empty decoded map. An argumentless callback is unparsed by design (no
// write evidence), so req.ToolCallUnparsed alone cannot refuse it; any other
// parser refusal (req.toolCallShapeUnparsed) does. Every callback consumes
// the prior call of its tool, bound or not, so no later callback can reuse
// it.
func (j *copilotPermissionJoin) match(ctx context.Context, req agentHookRequest, raw []byte) (string, json.RawMessage, bool) {
	calls, ok := j.bind(ctx, req, raw)
	if !ok {
		return "", nil, false
	}
	return calls[0].Name, calls[0].Args, true
}

// bind is match for every call the callback is bound to: the one call of a
// single preToolUse, or the calls of a parallel envelope the callback's tool
// can stand for (each callback takes one of their uses).
func (j *copilotPermissionJoin) bind(ctx context.Context, req agentHookRequest, raw []byte) ([]copilotargs.NativeCall, bool) {
	if req.ConnectorName != "copilot" || req.HookEventName != "permissionRequest" ||
		req.HookSurface == connector.CopilotHookSurfaceVSCodeLocal {
		return nil, false
	}
	scope := copilotPermissionKey(ctx, req)
	if scope == "" {
		return nil, false
	}
	key := copilotPermissionToolKey(scope, req.ToolName)
	j.mu.Lock()
	entry, exists := j.entries[key]
	if exists && time.Since(entry.at) > copilotPermissionJoinTTL {
		delete(j.entries, key)
		exists = false
	}
	if exists {
		// This callback consumes one use of the prior calls of its tool
		// even if its argument shape differs. Another callback cannot
		// bind to it.
		if entry.uses > 1 {
			kept := entry
			kept.uses--
			j.entries[key] = kept
		} else {
			delete(j.entries, key)
		}
	} else {
		// A callback no preToolUse of its tool announced means the join
		// lost track of the session's calls: it consumes every prior call
		// of the scope, so none is bound to a later callback.
		for other := range j.entries {
			if strings.HasPrefix(other, scope+"\x00") {
				delete(j.entries, other)
			}
		}
	}
	j.mu.Unlock()
	if !exists || entry.ambiguous || req.toolCallShapeUnparsed ||
		!hookToolCallJSONUnambiguous(req.ConnectorName, raw) ||
		!copilotEmptyPermissionArgs(req.Payload) {
		return nil, false
	}
	var bound []copilotargs.NativeCall
	for _, call := range entry.calls {
		if copilotPermissionToolMatches(call.Name, req.ToolName) {
			bound = append(bound, copilotargs.NativeCall{Name: call.Name, Args: append(json.RawMessage(nil), call.Args...)})
		}
	}
	return bound, len(bound) > 0
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
