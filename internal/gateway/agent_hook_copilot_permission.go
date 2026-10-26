// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

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
	// A parallel toolCalls envelope names several calls: a later callback
	// cannot tell which one it is for.
	if calls, _ := req.Payload["toolCalls"].([]any); len(calls) > 1 {
		allowed = false
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
	if req.ConnectorName != "copilot" || req.HookEventName != "permissionRequest" ||
		req.HookSurface == connector.CopilotHookSurfaceVSCodeLocal {
		return "", nil, false
	}
	key := copilotPermissionKey(ctx, req)
	if key == "" {
		return "", nil, false
	}
	j.mu.Lock()
	entry, exists := j.entries[key]
	if exists && time.Since(entry.at) > copilotPermissionJoinTTL {
		delete(j.entries, key)
		exists = false
	}
	if exists {
		// This callback consumes the one prior call even if its tool or
		// argument shape differs. Another callback cannot bind to it.
		delete(j.entries, key)
	}
	j.mu.Unlock()
	if !exists || entry.ambiguous || req.toolCallShapeUnparsed ||
		!hookToolCallJSONUnambiguous(req.ConnectorName, raw) ||
		!copilotEmptyPermissionArgs(req.Payload) ||
		!copilotPermissionToolMatches(entry.tool, req.ToolName) {
		return "", nil, false
	}
	return entry.tool, append(json.RawMessage(nil), entry.args...), true
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
