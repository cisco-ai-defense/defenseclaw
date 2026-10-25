// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
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
// caller/session/directory can supply that missing decision.
type copilotPermissionJoin struct {
	mu      sync.Mutex
	entries map[string]copilotPermissionEntry
}

type copilotPermissionEntry struct {
	response  agentHookResponse
	tool      string
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

func (j *copilotPermissionJoin) record(ctx context.Context, req agentHookRequest, response agentHookResponse) {
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
	if req.ToolCallUnparsed || req.ToolArgsProjectionUncertain || req.ToolName == "" || response.Action != "allow" {
		return
	}
	j.entries[key] = copilotPermissionEntry{response: response, tool: req.ToolName, at: now}
}

// match reuses the prior decision only for a callback whose raw body is one
// unambiguous JSON value: a decoder keeps the last of duplicate keys, so a
// duplicate toolInput, toolName or hookName could pair a protected call with
// an empty decoded map. Such a callback still consumes the prior decision
// and gets its own (unparsed) gate. An argumentless callback is unparsed by
// design, so the raw body is checked here and not req.ToolCallUnparsed.
func (j *copilotPermissionJoin) match(ctx context.Context, req agentHookRequest, profile connector.HookProfile, raw []byte) (agentHookResponse, bool) {
	if req.ConnectorName != "copilot" || req.HookEventName != "permissionRequest" ||
		req.HookSurface == connector.CopilotHookSurfaceVSCodeLocal {
		return agentHookResponse{}, false
	}
	key := copilotPermissionKey(ctx, req)
	if key == "" {
		return agentHookResponse{}, false
	}
	j.mu.Lock()
	entry, exists := j.entries[key]
	if exists && time.Since(entry.at) > copilotPermissionJoinTTL {
		delete(j.entries, key)
		exists = false
	}
	if exists {
		// This callback consumes the one prior decision even if its tool or
		// argument shape differs. Another callback cannot reuse that allow.
		delete(j.entries, key)
	}
	j.mu.Unlock()
	if !exists || entry.ambiguous || !hookToolCallJSONUnambiguous(req.ConnectorName, raw) ||
		!copilotEmptyPermissionArgs(req.Payload) ||
		!copilotPermissionToolMatches(entry.tool, req.ToolName) {
		return agentHookResponse{}, false
	}
	return copilotDedupedResponse(profile, req, entry.response), true
}

func copilotPermissionToolMatches(pre, permission string) bool {
	return pre == permission || pre == "apply_patch" && permission == "edit"
}

func copilotEmptyPermissionArgs(payload map[string]any) bool {
	if payload == nil || payload["hookName"] != "permissionRequest" {
		return false
	}
	for _, name := range []string{"toolCalls", "tool_name", "tool_input", "tool_args"} {
		if _, present := payload[name]; present {
			return false
		}
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
