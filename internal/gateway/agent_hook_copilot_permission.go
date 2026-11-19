// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
	"github.com/defenseclaw/defenseclaw/internal/copilotjoin"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A native Copilot permissionRequest sometimes omits the call arguments and
// call id. Only one recent, audited, allowed preToolUse in the same verified
// caller/session/directory can name the call such a callback is for. The
// join keeps that call (tool and arguments), never its decision: the
// callback is bound to the call and decided again, now, like any call, so
// the write targets as they resolve now, the live policy and the live
// sandbox floor all apply. What the join keeps and consumes is the
// copilotjoin state: this gateway's own, or, for a verified Substrate actor,
// the leader's, since the actor's preToolUse and its callback can land on
// different gateway replicas (substrate-1 GAP-0269).
type copilotPermissionJoin struct {
	own copilotjoin.Process
}

// substrateCopilotJoin, when set (a gateway replica on Agent Substrate), is
// the join state of every verified actor's calls.
var substrateCopilotJoin atomic.Pointer[copilotjoin.Store]

// setSubstrateCopilotJoin sets (nil clears) the shared join state.
func setSubstrateCopilotJoin(store copilotjoin.Store) {
	if store == nil {
		substrateCopilotJoin.Store(nil)
		return
	}
	substrateCopilotJoin.Store(&store)
}

func (j *copilotPermissionJoin) store(ctx context.Context) copilotjoin.Store {
	if _, ok := substrateActorFrom(ctx); ok {
		if shared := substrateCopilotJoin.Load(); shared != nil {
			return *shared
		}
	}
	return &j.own
}

var copilotJoinLastWarn atomic.Int64

func copilotJoinWarn(op string, err error) {
	now := time.Now().UnixNano()
	last := copilotJoinLastWarn.Load()
	if now-last < int64(time.Minute) || !copilotJoinLastWarn.CompareAndSwap(last, now) {
		return
	}
	fmt.Fprintf(os.Stderr, "[gateway] warning: the Copilot permission join state could not be %s (%v); an argumentless permission callback keeps its own unparsed decision\n", op, err)
}

func copilotPermissionKey(ctx context.Context, req agentHookRequest) string {
	scope := copilotDedupeScope(ctx)
	if scope == "" || req.SessionID == "" || req.CWD == "" {
		return ""
	}
	return scope + "\x00" + req.SessionID + "\x00" + req.CWD
}

// record keeps the calls of an audited preToolUse when allowed is true
// (copilotjoin.Process.Record has the rules).
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
	if err := j.store(ctx).Record(ctx, scope, readable, allowed, calls); err != nil {
		copilotJoinWarn("written", err)
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
	// The callback consumes its tool's prior calls even when it is not
	// bound to them (copilotjoin.Process.Take). A state that cannot be read
	// binds nothing: the callback keeps its own unparsed decision.
	entry, exists, err := j.store(ctx).Take(ctx, scope, req.ToolName)
	if err != nil {
		copilotJoinWarn("read", err)
		return nil, false
	}
	if !exists || entry.Ambiguous || req.toolCallShapeUnparsed ||
		!hookToolCallJSONUnambiguous(req.ConnectorName, raw) ||
		!copilotEmptyPermissionArgs(req.Payload) {
		return nil, false
	}
	var bound []copilotargs.NativeCall
	for _, call := range entry.Calls {
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
