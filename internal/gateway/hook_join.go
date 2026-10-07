// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor"
)

// recordManagedHookDecision hands a managed hook decision to the runtime
// planes' hook-join ring (Tetragon spec 9.3), so the processes of the tool
// call it covered are labelled with it: the session, the tool invocation and
// how the two were matched. A process no decision covers is labelled
// hook_seen=false.
//
// Only decisions from the managed hook socket are recorded. Their peer pid
// and uid are the kernel's (SO_PEERCRED), and on a managed host every agent
// runs those machine-policy hooks, so a tool call none covers is a fact
// rather than a missing install. The decision is recorded before the hook
// answers, so it is in the ring before the tool's process starts. The join
// only labels; nothing here can block.
func (a *APIServer) recordManagedHookDecision(ctx context.Context, connectorName string, req agentHookRequest, resp agentHookResponse) {
	if !hookDecisionJoinable(req, resp) {
		return
	}
	peer, ok := managedHookRequestPeer(ctx)
	if !ok || peer.PID <= 0 {
		return
	}
	service, release := a.leaseAIRuntime()
	defer release()
	if service == nil {
		return
	}
	service.RecordHookDecision(sensor.HookDecision{
		Connector:        connName(connectorName),
		SessionID:        req.SessionID,
		ToolInvocationID: req.ToolInvocationID,
		CommandHash:      sensor.HookCommandHash(hookShellCommand(connectorName, req)),
		PeerPID:          peer.PID,
		PeerUID:          peer.UID,
		At:               time.Now(),
	})
}

// hookDecisionJoinable reports a decision a tool's processes can follow: a
// pre-tool event that let the tool run, delivered once. A permission request
// repeats its tool call's PreToolUse decision, a block runs nothing, and an
// exact replay of a delivery is the same decision again.
func hookDecisionJoinable(req agentHookRequest, resp agentHookResponse) bool {
	if !isGenericToolInspectionEvent(req.HookEventName) || canonicalEvent(req.HookEventName) == "permissionrequest" {
		return false
	}
	if req.SuppressCorrelationEmit && !req.CorrelationUnavailable {
		return false
	}
	return resp.Action != "block"
}

// hookShellCommand is the shell command a tool call runs, or "" for a tool
// that runs none. The tool's arguments are projected onto the plain shell
// shape the trusted-action parser uses, so every connector's shell tool
// (Bash, shell, execute_bash, run_command, ...) reads the same way.
func hookShellCommand(connectorName string, req agentHookRequest) string {
	tool := agentHookTrustedActionTool(connectorName, req.ToolName, "linux")
	projected, _ := agentHookTrustedActionArgs(connectorName, tool, req.ToolArgs)
	var fields map[string]json.RawMessage
	if json.Unmarshal(projected, &fields) != nil {
		return ""
	}
	for _, key := range []string{"command", "cmd"} {
		raw, ok := fields[key]
		if !ok {
			continue
		}
		var text string
		if json.Unmarshal(raw, &text) == nil {
			return text
		}
		var argv []string
		if json.Unmarshal(raw, &argv) == nil && len(argv) > 0 {
			return sensor.HookArgvCommand(argv)
		}
	}
	return ""
}
