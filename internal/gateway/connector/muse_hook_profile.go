// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package connector

import "encoding/json"

// museProfileDecode maps Muse Gadget SDK hook payloads into the shared
// HookProfileRequest. Muse's Executor dispatches link.invoke messages
// containing a command name (system.run, file.read, file.write,
// device.health) and a params dict. The hook bridge on the gadget
// translates these into the DefenseClaw hook vocabulary before posting.
func museProfileDecode(payload map[string]interface{}) HookProfileRequest {
	req := HookProfileRequest{
		ConnectorName: "muse",
		Payload:       payload,
	}

	if event, ok := payload["event"].(string); ok {
		req.HookEventName = event
	}
	if tool, ok := payload["tool_name"].(string); ok {
		req.ToolName = tool
	}
	if args, ok := payload["tool_args"]; ok {
		if raw, err := json.Marshal(args); err == nil {
			req.ToolArgs = raw
			req.ToolArgsAuthoritative = true
		}
	}
	if content, ok := payload["content"].(string); ok {
		req.Content = content
	}
	if sessionID, ok := payload["session_id"].(string); ok {
		req.SessionID = sessionID
	}
	if deviceID, ok := payload["device_id"].(string); ok {
		req.AgentID = deviceID
	}
	if direction, ok := payload["direction"].(string); ok {
		req.Direction = direction
	}
	if cwd, ok := payload["cwd"].(string); ok {
		req.CWD = cwd
	}

	return req
}

// museProfileRespond builds the Muse-specific response envelope. The
// gadget-side hook bridge reads the decision field to decide whether to
// proceed with command execution or abort with an error.
func museProfileRespond(in HookRespondInput) HookRespondOutput {
	out := map[string]interface{}{
		"decision": in.Action,
	}
	if in.Reason != "" {
		out["reason"] = in.Reason
	}
	if in.AdditionalContext != "" {
		out["context"] = in.AdditionalContext
	}
	return HookRespondOutput{
		FieldName: "hook_output",
		Output:    out,
	}
}
