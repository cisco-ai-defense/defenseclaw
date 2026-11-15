// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
)

// outageGuardCall is the guarded call a connector's managed hook makes: the
// tool event, the payload's session key, and whether the event is bound on
// the command line (Codex, Copilot). The plugins and the standalone Hermes
// hook ask `hook --foreign-hook-check` (check); the managed hooks run the
// hook-time guard and then hookexec (hookTime). The machine-policy OpenCode
// plugin does both.
type outageGuardCall struct {
	Event, key       string
	bound            bool
	check, hookTime  bool
	contractID       string
	hookOutputBlocks func(code int, stdout string) bool
}

func outageGuardCallFor(id string) outageGuardCall {
	blocked := func(code int, stdout string) bool {
		return code != 0 || strings.Contains(stdout, "deny") || strings.Contains(stdout, `"block"`)
	}
	call := outageGuardCall{Event: "PreToolUse", key: "session_id", hookTime: true, hookOutputBlocks: blocked}
	switch id {
	case "codex":
		call.bound, call.contractID = true, "codex-hooks-v4"
	case "cursor":
		call.Event, call.key = "preToolUse", "conversation_id"
	case "copilot":
		call.Event, call.key, call.bound = "preToolUse", "sessionId", true
	case "opencode":
		// The machine-policy plugin passes the event on the command line.
		call.Event, call.check, call.bound = "tool.execute.before", true, true
	case "amp":
		call.Event, call.check, call.hookTime = "tool.call", true, false
	case "hermes":
		call.Event, call.check, call.hookTime = "pre_tool_call", true, false
	}
	return call
}
