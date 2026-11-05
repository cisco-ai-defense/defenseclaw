// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// OrdinaryNoAnswerPayload is a local proof for a small per-user tool call
// whose verified gateway connection reaches the answer deadline. It does
// not turn an unknown tool or an unproved target into an allowed call.
func OrdinaryNoAnswerPayload(body []byte) bool {
	account, err := osuser.Current()
	return err == nil && ordinaryNoAnswerPayloadInHome(body, account.HomeDir)
}

func ordinaryNoAnswerPayloadInHome(body []byte, home string) bool {
	if len(body) == 0 || len(body) > 64<<10 || !filepath.IsAbs(home) || !validUniqueGatewayResponse(body) {
		return false
	}
	var call struct {
		Event string          `json:"hook_event_name"`
		Tool  string          `json:"tool_name"`
		CWD   string          `json:"cwd"`
		Input json.RawMessage `json:"tool_input"`
	}
	if json.Unmarshal(body, &call) != nil || call.Event != "PreToolUse" ||
		!filepath.IsAbs(call.CWD) || len(call.Input) == 0 {
		return false
	}
	var input map[string]json.RawMessage
	if json.Unmarshal(call.Input, &input) != nil {
		return false
	}
	switch call.Tool {
	case "Bash":
		var command string
		if json.Unmarshal(input["command"], &command) != nil || strings.TrimSpace(command) == "" {
			return false
		}
		if len(body) > 4096 {
			return hookpaths.OrdinaryLongTouchMissingLeaves(command, call.CWD, home)
		}
		return hookpaths.ActionCommandDecision(command, call.CWD, home) == "" &&
			!hookpaths.ActionStateTargetMention(command, call.CWD, home) &&
			!hookpaths.ActionPrivateKeyRead(command, call.CWD, home) &&
			hookpaths.UnprovenProtectedWrite(command, call.CWD, home) == ""
	case "Read":
		if len(body) > 4096 {
			return false
		}
		var path string
		if json.Unmarshal(input["file_path"], &path) != nil || !filepath.IsAbs(path) ||
			strings.ContainsAny(path, " \t\r\n'\"\\$`*?[];|&<>(){}") {
			return false
		}
		cwd, err := filepath.EvalSymlinks(call.CWD)
		if err != nil {
			return false
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return false
		}
		rel, err := filepath.Rel(cwd, resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return false
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
		command := "cat " + path
		return hookpaths.ActionCommandDecision(command, call.CWD, home) == "" &&
			!hookpaths.ActionStateTargetMention(command, call.CWD, home) &&
			!hookpaths.ActionPrivateKeyRead(command, call.CWD, home)
	default:
		return false
	}
}
