// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	osuser "os/user"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// OrdinaryNoAnswerPayload reports that a verified late call has no protected
// candidate in the shared path reader. Unknown input keeps the closed answer.
func OrdinaryNoAnswerPayload(body []byte) bool {
	account, err := osuser.Current()
	return err == nil && ordinaryNoAnswerPayloadInHome(body, account.HomeDir)
}

func ordinaryNoAnswerPayloadInHome(body []byte, home string) bool {
	if len(body) == 0 || len(body) > hookpaths.MaxPayloadBytes || !filepath.IsAbs(home) || !validUniqueGatewayResponse(body) {
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
		return lateCommandGrade(input["command"], call.CWD, home) == hookpaths.GradeNone
	case "exec_command":
		if len(input["command"]) != 0 {
			return false
		}
		return lateCommandGrade(input["cmd"], commandWorkdir(input, call.CWD), home) == hookpaths.GradeNone
	case "shell", "shell_command":
		return lateCommandGrade(input["command"], commandWorkdir(input, call.CWD), home) == hookpaths.GradeNone
	case "Read":
		var path string
		if json.Unmarshal(input["file_path"], &path) != nil || !filepath.IsAbs(path) {
			return false
		}
		return hookpaths.ProtectedReach(path, home, hookpaths.NewTargetMemo()) == hookpaths.GradeNone
	default:
		return false
	}
}

func commandWorkdir(input map[string]json.RawMessage, cwd string) string {
	if len(input["workdir"]) == 0 {
		return cwd
	}
	var workdir string
	if json.Unmarshal(input["workdir"], &workdir) != nil || !filepath.IsAbs(workdir) {
		return ""
	}
	return workdir
}

func lateCommandGrade(raw json.RawMessage, cwd, home string) hookpaths.Grade {
	if !filepath.IsAbs(cwd) || len(raw) == 0 {
		return hookpaths.GradePossible
	}
	var command string
	if json.Unmarshal(raw, &command) != nil {
		// A shell argv has the same meaning only for one exact command body.
		var argv []string
		if json.Unmarshal(raw, &argv) != nil || len(argv) != 3 ||
			(argv[0] != "bash" && argv[0] != "sh" && argv[0] != "zsh") ||
			(argv[1] != "-c" && argv[1] != "-lc") {
			return hookpaths.GradePossible
		}
		command = argv[2]
	}
	if strings.TrimSpace(command) == "" {
		return hookpaths.GradePossible
	}
	return hookpaths.LateCallGrade(command, cwd, home)
}
