// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"os"
	osuser "os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// OrdinaryNoAnswerPayload reports that a verified late call has no protected
// candidate in the shared path reader. Unknown input keeps the closed answer.
//
// The protected files of every home the call can mean are read: the home the
// agent runs with ($HOME, as the other late-call scan reads it,
// hookpaths.LateOrdinaryCall) and the account database home. They are one
// folder for an ordinary user, and differ when the hook runs with another
// HOME; a call that names a protected file of either is not ordinary.
func OrdinaryNoAnswerPayload(body []byte) bool {
	var homes []string
	if home, err := os.UserHomeDir(); err == nil {
		homes = append(homes, home)
	}
	if account, err := osuser.Current(); err == nil {
		homes = append(homes, account.HomeDir)
	}
	return ordinaryNoAnswerPayloadInHomes(body, homes)
}

// ordinaryNoAnswerPayloadInHomes is ordinary only when the call names no
// protected file of any of the absolute homes; a list with none is not.
func ordinaryNoAnswerPayloadInHomes(body []byte, homes []string) bool {
	var seen []string
	for _, home := range homes {
		if !filepath.IsAbs(home) || slices.Contains(seen, home) {
			continue
		}
		seen = append(seen, home)
		if !ordinaryNoAnswerPayloadInHome(body, home) {
			return false
		}
	}
	return len(seen) != 0
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
