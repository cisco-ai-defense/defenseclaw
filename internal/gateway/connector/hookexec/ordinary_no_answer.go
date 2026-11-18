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
// hookpaths.LateOrdinaryCallAt) and the account database home. They are one
// folder for an ordinary user, and differ when the hook runs with another
// HOME; a call that names a protected file of either is not ordinary.
func OrdinaryNoAnswerPayload(body []byte) bool {
	return ordinaryNoAnswerPayloadAt("", body)
}

// ordinaryNoAnswerPayloadAt is OrdinaryNoAnswerPayload for the account whose
// home is given (the home a shell hook saved before it replaced HOME, GAP-0850)
// instead of $HOME; "" is $HOME. The account database home is read as well.
func ordinaryNoAnswerPayloadAt(home string, body []byte) bool {
	return noAnswerPayloadAt(home, body, false)
}

// lateOrdinaryNoAnswerPayloadAt is ordinaryNoAnswerPayloadAt as the
// late-ordinary rule asks it (LateOrdinaryBothScans, Linux and macOS), beside
// the link-hop scan, which reads these shapes too: it also reads a
// PermissionRequest that carries the tool and input of a PreToolUse, a shell
// call with a cd at any step (hookpaths.LateChainCallGrade, GAP-1303) and a Codex
// workdir relative to the call folder (hookpaths.LateEnteredDirectory), so an
// ordinary call of those shapes is not closed only because this reader did
// not model it (rel-1-0-10 GAP-1188). A protected reach in any of them stays
// closed. The managed and Secure Client callers keep OrdinaryNoAnswerPayload.
func lateOrdinaryNoAnswerPayloadAt(home string, body []byte) bool {
	return noAnswerPayloadAt(home, body, true)
}

// noAnswerPayloadAt is the shared reader for home and the account database
// home; late is the reading of lateOrdinaryNoAnswerPayloadAt.
func noAnswerPayloadAt(home string, body []byte, late bool) bool {
	var homes []string
	if home != "" {
		homes = append(homes, home)
	} else if processHome, err := os.UserHomeDir(); err == nil {
		homes = append(homes, processHome)
	}
	if account, err := osuser.Current(); err == nil {
		homes = append(homes, account.HomeDir)
	}
	return noAnswerPayloadInHomes(body, homes, late)
}

func noAnswerPayloadInHomes(body []byte, homes []string, late bool) bool {
	var seen []string
	for _, home := range homes {
		if !filepath.IsAbs(home) || slices.Contains(seen, home) {
			continue
		}
		seen = append(seen, home)
		if !noAnswerPayloadInHome(body, home, late) {
			return false
		}
	}
	return len(seen) != 0
}

func noAnswerPayloadInHome(body []byte, home string, late bool) bool {
	if len(body) == 0 || len(body) > hookpaths.MaxPayloadBytes || !filepath.IsAbs(home) || !validUniqueGatewayResponse(body) {
		return false
	}
	var call struct {
		Event string          `json:"hook_event_name"`
		Tool  string          `json:"tool_name"`
		CWD   string          `json:"cwd"`
		Input json.RawMessage `json:"tool_input"`
	}
	if json.Unmarshal(body, &call) != nil || !noAnswerEvent(call.Event, late) ||
		!filepath.IsAbs(call.CWD) || len(call.Input) == 0 {
		return false
	}
	var input map[string]json.RawMessage
	if json.Unmarshal(call.Input, &input) != nil {
		return false
	}
	grade := hookpaths.LateCallGrade
	if late {
		grade = hookpaths.LateChainCallGrade
	}
	switch call.Tool {
	case "Bash":
		return lateCommandGrade(input["command"], call.CWD, home, grade) == hookpaths.GradeNone
	case "exec_command":
		if len(input["command"]) != 0 {
			return false
		}
		return lateCommandGrade(input["cmd"], commandWorkdir(input, call.CWD, home, late), home, grade) == hookpaths.GradeNone
	case "shell", "shell_command":
		return lateCommandGrade(input["command"], commandWorkdir(input, call.CWD, home, late), home, grade) == hookpaths.GradeNone
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

// noAnswerEvent is a hook event whose call the shared reader reads: a
// PreToolUse, and for the late-ordinary rule (late) a PermissionRequest,
// which Claude Code and Codex send with the same tool and input.
func noAnswerEvent(event string, late bool) bool {
	return event == "PreToolUse" || late && event == "PermissionRequest"
}

// commandWorkdir is the folder a Codex call runs in: cwd, or its absolute
// workdir. A relative workdir is "" (not read), except for the late-ordinary
// rule (late), which places it as a cd from cwd (hookpaths.LateEnteredDirectory).
func commandWorkdir(input map[string]json.RawMessage, cwd, home string, late bool) string {
	if len(input["workdir"]) == 0 {
		return cwd
	}
	var workdir string
	if json.Unmarshal(input["workdir"], &workdir) != nil {
		return ""
	}
	if filepath.IsAbs(workdir) {
		return workdir
	}
	if late {
		if entered, ok := hookpaths.LateEnteredDirectory(cwd, workdir, home); ok {
			return entered
		}
	}
	return ""
}

func lateCommandGrade(raw json.RawMessage, cwd, home string, grade func(command, cwd, home string) hookpaths.Grade) hookpaths.Grade {
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
	return grade(command, cwd, home)
}
