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
		return ordinaryNoAnswerCommand(input["command"], call.CWD, home, len(body))
	case "exec_command":
		if len(input["command"]) != 0 {
			return false
		}
		return ordinaryNoAnswerCommand(input["cmd"], commandWorkdir(input, call.CWD), home, len(body))
	case "shell", "shell_command":
		return ordinaryNoAnswerCommand(input["command"], commandWorkdir(input, call.CWD), home, len(body))
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
		if hookpaths.CallMayReachProtected(path, home) ||
			pathMayNameProtectedLink(path, resolved, home, info) {
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

func ordinaryNoAnswerCommand(raw json.RawMessage, cwd, home string, bodySize int) bool {
	if !filepath.IsAbs(cwd) || len(raw) == 0 {
		return false
	}
	var command string
	if json.Unmarshal(raw, &command) != nil {
		// Codex shell also sends a shell argv. Only an exact single shell
		// command has the same meaning as the string form.
		var argv []string
		if json.Unmarshal(raw, &argv) != nil || len(argv) != 3 ||
			(argv[0] != "bash" && argv[0] != "sh" && argv[0] != "zsh") ||
			(argv[1] != "-c" && argv[1] != "-lc") {
			return false
		}
		command = argv[2]
	}
	if strings.TrimSpace(command) == "" || hookpaths.CallMayReachProtected(command, home) {
		return false
	}
	if hookpaths.OrdinaryLongTouchMissingLeaves(command, cwd, home) {
		return true
	}
	if bodySize > 4096 || commandMayNameLink(command, cwd, home) {
		return false
	}
	return hookpaths.ActionCommandDecision(command, cwd, home) == "" &&
		!hookpaths.ActionStateTargetMention(command, cwd, home) &&
		!hookpaths.ActionPrivateKeyRead(command, cwd, home) &&
		hookpaths.UnprovenProtectedWrite(command, cwd, home) == ""
}

// commandMayNameLink closes an unresolved operand at a no-answer deadline.
// The shell's words must be resolved before checking file identity; a known
// PWD or HOME value can otherwise hide a protected link behind an alias.
func commandMayNameLink(command, cwd, home string) bool {
	calls, known := hookpaths.LateKnownCalls(command, cwd, home)
	if !known {
		return true
	}
	wordCount := 0
	for _, words := range calls {
		wordCount += len(words)
		if wordCount > 128 {
			return true
		}
		if commandWordsMayNameLink(words, cwd, home) {
			return true
		}
	}
	return false
}

func commandWordsMayNameLink(words []string, cwd, home string) bool {
	display := len(words) != 0 && (words[0] == "echo" || words[0] == "printf")
	endOptions := false
	for i, word := range words {
		if i == 0 && !strings.ContainsAny(word, "/\\") {
			continue
		}
		if !endOptions && word == "--" {
			endOptions = true
			continue
		}
		if !endOptions && strings.HasPrefix(word, "-") {
			_, value, assigned := strings.Cut(word, "=")
			if !assigned {
				continue
			}
			word = value
		}
		if word == "" {
			continue
		}
		path := word
		if !filepath.IsAbs(path) {
			path = filepath.Join(cwd, path)
		}
		parent := filepath.Dir(path)
		resolvedParent, parentErr := filepath.EvalSymlinks(parent)
		if parentErr != nil && (!display || !os.IsNotExist(parentErr)) ||
			parentErr == nil && (resolvedParent != filepath.Clean(parent) ||
				hookpaths.CallMayReachProtected(resolvedParent, home)) {
			return true
		}
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return true
		}
		if err != nil && !os.IsNotExist(err) {
			return true
		}
		if err == nil {
			resolved, resolveErr := filepath.EvalSymlinks(path)
			if resolveErr != nil || pathMayNameProtectedLink(path, resolved, home, info) {
				return true
			}
		}
	}
	return false
}

func pathMayNameProtectedLink(path, resolved, home string, info os.FileInfo) bool {
	if resolved != filepath.Clean(path) || hookpaths.CallMayReachProtected(resolved, home) {
		return true
	}
	for _, protected := range hookpaths.ProtectedAuthorizedKeysPaths(home) {
		other, err := os.Stat(protected)
		if err == nil && os.SameFile(info, other) {
			return true
		}
	}
	_, protected := hookpaths.ResolveActiveStateHardlinkTarget(resolved, home)
	return protected
}
