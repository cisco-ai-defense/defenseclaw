// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// A Codex shell call runs in the workdir the model gave it, but the Codex
// PreToolUse hook sends only {"command": ...} as tool_input and the session
// cwd as cwd (GAP-1388). The call itself, with its workdir, is in the session
// rollout (transcript_path) under the hook tool_use_id: Codex records the
// model output item before it runs the tool. A per-user gateway reads the
// rollout itself; a managed gateway cannot read the home of the user, so its
// hook client reads it as the user and sends the workdir of the
// call (CallWorkdirKey, GAP-0991).

const (
	// codexRolloutTailBytes bounds the rollout read: the call is the last
	// model output item when its PreToolUse hook runs.
	codexRolloutTailBytes = 1 << 20
	codexRolloutAttempts  = 4
)

// CodexRolloutCallWorkdir is the workdir argument of the Codex function call
// toolUseID in the session rollout transcript, "" when there is no such call
// or argument. It reads only a regular file named rollout-*.jsonl inside home.
func CodexRolloutCallWorkdir(home, transcript, toolUseID string) string {
	id := strings.TrimSpace(toolUseID)
	if id == "" || len(id) > 256 || strings.ContainsAny(id, "\"\\\x00\n") {
		return ""
	}
	if home == "" || !filepath.IsAbs(transcript) || strings.ContainsRune(transcript, 0) ||
		filepath.Clean(transcript) != transcript {
		return ""
	}
	base := filepath.Base(transcript)
	if !strings.HasPrefix(base, "rollout-") || !strings.HasSuffix(base, ".jsonl") {
		return ""
	}
	if rel, err := filepath.Rel(home, transcript); err != nil || rel == ".." ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return ""
	}
	marker := []byte(`"call_id":"` + id + `"`)
	for attempt := 0; attempt < codexRolloutAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 25 * time.Millisecond)
		}
		workdir, found, readable := codexRolloutCallWorkdirOnce(transcript, marker, id)
		if found || !readable {
			return workdir
		}
	}
	return ""
}

// codexRolloutCallWorkdirOnce scans the tail of the rollout, newest line
// first, for the function_call of id. found reports the call was there;
// readable is false when the file cannot be read as a regular file.
func codexRolloutCallWorkdirOnce(transcript string, marker []byte, id string) (workdir string, found, readable bool) {
	if linkUnanswered(transcript) {
		return "", false, false
	}
	info, err := pathidentity.LstatPinned(transcript)
	if err != nil || !info.Mode().IsRegular() {
		return "", false, false
	}
	file, err := pathOpen(transcript)
	if err != nil {
		return "", false, false
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !os.SameFile(info, opened) {
		return "", false, false
	}
	offset := info.Size() - codexRolloutTailBytes
	if offset < 0 {
		offset = 0
	}
	tail, err := io.ReadAll(io.NewSectionReader(file, offset, info.Size()-offset))
	if err != nil {
		return "", false, false
	}
	lines := bytes.Split(tail, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		if offset > 0 && i == 0 {
			break // a cut first line
		}
		line := lines[i]
		if !bytes.Contains(line, marker) {
			continue
		}
		var item struct {
			Type    string `json:"type"`
			Payload struct {
				Type      string `json:"type"`
				CallID    string `json:"call_id"`
				Arguments string `json:"arguments"`
			} `json:"payload"`
		}
		if json.Unmarshal(line, &item) != nil || item.Type != "response_item" ||
			item.Payload.CallID != id || item.Payload.Type != "function_call" {
			continue
		}
		var args map[string]json.RawMessage
		if json.Unmarshal([]byte(item.Payload.Arguments), &args) != nil {
			return "", true, true
		}
		_ = json.Unmarshal(args["workdir"], &workdir)
		if strings.ContainsRune(workdir, 0) {
			workdir = ""
		}
		return workdir, true, true
	}
	return "", false, true
}

// codexCallWorkdir is the workdir a shell call runs in when it is not the
// session cwd: the tool_input workdir of an exec_command or Codex shell call,
// else (Codex only, whose hook leaves it out) the workdir of the call in the
// session rollout. present is false when the call names none. ok is false
// for a workdir the client cannot place (a home spelling, a control byte),
// which makes the evidence incomplete.
func codexCallWorkdir(connector, tool string, toolArgs, envelope map[string]json.RawMessage, home string) (workdir string, present, ok bool) {
	codex := strings.EqualFold(strings.TrimSpace(connector), "codex")
	shellCall := codex && !isApplyPatchToolName(tool) && codexShellText(toolArgs)
	if tool != "exec_command" && !shellCall {
		return "", false, true
	}
	if raw, named := toolArgs["workdir"]; named {
		if json.Unmarshal(raw, &workdir) != nil || workdir == "" ||
			strings.HasPrefix(workdir, "~") || strings.IndexByte(workdir, 0) >= 0 {
			return "", false, false
		}
		return workdir, true, true
	}
	if !codex {
		return "", false, true
	}
	var transcript, id string
	_ = json.Unmarshal(envelope["transcript_path"], &transcript)
	_ = json.Unmarshal(envelope["tool_use_id"], &id)
	if workdir = CodexRolloutCallWorkdir(home, transcript, id); workdir == "" {
		return "", false, true
	}
	if strings.HasPrefix(workdir, "~") {
		return "", false, false
	}
	return workdir, true, true
}

// codexShellText reports whether the arguments carry the text of a shell
// command (the closed key names of the Codex shell tools).
func codexShellText(toolArgs map[string]json.RawMessage) bool {
	for _, key := range []string{"command", "cmd"} {
		var text string
		if json.Unmarshal(toolArgs[key], &text) == nil && text != "" {
			return true
		}
	}
	return false
}
