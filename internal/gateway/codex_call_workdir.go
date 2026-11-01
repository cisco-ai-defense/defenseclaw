// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A Codex shell call runs in the workdir the model gave it, but the Codex
// PreToolUse hook sends only {"command": ...} as tool_input and the session
// cwd as cwd (GAP-1388): a relative `echo x >> AGENTS.md` with workdir set to
// another folder was judged, and its folder snapshotted, as if it ran in the
// session folder, so a pre-existing AGENTS.md there was writable in action
// mode. The call itself, with its workdir, is in the session rollout
// (transcript_path) under the hook tool_use_id: Codex records the model
// output item before it runs the tool.

const (
	// codexTranscriptTailBytes bounds the rollout read: the call is the last
	// model output item when its PreToolUse hook runs.
	codexTranscriptTailBytes = 1 << 20
	codexTranscriptAttempts  = 4
)

// codexTranscriptCallWorkdir is the workdir argument of the Codex function
// call req.ToolUseID in the session rollout req.TranscriptPath, when the
// hook tool_input has none. It reads only a regular file named rollout-*.jsonl
// inside the caller home, only on a gateway that reads the caller files, and
// never for a sandbox request. "" when there is no such call or argument.
func codexTranscriptCallWorkdir(ctx context.Context, req codexHookRequest) string {
	if isSandboxHookRequest(ctx) || !instructionGatewayReadsFiles(ctx) {
		return ""
	}
	if _, present := req.ToolInput["workdir"]; present {
		return ""
	}
	id := strings.TrimSpace(req.ToolUseID)
	if id == "" || len(id) > 256 || strings.ContainsAny(id, "\"\\\x00\n") {
		return ""
	}
	transcript := req.TranscriptPath
	home := instructionHome(ctx)
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
	for attempt := 0; attempt < codexTranscriptAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 25 * time.Millisecond)
		}
		workdir, found, readable := codexTranscriptCallWorkdirOnce(transcript, marker, id)
		if found || !readable {
			return workdir
		}
	}
	return ""
}

// codexTranscriptCallWorkdirOnce scans the tail of the rollout, newest line
// first, for the function_call of id. found reports the call was there;
// readable is false when the file cannot be read as a regular file.
func codexTranscriptCallWorkdirOnce(transcript string, marker []byte, id string) (workdir string, found, readable bool) {
	info, err := os.Lstat(transcript)
	if err != nil || !info.Mode().IsRegular() {
		return "", false, false
	}
	file, err := os.Open(transcript)
	if err != nil {
		return "", false, false
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !os.SameFile(info, opened) {
		return "", false, false
	}
	offset := info.Size() - codexTranscriptTailBytes
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
