// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// claudeCodeTranscriptTailBytes bounds how much of a session transcript is
// read to find the model. The newest assistant message is near the end.
const claudeCodeTranscriptTailBytes = 256 << 10

// claudeCodeTranscriptModel returns the model of the newest assistant message
// in a Claude Code session transcript (the transcript_path of every hook).
//
// Claude Code names the model only on a startup SessionStart. The gateway
// keeps it in memory for the session, so after a gateway restart (upgrade,
// setup ... --restart, watchdog) an open session, and a session resumed with
// --continue or --resume, had no model and every later turn reached Galileo
// and OTLP without its chat span (GAP-2511). The transcript records the model
// on each assistant message, so it fills the gap. Only a bounded tail of a
// regular .jsonl file is read, and only a value that is a valid model
// identifier is returned. A managed (Secure Client) deployment reads nothing.
func claudeCodeTranscriptModel(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || managedEnterpriseActive.Load() || !filepath.IsAbs(path) ||
		!strings.EqualFold(filepath.Ext(path), ".jsonl") {
		return ""
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	offset := max(info.Size()-claudeCodeTranscriptTailBytes, 0)
	tail := make([]byte, info.Size()-offset)
	read, _ := file.ReadAt(tail, offset)
	lines := bytes.Split(tail[:read], []byte{'\n'})
	for index := len(lines) - 1; index >= 0; index-- {
		line := lines[index]
		if !bytes.Contains(line, []byte(`"assistant"`)) {
			continue
		}
		var entry struct {
			Type    string `json:"type"`
			Message struct {
				Role  string `json:"role"`
				Model string `json:"model"`
			} `json:"message"`
		}
		if json.Unmarshal(line, &entry) != nil ||
			(entry.Type != "assistant" && entry.Message.Role != "assistant") {
			continue
		}
		// Claude Code writes "<synthetic>" for messages it made itself;
		// the identifier check skips them.
		if model := strings.TrimSpace(entry.Message.Model); hookModelV8Identifier(model) {
			return model
		}
	}
	return ""
}
