// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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
//
// The first turn of a new session has no assistant message yet when its Stop
// hook runs: Claude Code writes it to the transcript after the hook. That turn
// lost its chat span when the gateway restarted between SessionStart and the
// turn (GAP-2578). Claude Code records a "model" attachment with the model ID
// when the prompt is submitted, so the newest of the two is used.
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
		if !bytes.Contains(line, []byte(`"assistant"`)) && !bytes.Contains(line, []byte(`"modelId"`)) {
			continue
		}
		var entry struct {
			Type    string `json:"type"`
			Message struct {
				Role  string `json:"role"`
				Model string `json:"model"`
			} `json:"message"`
			Attachment struct {
				Type     string `json:"type"`
				Identity struct {
					ModelID string `json:"modelId"`
				} `json:"identity"`
			} `json:"attachment"`
		}
		if json.Unmarshal(line, &entry) != nil {
			continue
		}
		model := ""
		switch {
		case entry.Type == "assistant" || entry.Message.Role == "assistant":
			model = entry.Message.Model
		case entry.Type == "attachment" && entry.Attachment.Type == "model":
			model = entry.Attachment.Identity.ModelID
		}
		// Claude Code writes "<synthetic>" for messages it made itself;
		// the identifier check skips them.
		if model = strings.TrimSpace(model); hookModelV8Identifier(model) {
			return model
		}
	}
	return ""
}

// bedrockInferenceProfileModel matches a Bedrock cross-region inference
// profile ID ("us.anthropic.claude-haiku-4-5-20251001-v1:0") and captures the
// model ID it routes to ("anthropic.claude-haiku-4-5-20251001-v1:0").
var bedrockInferenceProfileModel = regexp.MustCompile(`^(?:us|us-gov|eu|apac|ca|jp|au|global)\.(anthropic\..+)$`)

// telemetryModelID gives one model one ID on every connector's telemetry. On
// Bedrock the startup SessionStart names the inference profile the user
// configured ("us.anthropic..."), while the transcript, which names the model
// after a gateway restart or on a resumed session (GAP-2511), records the
// model ID Bedrock answered with ("anthropic..."). The same session then
// showed up under two models in Galileo (GAP-2556). OpenClaw, the other hook
// connectors and the proxy report the profile too, so they kept the prefix
// while Claude Code dropped it (GAP-2584). Every connector now uses the model
// ID. The request sent to the provider is unchanged.
func telemetryModelID(model string) string {
	if match := bedrockInferenceProfileModel.FindStringSubmatch(model); match != nil {
		return match[1]
	}
	return model
}
