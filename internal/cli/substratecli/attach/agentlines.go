// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"encoding/json"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
)

// agentLine turns one stdout line of a headless agent into what a person
// reads. Claude Code in headless mode writes one JSON event per line
// (--output-format stream-json, kit.HeadlessArgv): its text and tool calls
// are shown, its bookkeeping (system, user, thinking, the final result that
// repeats the text) is not. Any other line is shown as it is. show is false
// for a line that has nothing for a person. The text is the agent's, so it
// goes through safetext.
func agentLine(data string) (text string, show bool) {
	t := strings.TrimSpace(data)
	if !strings.HasPrefix(t, "{") || !strings.Contains(t, `"type"`) {
		return safetext.Clean(data), true
	}
	var ev struct {
		Type    string `json:"type"`
		Subtype string `json:"subtype"`
		IsError bool   `json:"is_error"`
		Result  string `json:"result"`
		Message struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
				Name string `json:"name"`
			} `json:"content"`
		} `json:"message"`
		SessionID string `json:"session_id"`
	}
	if json.Unmarshal([]byte(t), &ev) != nil || ev.Type == "" || ev.SessionID == "" {
		return safetext.Clean(data), true
	}
	switch ev.Type {
	case "assistant":
		var parts []string
		for _, c := range ev.Message.Content {
			switch c.Type {
			case "text":
				if s := strings.TrimSpace(safetext.Clean(c.Text)); s != "" {
					parts = append(parts, s)
				}
			case "tool_use":
				parts = append(parts, "> "+safetext.Line(c.Name))
			}
		}
		if len(parts) == 0 {
			return "", false
		}
		return strings.Join(parts, "\n"), true
	case "result":
		if ev.IsError || (ev.Subtype != "" && ev.Subtype != "success") {
			return "the agent stopped: " + orText(safetext.Line(ev.Result), safetext.Line(ev.Subtype)), true
		}
	}
	return "", false
}

func orText(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
