// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"time"
)

// promptScanEchoWindow bounds how long an id-less user prompt copy waits
// for the id-bearing copy of the same prompt.
const promptScanEchoWindow = 2 * time.Minute

// promptScanEchoMaxSessions keeps the per-session memo bounded.
const promptScanEchoMaxSessions = 256

type promptScanEchoEntry struct {
	content string
	at      time.Time
}

// countPromptScanMetric reports whether this prompt scan should add to
// defenseclaw_inspect_evaluations_total and defenseclaw_alert_count_total.
//
// OpenClaw delivers one user prompt as two session.message frames: first
// without a messageId (the raw text), then with a messageId (the transcript
// copy, with OpenClaw's prefix around the same text). Both are scanned, so
// each blocked prompt counted twice (GAP-2288). The id-less copy is counted
// and remembered; the id-bearing copy that contains its text within the
// window is not counted again. The id-bearing copy still writes the alert
// row, which needs the messageId.
func (r *EventRouter) countPromptScanMetric(sessionKey, messageID, content string) bool {
	if r == nil || sessionKey == "" || content == "" {
		return true
	}
	now := time.Now()
	r.promptScanEchoMu.Lock()
	defer r.promptScanEchoMu.Unlock()
	if messageID == "" {
		if r.promptScanEcho == nil || len(r.promptScanEcho) >= promptScanEchoMaxSessions {
			r.promptScanEcho = make(map[string]promptScanEchoEntry)
		}
		r.promptScanEcho[sessionKey] = promptScanEchoEntry{content: content, at: now}
		return true
	}
	prev, ok := r.promptScanEcho[sessionKey]
	if !ok {
		return true
	}
	delete(r.promptScanEcho, sessionKey)
	if now.Sub(prev.at) > promptScanEchoWindow {
		return true
	}
	return !promptCopyContains(content, prev.content)
}

// promptCopyContains reports whether copy holds raw, either as plain text or
// JSON-escaped inside a content-block array.
func promptCopyContains(copyText, raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if strings.Contains(copyText, raw) {
		return true
	}
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(raw); err != nil {
		return false
	}
	escaped := strings.TrimSpace(b.String())
	if len(escaped) < 2 {
		return false
	}
	return strings.Contains(copyText, escaped[1:len(escaped)-1])
}
