// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"strings"
)

// oversizedReviewPayload keeps complete identity and target fields from the
// bounded prefix. A content string cut by the cap contributes at most 8 KiB
// of its head. The gateway receives an ordinary, valid hook request and
// applies its usual target policy before the hook can allow the call.
func oversizedReviewPayload(prefix []byte, boundEvent string) []byte {
	review := map[string]any{
		"content_truncated":     true,
		"bounded_prefix_review": true,
		"original_body_bytes":   len(prefix), // lower bound: the reader stopped at cap+1
	}
	for key, value := range payloadPrefixFields(prefix) {
		review[key] = value
	}
	decoder := json.NewDecoder(bytes.NewReader(prefix))
	if token, err := decoder.Token(); err == nil && token == json.Delim('{') {
		readOversizedObjectPrefix(decoder, prefix, review, false, 0)
	}
	if boundEvent != "" {
		review["hook_event_name"] = boundEvent
	}
	if _, ok := review["tool_input"]; !ok {
		if path, ok := review["file_path"].(string); ok {
			review["tool_input"] = map[string]any{"file_path": path}
		}
	}
	body, _ := json.Marshal(review)
	return body
}

// OversizedReviewPayload is the shell transport's bounded review encoder.
// The native hook uses the same encoder directly before its gateway call.
func OversizedReviewPayload(prefix []byte, boundEvent string) []byte {
	return oversizedReviewPayload(prefix, boundEvent)
}

func readOversizedObjectPrefix(decoder *json.Decoder, prefix []byte, out map[string]any, nested bool, depth int) {
	if depth > 16 {
		return
	}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return
		}
		key, ok := keyToken.(string)
		if !ok {
			return
		}
		start := decoder.InputOffset()
		value, err := decoder.Token()
		if err != nil {
			if oversizedReviewField(key, nested) {
				if head := oversizedStringHead(prefix[start:]); head != "" {
					out[key] = head
				}
			}
			return
		}
		if value == json.Delim('{') {
			child := map[string]any{}
			readOversizedObjectPrefix(decoder, prefix, child, true, depth+1)
			if !nested && (key == "tool_input" || key == "toolInput" || key == "toolArgs" || key == "args") {
				out[key] = child
			}
			continue
		}
		if value == json.Delim('[') {
			return
		}
		if str, ok := value.(string); ok && oversizedReviewField(key, nested) {
			if len(str) > 8192 {
				str = str[:8192]
			}
			out[key] = str
		}
	}
	_, _ = decoder.Token() // closing object delimiter, if present
}

func oversizedReviewField(key string, nested bool) bool {
	if nested {
		switch key {
		case "file_path", "filePath", "path", "command", "CommandLine", "content", "diff":
			return true
		}
		return false
	}
	if oversizedRefusalFields[key] {
		return true
	}
	switch key {
	case "file_path", "filePath", "path", "command", "content", "tool_response", "tool_result", "prompt", "response":
		return true
	}
	return false
}

func oversizedStringHead(raw []byte) string {
	raw = bytes.TrimLeft(raw, " \t\r\n")
	if len(raw) == 0 || raw[0] != '"' {
		return ""
	}
	if len(raw) > 8193 {
		raw = raw[:8193]
	}
	// A cap may split a UTF-8 rune or escape. Drop only its incomplete tail.
	for trim := 0; trim < 8 && len(raw) > 1; trim++ {
		var text string
		if json.Unmarshal(append(append([]byte(nil), raw...), '"'), &text) == nil {
			return strings.ToValidUTF8(text, "")
		}
		raw = raw[:len(raw)-1]
	}
	return ""
}
