// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
)

// passthroughBody is what the passthrough reads of a request body to inspect
// it. Parse multiple API formats:
//   - Chat Completions: {"messages": [...]}
//   - Anthropic Messages: {"messages": [...], "system": "..."}
//   - OpenAI/Azure Responses API: {"input": [...] | "string", "instructions": "..."}
//   - Gemini generateContent: {"contents": [{"role": "user", "parts": [{"text": "..."}]}], "systemInstruction": {...}}
//   - Ollama /api/generate: {"prompt": "...", "system": "..."}
type passthroughBody struct {
	Model             string          `json:"model"`
	Messages          []ChatMessage   `json:"messages"`
	System            string          `json:"system,omitempty"`
	Instructions      string          `json:"instructions,omitempty"` // Responses API system prompt
	Input             json.RawMessage `json:"input,omitempty"`        // Responses API
	Contents          json.RawMessage `json:"contents,omitempty"`     // Gemini native
	SystemInstruction json.RawMessage `json:"systemInstruction,omitempty"`
	Prompt            string          `json:"prompt,omitempty"` // Ollama /api/generate + legacy completion APIs
	Stream            bool            `json:"stream,omitempty"`
}

// promptView is the message list the inspectors read (AI Defense, the judge)
// and the user and turn text of the body. One reader for the body as the
// client sent it and for the body the proxy forwards after a history
// redaction, so the inspectors always see what the upstream gets
// (GAP-0284): a message that also holds a refused string keeps its other
// blocks and strings in the view, as in the body.
func (b *passthroughBody) promptView() (msgs []ChatMessage, userText, turnText, ollamaSystemText string) {
	msgs = b.Messages
	userText = lastUserText(msgs)
	// turnText is the whole user turn of a message list, inspected instead of
	// userText as on the chat-completions route: OpenClaw 2026.9 appends a
	// context message after the prompt (GAP-0190, GAP-0243). userText still
	// drives the heartbeat and session-startup gates.
	turnText = promptTurnText(msgs)
	// A coexisting Ollama /api/generate `prompt` is the user generation
	// input. Do not let top-level `system` replace it (#718). Anthropic
	// and other system-only native shapes still fall through here when
	// prompt is empty.
	// System must be non-blank, not merely non-empty: a whitespace-only value
	// would otherwise become the inspected text and produce an empty-content
	// inspection instead of falling through to the other native shapes.
	if userText == "" && strings.TrimSpace(b.System) != "" && strings.TrimSpace(b.Prompt) == "" {
		userText = b.System
	}
	// Responses API: input can be a string or array of message/item objects.
	if userText == "" && len(b.Input) > 0 {
		switch b.Input[0] {
		case '"':
			// Plain string input
			_ = json.Unmarshal(b.Input, &userText)
		case '[':
			// Array of items. The Responses API wraps each turn in an outer
			// object with "type":"message"; extract the inner content directly.
			var rawItems []json.RawMessage
			if json.Unmarshal(b.Input, &rawItems) == nil {
				var inputMsgs []ChatMessage
				for _, raw := range rawItems {
					var wrapper struct {
						Type    string          `json:"type"`
						Role    string          `json:"role"`
						Content json.RawMessage `json:"content"`
					}
					if json.Unmarshal(raw, &wrapper) == nil {
						// Both bare messages and "type":"message" wrapped items.
						if wrapper.Role != "" {
							msg := ChatMessage{Role: wrapper.Role, RawContent: wrapper.Content}
							// Re-unmarshal to populate msg.Content via ChatMessage logic.
							_ = json.Unmarshal(raw, &msg)
							inputMsgs = append(inputMsgs, msg)
						}
					}
				}
				userText = lastUserText(inputMsgs)
				turnText = promptTurnText(inputMsgs)
				if len(msgs) == 0 {
					msgs = inputMsgs
				}
			}
		}
	}
	// Gemini native (generateContent / streamGenerateContent): top-level
	// `contents[]` is an array of turns, each with `parts[]` holding the
	// actual text. Prior to this, Gemini-shaped bodies reached
	// handlePassthrough with userText == "" and bypassed pre-call
	// inspection entirely — a full policy bypass on Gemini's wire format.
	// Also pull systemInstruction as a fallback so Vertex flows that
	// only set a system prompt are still inspected.
	if userText == "" && len(b.Contents) > 0 {
		if turns := extractGeminiContentsText(b.Contents); len(turns) > 0 {
			// Build synthetic ChatMessages so downstream scanners
			// (Cisco AI Defense, judge) see realistic conversation
			// shape instead of a single blob.
			geminiMsgs := make([]ChatMessage, 0, len(turns))
			for _, t := range turns {
				role := t.Role
				if role == "model" {
					role = "assistant"
				}
				if role == "" {
					role = "user"
				}
				geminiMsgs = append(geminiMsgs, ChatMessage{Role: role, Content: t.Text})
			}
			userText = lastUserText(geminiMsgs)
			turnText = promptTurnText(geminiMsgs)
			if len(msgs) == 0 {
				msgs = geminiMsgs
			}
		}
	}
	if userText == "" && len(b.SystemInstruction) > 0 {
		userText = extractGeminiSystemInstructionText(b.SystemInstruction)
	}

	// Ollama /api/generate + legacy completion endpoints: top-level
	// `prompt` is a single string. Inspect it like any user turn so
	// direct Ollama clients are not a bypass route. When system and
	// prompt coexist, keep both in Messages for message-aware inspectors
	// and join both texts for regex_judge / content scanners, which
	// inspect the string rather than Messages (#718). One Inspect keeps
	// managed AID at a single call.
	if userText == "" && strings.TrimSpace(b.Prompt) != "" {
		userText = b.Prompt
		if strings.TrimSpace(b.System) != "" {
			ollamaSystemText = b.System
		}
		if len(msgs) == 0 {
			if ollamaSystemText != "" {
				msgs = append(msgs, ChatMessage{Role: "system", Content: ollamaSystemText})
			}
			msgs = append(msgs, ChatMessage{Role: "user", Content: b.Prompt})
		}
	}

	// Responses API: fall back to instructions (system-level prompt) if no
	// user turn was found — still worth inspecting for prompt injection.
	if userText == "" && b.Instructions != "" {
		userText = b.Instructions
	}
	return msgs, userText, turnText, ollamaSystemText
}
