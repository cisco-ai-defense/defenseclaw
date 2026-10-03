// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// An OpenClaw prompt is blocked by the guardrail proxy before the model
// call, while the turn's invoke_agent and chat spans come from the event
// router, which sees the block text as the assistant message. The decision
// sat only on apply_guardrail root traces, which Galileo has no shape for,
// so the blocked turn was not shown as blocked there (GAP-2231, the prompt
// side of GAP-1930). The proxy leaves each prompt block here, keyed by the
// block text it returned; the router marks the turn whose message carries
// that text as blocked and names the user, as the ACP guard does (GAP-1836).

type openClawPromptBlock struct {
	message                      string
	userID, userIDKind, userName string
	at                           time.Time
}

var openClawPromptBlocks struct {
	mu      sync.Mutex
	entries []openClawPromptBlock
}

// rememberOpenClawPromptBlock records a prompt block by the block text the
// proxy returned for it.
func rememberOpenClawPromptBlock(message string, identity AgentIdentity) {
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	entry := openClawPromptBlock{
		message: message, userID: identity.UserID, userIDKind: identity.UserIDKind, userName: identity.UserName,
	}
	if entry.userID == "" && entry.userName == "" {
		entry.userID, entry.userName = localProcessUser()
		entry.userIDKind = useridentity.KindForID(entry.userID)
	}
	openClawPromptBlocks.mu.Lock()
	defer openClawPromptBlocks.mu.Unlock()
	entry.at = openClawToolOutcomeNow()
	entries := openClawPromptBlocks.entries[:0]
	for _, e := range openClawPromptBlocks.entries {
		if entry.at.Sub(e.at) < openClawToolOutcomeTTL {
			entries = append(entries, e)
		}
	}
	entries = append(entries, entry)
	if len(entries) > openClawToolOutcomeCap {
		entries = entries[len(entries)-openClawToolOutcomeCap:]
	}
	openClawPromptBlocks.entries = entries
}

// takeOpenClawPromptBlock removes and returns the newest live block whose
// text the assistant message carries.
func takeOpenClawPromptBlock(response string) (openClawPromptBlock, bool) {
	text := openClawMessageText(response)
	if !strings.Contains(text, "[DefenseClaw]") {
		return openClawPromptBlock{}, false
	}
	openClawPromptBlocks.mu.Lock()
	defer openClawPromptBlocks.mu.Unlock()
	now := openClawToolOutcomeNow()
	for i := len(openClawPromptBlocks.entries) - 1; i >= 0; i-- {
		e := openClawPromptBlocks.entries[i]
		if now.Sub(e.at) >= openClawToolOutcomeTTL || !strings.Contains(text, e.message) {
			continue
		}
		openClawPromptBlocks.entries = append(openClawPromptBlocks.entries[:i], openClawPromptBlocks.entries[i+1:]...)
		return e, true
	}
	return openClawPromptBlock{}, false
}

// openClawMessageText is the text of an OpenClaw message body: the string
// itself, or the joined text blocks of a content array.
func openClawMessageText(content string) string {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "[{") {
		return content
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal([]byte(trimmed), &blocks) != nil {
		return content
	}
	var b strings.Builder
	for _, block := range blocks {
		if block.Type == "text" {
			b.WriteString(block.Text)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// applyOpenClawPromptBlock marks the turn of a blocked prompt: its agent and
// chat spans get a blocked outcome, and the user when the stream named none.
func applyOpenClawPromptBlock(observation *hookModelV8Observation) {
	if observation == nil || observation.outcome != "" {
		return
	}
	entry, ok := takeOpenClawPromptBlock(observation.response)
	if !ok {
		return
	}
	observation.outcome = observability.OutcomeBlocked
	if observation.meta.UserID == "" && observation.meta.UserName == "" {
		observation.meta.UserID, observation.meta.UserIDKind, observation.meta.UserName =
			entry.userID, entry.userIDKind, entry.userName
	}
}
