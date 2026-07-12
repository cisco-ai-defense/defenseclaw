// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

const rawTelemetryDedupeTTL = 2 * time.Minute

type rawTelemetryFingerprint struct {
	connector string
	kind      string
	sessionID string
	turnID    string
	toolID    string
	hash      string
}

type rawTelemetryDedupeEntry struct {
	eventID   string
	expiresAt time.Time
}

type rawTelemetryDeduper struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]rawTelemetryDedupeEntry
}

func newRawTelemetryDeduper() *rawTelemetryDeduper {
	return &rawTelemetryDeduper{
		ttl:     rawTelemetryDedupeTTL,
		entries: map[string]rawTelemetryDedupeEntry{},
	}
}

func (a *APIServer) rawDeduper() *rawTelemetryDeduper {
	a.rawTelemetryMu.RLock()
	d := a.rawTelemetryDedupe
	a.rawTelemetryMu.RUnlock()
	if d != nil {
		return d
	}
	a.rawTelemetryMu.Lock()
	defer a.rawTelemetryMu.Unlock()
	if a.rawTelemetryDedupe == nil {
		a.rawTelemetryDedupe = newRawTelemetryDeduper()
	}
	return a.rawTelemetryDedupe
}

func (d *rawTelemetryDeduper) remember(fp rawTelemetryFingerprint) string {
	if !fp.valid() {
		return ""
	}
	now := time.Now()
	key := fp.key()
	eventID := rawTelemetryEventID(key)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked(now)
	if existing, ok := d.entries[key]; ok && existing.expiresAt.After(now) {
		return existing.eventID
	}
	d.entries[key] = rawTelemetryDedupeEntry{eventID: eventID, expiresAt: now.Add(d.ttl)}
	return eventID
}

func (d *rawTelemetryDeduper) duplicateOf(fp rawTelemetryFingerprint) (string, bool) {
	if !fp.valid() {
		return "", false
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked(now)
	entry, ok := d.entries[fp.key()]
	if !ok || !entry.expiresAt.After(now) {
		return "", false
	}
	return entry.eventID, true
}

func (d *rawTelemetryDeduper) pruneLocked(now time.Time) {
	for key, entry := range d.entries {
		if !entry.expiresAt.After(now) {
			delete(d.entries, key)
		}
	}
}

func (fp rawTelemetryFingerprint) valid() bool {
	return fp.connector != "" &&
		fp.kind != "" &&
		fp.hash != "" &&
		(fp.sessionID != "" || fp.turnID != "" || fp.toolID != "")
}

func (fp rawTelemetryFingerprint) key() string {
	return strings.Join([]string{
		normalizeRawTelemetryToken(fp.connector),
		normalizeRawTelemetryToken(fp.kind),
		normalizeRawTelemetryToken(fp.sessionID),
		normalizeRawTelemetryToken(fp.turnID),
		normalizeRawTelemetryToken(fp.toolID),
		fp.hash,
	}, "|")
}

func normalizeRawTelemetryToken(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func rawTelemetryHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func rawTelemetryEventID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "raw-" + hex.EncodeToString(sum[:8])
}

func newRawTelemetryFingerprint(connector, kind, sessionID, turnID, toolID string, raw []byte) rawTelemetryFingerprint {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return rawTelemetryFingerprint{}
	}
	return rawTelemetryFingerprint{
		connector: connector,
		kind:      kind,
		sessionID: sessionID,
		turnID:    turnID,
		toolID:    toolID,
		hash:      rawTelemetryHash(raw),
	}
}

func (a *APIServer) rememberRawHookEvent(connector, kind, sessionID, turnID, toolID string, raw []byte) string {
	return a.rawDeduper().remember(newRawTelemetryFingerprint(connector, kind, sessionID, turnID, toolID, raw))
}

func (a *APIServer) rememberCodexRawHookEvents(req codexHookRequest) []string {
	var ids []string
	switch req.HookEventName {
	case "UserPromptSubmit":
		ids = append(ids, a.rememberRawHookEvent("codex", "prompt", req.SessionID, req.TurnID, "", []byte(req.Prompt)))
	case "PreToolUse", "PermissionRequest":
		ids = append(ids, a.rememberRawHookEvent("codex", "tool_call", req.SessionID, req.TurnID, req.ToolUseID, codexToolArgs(req)))
	case "PostToolUse":
		ids = append(ids, a.rememberRawHookEvent("codex", "tool_result", req.SessionID, req.TurnID, req.ToolUseID, []byte(codexToolResponseString(req.ToolResponse))))
	}
	return uniqueNonEmpty(ids)
}

func (a *APIServer) rememberClaudeCodeRawHookEvents(req claudeCodeHookRequest) []string {
	var ids []string
	switch req.HookEventName {
	case "UserPromptSubmit", "UserPromptExpansion":
		ids = append(ids, a.rememberRawHookEvent("claudecode", "prompt", req.SessionID, "", "", []byte(claudeCodePromptContent(req))))
	case "PreToolUse", "PermissionRequest", "PermissionDenied":
		ids = append(ids, a.rememberRawHookEvent("claudecode", "tool_call", req.SessionID, "", req.ToolUseID, claudeCodeToolArgs(req)))
	case "PostToolUse", "PostToolUseFailure", "PostToolBatch":
		ids = append(ids, a.rememberRawHookEvent("claudecode", "tool_result", req.SessionID, "", req.ToolUseID, []byte(claudeCodeToolOutput(req))))
	}
	return uniqueNonEmpty(ids)
}

// rememberHookRawEvents is the profile-driven raw event deduper.
// It folds rememberCodexRawHookEvents and
// rememberClaudeCodeRawHookEvents into a single helper keyed on the
// generic agentHookRequest, so any connector — codex, claudecode, and
// every future generic connector with a non-nil NativeOTLPSpec — gets
// automatic dedup coverage without bespoke code paths.
//
// The kind classification (prompt / tool_call / tool_result) matches
// the bespoke helpers byte-for-byte by canonicalizing the event name
// through canonicalEvent(). The content for hashing is derived from
// the canonical fields of agentHookRequest:
//
//   - prompt   → req.Content (UserPromptSubmit, UserPromptExpansion)
//   - tool_call → req.ToolArgs (PreToolUse, PermissionRequest,
//     PermissionDenied)
//   - tool_result → req.Content (PostToolUse, PostToolBatch, etc.)
//
// The toolID field is recovered from req.Payload["tool_use_id"]
// because the unified normalizer (normalizeAgentHookRequest) does not
// strip it to a typed slot — keeping the bespoke handlers' behaviour
// without forcing the unified handler to know about every vendor
// schema.
//
// Post PR #284 this helper handles the 5 hookOnly connectors
// (hermes/cursor/windsurf/geminicli/copilot); codex and claudecode
// have their own dedupers (rememberCodexRawHookEvents /
// rememberClaudeCodeRawHookEvents) that probe connector-specific
// fields like ToolUseID / PermissionRequestID. The unified
// handleAgentHook routes to either via
// hook_profile_runtime.go's profile-runtime registry.
func (a *APIServer) rememberHookRawEvents(req agentHookRequest) []string {
	canon := canonicalEvent(req.HookEventName)
	toolID := firstString(req.Payload, "tool_use_id", "toolUseId", "tool_call_id", "toolCallId")
	var ids []string
	switch {
	case isPromptLikeEvent(canon) || canon == "userpromptexpansion":
		ids = append(ids, a.rememberRawHookEvent(req.ConnectorName, "prompt", req.SessionID, req.TurnID, toolID, []byte(req.Content)))
	case isGenericToolInspectionEvent(canon) || canon == "permissiondenied":
		args := []byte(req.ToolArgs)
		if len(args) == 0 {
			args = []byte("{}")
		}
		ids = append(ids, a.rememberRawHookEvent(req.ConnectorName, "tool_call", req.SessionID, req.TurnID, toolID, args))
	case isResultLikeEvent(canon) || canon == "posttoolbatch":
		ids = append(ids, a.rememberRawHookEvent(req.ConnectorName, "tool_result", req.SessionID, req.TurnID, toolID, []byte(req.Content)))
	}
	return uniqueNonEmpty(ids)
}

// rawOriginIfHook returns "hook" when the supplied raw event ID
// slice is non-empty, "" otherwise. The HookAuditEnvelope schema
// requires RawOrigin to be set whenever RawEventIDs is present so a
// downstream SIEM query has the join key. Returning "" lets the
// JSON omitempty rule drop the field entirely for events with no
// dedup signature (e.g. SessionStart, ConfigChange).
func rawOriginIfHook(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return "hook"
}

func uniqueNonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
