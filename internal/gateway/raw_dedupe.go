// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
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

type rawTelemetryDedupeDecision struct {
	duplicateIDs []string
	duplicateOf  map[string]string
	candidates   int
}

func newRawTelemetryDeduper() *rawTelemetryDeduper {
	return &rawTelemetryDeduper{
		ttl:     rawTelemetryDedupeTTL,
		entries: map[string]rawTelemetryDedupeEntry{},
	}
}

func (a *APIServer) rawDeduper() *rawTelemetryDeduper {
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

func appendRawTelemetryCanonicalDetails(details, origin string, canonical bool, eventIDs []string) string {
	if !redaction.DisableAll() || origin == "" || len(eventIDs) == 0 {
		return details
	}
	return fmt.Sprintf("%s raw_origin=%s raw_canonical=%t raw_event_ids=%s",
		details, origin, canonical, strings.Join(uniqueNonEmpty(eventIDs), ","))
}

func appendRawTelemetryDedupeDetails(details string, decision rawTelemetryDedupeDecision) string {
	if !redaction.DisableAll() || len(decision.duplicateIDs) == 0 {
		return details
	}
	return fmt.Sprintf("%s raw_origin=native_otlp raw_canonical=false raw_duplicate_of=%s raw_duplicate_count=%d",
		details, strings.Join(uniqueNonEmpty(decision.duplicateIDs), ","), len(decision.duplicateIDs))
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

func (a *APIServer) appendRawOTLPDetails(details, source string, signal otelIngestSignal, body []byte) string {
	if !redaction.DisableAll() {
		return details
	}
	decision := a.rawOTLPDedupeDecision(source, signal, body)
	details = appendRawTelemetryDedupeDetails(details, decision)
	if len(decision.duplicateOf) == 0 {
		return appendRawTelemetryDetails(details, "raw_body", body)
	}
	if decision.candidates > 0 && len(decision.duplicateOf) == decision.candidates {
		return details + " raw_body_omitted=duplicate"
	}
	if deduped, ok := redactDuplicateOTLPValues(body, decision.duplicateOf); ok {
		return appendRawTelemetryDetails(details, "raw_body_deduped", deduped)
	}
	return details + " raw_body_omitted=duplicate"
}

func (a *APIServer) rawOTLPDedupeDecision(source string, signal otelIngestSignal, body []byte) rawTelemetryDedupeDecision {
	decision := rawTelemetryDedupeDecision{duplicateOf: map[string]string{}}
	if signal != otelSignalLogs || len(body) == 0 {
		return decision
	}
	for _, candidate := range extractRawOTLPCandidates(source, body) {
		fp := newRawTelemetryFingerprint(source, candidate.kind, candidate.sessionID, candidate.turnID, candidate.toolID, []byte(candidate.content))
		if !fp.valid() {
			continue
		}
		decision.candidates++
		if eventID, ok := a.rawDeduper().duplicateOf(fp); ok {
			decision.duplicateIDs = append(decision.duplicateIDs, eventID)
			decision.duplicateOf[fp.hash] = eventID
		}
	}
	return decision
}

type rawOTLPCandidate struct {
	kind      string
	sessionID string
	turnID    string
	toolID    string
	content   string
}

func extractRawOTLPCandidates(source string, body []byte) []rawOTLPCandidate {
	var envelope struct {
		ResourceLogs []struct {
			Resource struct {
				Attributes []otlpAttribute `json:"attributes"`
			} `json:"resource"`
			ScopeLogs []struct {
				LogRecords []struct {
					Body       json.RawMessage `json:"body"`
					Attributes []otlpAttribute `json:"attributes"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil
	}

	var out []rawOTLPCandidate
	for _, resource := range envelope.ResourceLogs {
		resourceAttrs := otlpAttributesToMap(resource.Resource.Attributes)
		for _, scope := range resource.ScopeLogs {
			for _, rec := range scope.LogRecords {
				attrs := otlpAttributesToMap(rec.Attributes)
				for k, v := range resourceAttrs {
					if _, exists := attrs[k]; !exists {
						attrs[k] = v
					}
				}
				eventName := strings.ToLower(firstNonEmpty(otlpString(attrs, "event.name"), otlpString(attrs, "name")))
				sessionID := firstNonEmpty(
					otlpString(attrs, "session.id"),
					otlpString(attrs, "session_id"),
					otlpString(attrs, "gen_ai.conversation.id"),
					otlpString(attrs, "conversation.id"),
				)
				turnID := firstNonEmpty(
					otlpString(attrs, "turn.id"),
					otlpString(attrs, "turn_id"),
					otlpString(attrs, "codex.turn.id"),
					otlpString(attrs, "request.id"),
					otlpString(attrs, "gen_ai.request.id"),
				)
				toolID := firstNonEmpty(
					otlpString(attrs, "tool_use_id"),
					otlpString(attrs, "tool_call_id"),
					otlpString(attrs, "gen_ai.tool.call.id"),
				)

				if strings.Contains(eventName, "prompt") {
					for _, raw := range rawStringsForOTLPKeys(attrs, []string{
						"prompt", "user_prompt", "gen_ai.prompt", "llm.prompt", "codex.prompt",
						"message", "content",
					}) {
						out = append(out, rawOTLPCandidate{kind: "prompt", sessionID: sessionID, turnID: turnID, toolID: toolID, content: raw})
					}
					if raw := otlpAnyValueString(rec.Body); raw != "" {
						out = append(out, rawOTLPCandidate{kind: "prompt", sessionID: sessionID, turnID: turnID, toolID: toolID, content: raw})
					}
				}

				if strings.Contains(eventName, "tool") {
					for _, raw := range rawStringsForOTLPKeys(attrs, []string{
						"tool_parameters", "tool_input", "tool.input", "tool.args",
						"gen_ai.tool.args", "arguments", "args",
					}) {
						out = append(out, rawOTLPCandidate{kind: "tool_call", sessionID: sessionID, turnID: turnID, toolID: toolID, content: raw})
					}
				}
				if strings.Contains(eventName, "tool") && (strings.Contains(eventName, "result") || strings.Contains(eventName, "response") || strings.Contains(eventName, "output")) {
					for _, raw := range rawStringsForOTLPKeys(attrs, []string{
						"tool_response", "tool.response", "tool_result", "tool.output", "output", "response",
					}) {
						out = append(out, rawOTLPCandidate{kind: "tool_result", sessionID: sessionID, turnID: turnID, toolID: toolID, content: raw})
					}
				}
			}
		}
	}
	return out
}

func rawStringsForOTLPKeys(attrs map[string]interface{}, keys []string) []string {
	var out []string
	for _, key := range keys {
		v, ok := otlpLookup(attrs, key)
		if !ok || v == nil {
			continue
		}
		raw := rawTelemetryValueString(v)
		if raw != "" {
			out = append(out, raw)
		}
	}
	return out
}

func rawTelemetryValueString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case nil:
		return ""
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
}

func otlpAnyValueString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	return rawTelemetryValueString(decodeOTLPAnyValue(raw))
}

func redactDuplicateOTLPValues(body []byte, duplicateOf map[string]string) ([]byte, bool) {
	var doc interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	changed := redactDuplicateOTLPValueInPlace(doc, duplicateOf)
	if !changed {
		return nil, false
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return out, true
}

func redactDuplicateOTLPValueInPlace(v interface{}, duplicateOf map[string]string) bool {
	switch x := v.(type) {
	case map[string]interface{}:
		changed := false
		if attrs, ok := x["attributes"].([]interface{}); ok {
			for _, item := range attrs {
				attr, ok := item.(map[string]interface{})
				if !ok || !rawOTLPAttributeKeyMayCarryContent(fmt.Sprint(attr["key"])) {
					continue
				}
				value, ok := attr["value"].(map[string]interface{})
				if !ok {
					continue
				}
				if eventID, ok := duplicateOf[rawTelemetryHash([]byte(rawTelemetryValueString(decodeGenericOTLPAnyValue(value))))]; ok {
					attr["value"] = map[string]interface{}{
						"stringValue": "<duplicate raw content omitted; duplicate_of=" + eventID + ">",
					}
					changed = true
				}
			}
		}
		if bodyValue, ok := x["body"].(map[string]interface{}); ok {
			if eventID, ok := duplicateOf[rawTelemetryHash([]byte(rawTelemetryValueString(decodeGenericOTLPAnyValue(bodyValue))))]; ok {
				x["body"] = map[string]interface{}{
					"stringValue": "<duplicate raw content omitted; duplicate_of=" + eventID + ">",
				}
				changed = true
			}
		}
		for _, child := range x {
			if redactDuplicateOTLPValueInPlace(child, duplicateOf) {
				changed = true
			}
		}
		return changed
	case []interface{}:
		changed := false
		for _, child := range x {
			if redactDuplicateOTLPValueInPlace(child, duplicateOf) {
				changed = true
			}
		}
		return changed
	default:
		return false
	}
}

func rawOTLPAttributeKeyMayCarryContent(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if strings.Contains(key, "prompt") ||
		strings.Contains(key, "tool") ||
		key == "message" ||
		key == "content" ||
		key == "arguments" ||
		key == "args" ||
		key == "output" ||
		key == "response" {
		return true
	}
	return false
}

func decodeGenericOTLPAnyValue(value map[string]interface{}) interface{} {
	if value == nil {
		return nil
	}
	if v, ok := value["stringValue"]; ok {
		return v
	}
	if v, ok := value["intValue"]; ok {
		return v
	}
	if v, ok := value["doubleValue"]; ok {
		return v
	}
	if v, ok := value["boolValue"]; ok {
		return v
	}
	if kv, ok := value["kvlistValue"].(map[string]interface{}); ok {
		if rawValues, ok := kv["values"].([]interface{}); ok {
			out := map[string]interface{}{}
			for _, rawAttr := range rawValues {
				attr, ok := rawAttr.(map[string]interface{})
				if !ok {
					continue
				}
				key, _ := attr["key"].(string)
				val, _ := attr["value"].(map[string]interface{})
				out[key] = decodeGenericOTLPAnyValue(val)
			}
			return out
		}
	}
	if arr, ok := value["arrayValue"].(map[string]interface{}); ok {
		if rawValues, ok := arr["values"].([]interface{}); ok {
			out := make([]interface{}, 0, len(rawValues))
			for _, item := range rawValues {
				itemMap, _ := item.(map[string]interface{})
				out = append(out, decodeGenericOTLPAnyValue(itemMap))
			}
			return out
		}
	}
	return nil
}
