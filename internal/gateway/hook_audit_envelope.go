// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// HookAuditEnvelopeSchema identifies the audit-envelope shape. Bumped
// only when the wire-format breaks compatibility; sinks check this
// before parsing.
const HookAuditEnvelopeSchema = "defenseclaw.hook.v1"

// HookAuditEnvelope is the structured JSON shape emitted from the
// unified hook collector for every accepted hook invocation. Sinks
// can rely on the field names being stable across releases inside a
// single Schema value; new fields are added as omitempty so older
// consumers ignore them.
//
// Why a typed shape instead of free-form details strings?
//
//   - The legacy "action=… raw_action=… severity=…" line was a Go
//     fmt.Sprintf — every new field meant grepping every call site,
//     and operators ran `jq`-flavoured regexes on a non-JSON value.
//   - codeguard-0-logging requires structured fields with explicit
//     redaction filters; this envelope is the structured form.
//   - The unified hook collector routes codex + claudecode through
//     the same handleAgentHook code path. Without a typed envelope
//     every connector-specific dispatch would re-invent the details
//     string and silently drift.
//
// Audit rows now carry this envelope directly on audit.Event.Structured
// and persist it as audit_events.structured_json. The legacy `details`
// column still carries BOTH the JSON envelope (under the literal key
// `details_json=`) AND the historical "action=… raw_action=…
// severity=…" tail, so operators with existing grep recipes are not
// regressed while new tooling can read structured_json. See
// logConnectorHookAuditEnvelope in hook_telemetry.go.
//
// All string fields are run through stripLogInjectionRunes before
// serialization — CR/LF/ANSI escape sequences are stripped so a
// hostile prompt can't fake new audit rows by embedding "\n" in a
// reason. Required by codeguard-0-logging.
type HookAuditEnvelope struct {
	Schema      string            `json:"schema"`
	Timestamp   string            `json:"timestamp"`
	Connector   string            `json:"connector"`
	Event       string            `json:"event"`
	Result      string            `json:"result"`
	Action      string            `json:"action,omitempty"`
	RawAction   string            `json:"raw_action,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	Mode        string            `json:"mode,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	WouldBlock  bool              `json:"would_block"`
	ElapsedMs   int64             `json:"elapsed_ms,omitempty"`
	BodyBytes   int64             `json:"body_bytes,omitempty"`
	RawOrigin   string            `json:"raw_origin,omitempty"`
	RawEventIDs []string          `json:"raw_event_ids,omitempty"`
	RawPayload  string            `json:"raw_payload,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`

	// EvaluationID + RuleIDs are the unified-pipeline correlation
	// keys this hook emission was attributed to. The hook
	// evaluator stamps them on agentHookResponse via
	// emitHookRuleFindings; finalizeAgentHook copies them onto the
	// envelope so audit sinks see the same join key SIEM
	// dashboards pivot on (matches ScanPayload.evaluation_id /
	// ScanFindingPayload.evaluation_id / VerdictPayload.
	// evaluation_id). Both are omitempty: hooks that fire on a
	// clean evaluation (no rules matched) carry neither.
	EvaluationID string   `json:"evaluation_id,omitempty"`
	RuleIDs      []string `json:"rule_ids,omitempty"`

	// Multi-connector identity fields. logConnectorHookAuditEnvelope
	// mirrors these onto the audit.Event columns of the same name
	// (SQLite migration 16) AND they ride inside this structured JSON
	// (audit_events.structured_json + the gateway structured-log
	// envelope), so all three sinks carry the same values — the DN2
	// parity contract. Connector is the existing field above.
	//   - StepIdx: 1-indexed per-turn counter within a session.
	//   - Enforced: true when the decision was an enforced block.
	//   - RulePackDir: effective rule-pack dir the verdict used.
	StepIdx     int    `json:"step_idx,omitempty"`
	Enforced    bool   `json:"enforced,omitempty"`
	RulePackDir string `json:"rule_pack_dir,omitempty"`

	// Agent lifecycle correlation is copied from the same phase snapshot used
	// by the native lifecycle/tool/hook-decision events. These additive v1
	// fields let the durable SQLite structured_json row prove which transition
	// produced the connector-facing decision without a lossy JSONL join.
	AgentPhase         string `json:"agent_phase,omitempty"`
	AgentPreviousPhase string `json:"agent_previous_phase,omitempty"`
	AgentSequence      int64  `json:"agent_sequence,omitempty"`
	AgentLifecycleID   string `json:"agent_lifecycle_id,omitempty"`
	AgentExecutionID   string `json:"agent_execution_id,omitempty"`
	AgentOperationID   string `json:"agent_operation_id,omitempty"`

	// AuditActionOverride steers the audit ROW action (not the
	// envelope JSON). When non-empty, the audit.Logger writes the
	// row under this action constant instead of
	// audit.ActionConnectorHook. Used by the synthetic codex notify
	// path to emit ActionConnectorHookSynthetic so SIEM rules can
	// distinguish synthesized events from operator-fired hooks
	// without losing visibility. Marshalled JSON omits this
	// because operators read it from the audit row's `Action`
	// column, not the details payload.
	AuditActionOverride string `json:"-"`
}

// renderHookAuditEnvelope serializes the envelope as a compact JSON
// document with the schema/timestamp filled in. Returns an empty
// string only when the envelope is completely empty (defensive
// fallback for the malformed path — sinks treat empty details as a
// no-op).
//
// All string fields are sanitized in place before encoding; the
// caller receives a JSON value that has no CR/LF/control runes in
// any field. Map values flow through the same sanitizer. Booleans
// and integers are not touched.
func renderHookAuditEnvelope(env HookAuditEnvelope) string {
	if env.Schema == "" {
		env.Schema = HookAuditEnvelopeSchema
	}
	if env.Timestamp == "" {
		env.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	env.Connector = stripLogInjectionRunes(env.Connector)
	env.Event = stripLogInjectionRunes(env.Event)
	env.Result = stripLogInjectionRunes(env.Result)
	env.Action = stripLogInjectionRunes(env.Action)
	env.RawAction = stripLogInjectionRunes(env.RawAction)
	env.Severity = stripLogInjectionRunes(env.Severity)
	env.Mode = stripLogInjectionRunes(env.Mode)
	// M2 fix: Reason is the only envelope field that routinely
	// carries user-influenced free-form text (policy reasons, AID
	// findings, scanner messages). The downstream audit choke point
	// runs the assembled `details` string through
	// redaction.ForSinkReason, which splits on raw ", " / "; "
	// byte sequences and per-chunk redacts. Without pre-redaction
	// here, a Reason like "X, Y" would split details_json across
	// that boundary and each half would be independently redacted,
	// corrupting the JSON value. By redacting Reason FIRST and
	// marking the envelope as already-redacted-equivalent (the
	// resulting JSON contains no further "free-form" surfaces),
	// the downstream pass becomes a no-op via isAlreadyRedacted
	// for any envelope whose Reason actually contained PII.
	env.Reason = preRedactEnvelopeFreeForm(env.Reason)
	env.RulePackDir = stripLogInjectionRunes(env.RulePackDir)
	if phase, ok := gatewaylog.NormalizeAgentPhase(env.AgentPhase); ok {
		env.AgentPhase = phase
	} else {
		env.AgentPhase = stripLogInjectionRunes(env.AgentPhase)
	}
	if previous, ok := gatewaylog.NormalizeAgentPhase(env.AgentPreviousPhase); ok {
		env.AgentPreviousPhase = previous
	} else {
		env.AgentPreviousPhase = ""
	}
	env.AgentLifecycleID = stripLogInjectionRunes(env.AgentLifecycleID)
	env.AgentExecutionID = stripLogInjectionRunes(env.AgentExecutionID)
	env.AgentOperationID = stripLogInjectionRunes(env.AgentOperationID)
	env.RawOrigin = stripLogInjectionRunes(env.RawOrigin)
	for i, id := range env.RawEventIDs {
		env.RawEventIDs[i] = stripLogInjectionRunes(id)
	}
	env.RawPayload = preRedactEnvelopeFreeForm(env.RawPayload)
	if env.Extra != nil {
		clean := make(map[string]string, len(env.Extra))
		for k, v := range env.Extra {
			cleanKey := stripLogInjectionRunes(k)
			if cleanKey == "" {
				continue
			}
			clean[cleanKey] = preRedactEnvelopeFreeForm(v)
		}
		env.Extra = clean
	}
	b, err := json.Marshal(env)
	if err != nil {
		// JSON marshaling of a string/bool/int map cannot fail in
		// practice; emit a quoted fallback rather than panicking so
		// the audit row still lands.
		return fmt.Sprintf(`{"schema":%q,"connector":%q,"event":%q,"result":"encode_error"}`,
			HookAuditEnvelopeSchema, env.Connector, env.Event)
	}
	return string(b)
}

func renderHookAuditEnvelopePayload(env HookAuditEnvelope) (string, map[string]any) {
	rendered := renderHookAuditEnvelope(env)
	if rendered == "" {
		return "", nil
	}
	var structured map[string]any
	if err := json.Unmarshal([]byte(rendered), &structured); err != nil {
		return rendered, nil
	}
	return rendered, structured
}

// preRedactEnvelopeFreeForm runs free-form, user-influenced fields
// through the same redaction pipeline the downstream audit sink would
// apply, BEFORE the field is folded into the envelope JSON. This is
// the M2 fix.
//
// Background: internal/audit/logger.go's sanitizeEvent runs the
// assembled audit details string through redaction.ForSinkReason,
// which tokenises on raw ", " / "; " byte sequences and per-chunk
// redacts. The hook envelope places JSON next to free-form text in a
// single `details` blob; without pre-redaction, a Reason carrying
// "blocked, see logs" creates a split point INSIDE the strconv.Quote'd
// JSON value, and PII patterns elsewhere in the JSON are then
// inline-redacted, breaking jq / SIEM parsers that expect well-formed
// details_json.
//
// The fix is to pre-redact the free-form fields. ForSinkReason is
// idempotent (its isAlreadyRedacted fast-path skips strings whose
// chunks are already `<redacted...>` placeholders or safe glue
// tokens), so the downstream pass is a no-op for already-redacted
// material — meaning the envelope JSON we emit here is identical to
// what the audit row contains, regardless of what
// redaction.ForSinkReason does later.
//
// stripLogInjectionRunes still runs on top so CR/LF/ANSI cannot
// survive even within already-redacted markers.
func preRedactEnvelopeFreeForm(s string) string {
	if s == "" {
		return s
	}
	return stripLogInjectionRunes(string(redaction.ForSinkReason(s)))
}

// stripLogInjectionRunes removes characters an attacker could use to
// forge fake log lines or smuggle ANSI escape sequences into operator
// terminals. Specifically:
//
//   - 0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F: ASCII control runes.
//   - 0x0A, 0x0D: CR and LF — the classic log-injection vectors.
//   - 0x1B: ESC, the prefix for ANSI escape sequences.
//
// 0x09 (TAB) and printable space are preserved so JSON readability
// isn't degraded for legitimate values. The replacement char is
// 0x20 (single space) so adjacent valid runes stay separated.
func stripLogInjectionRunes(s string) string {
	if s == "" {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\t':
			out = append(out, c)
		case c < 0x20:
			out = append(out, ' ')
		case c == 0x7F:
			out = append(out, ' ')
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// renderHookAuditLegacyDetails preserves the historical key=value
// formatter used by codex/claudecode/agent_hook today, so the audit
// row remains greppable for operators while the new JSON envelope
// rolls out. Callers pass the SAME HookAuditEnvelope they would
// hand to renderHookAuditEnvelope; this helper renders the legacy
// shape from it.
//
// Field ordering matches the existing call sites in agent_hook.go,
// codex_hook.go, and claude_code_hook.go so tests that snapshot the
// audit line keep passing under the flag-off path.
func renderHookAuditLegacyDetails(env HookAuditEnvelope) string {
	var b strings.Builder
	writeKV := func(key, value string) {
		if value == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(stripLogInjectionRunes(value))
	}
	writeKV("result", env.Result)
	writeKV("action", env.Action)
	writeKV("raw_action", env.RawAction)
	writeKV("severity", env.Severity)
	writeKV("mode", env.Mode)
	writeKV("reason", env.Reason)
	if env.WouldBlock {
		writeKV("would_block", "true")
	} else {
		writeKV("would_block", "false")
	}
	if env.ElapsedMs > 0 {
		writeKV("elapsed_ms", strconv.FormatInt(env.ElapsedMs, 10))
	}
	if env.BodyBytes > 0 {
		writeKV("body_bytes", strconv.FormatInt(env.BodyBytes, 10))
	}
	if env.RawOrigin != "" {
		writeKV("raw_origin", env.RawOrigin)
	}
	if len(env.RawEventIDs) > 0 {
		writeKV("raw_event_ids", strings.Join(env.RawEventIDs, ","))
	}
	if env.RawPayload != "" {
		writeKV("raw_payload", strconv.Quote(env.RawPayload))
	}
	// Extra keys are emitted in sorted order so snapshot tests and
	// log greps stay deterministic across runs. Go's map-iteration
	// order is intentionally randomized; the audit row should not
	// inherit that randomness.
	if len(env.Extra) > 0 {
		keys := make([]string, 0, len(env.Extra))
		for k := range env.Extra {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			writeKV(stripLogInjectionRunes(k), env.Extra[k])
		}
	}
	return b.String()
}
