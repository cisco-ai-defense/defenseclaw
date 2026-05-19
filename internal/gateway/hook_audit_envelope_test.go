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
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// TestRenderHookAuditEnvelope_RoundTrip locks the v1 schema field
// names and types. Adding a new field is an additive change (older
// consumers ignore it); renaming or retyping requires a Schema bump,
// which this test makes loud.
func TestRenderHookAuditEnvelope_RoundTrip(t *testing.T) {
	env := HookAuditEnvelope{
		Connector:   "codex",
		Event:       "PreToolUse",
		Result:      "ok",
		Action:      "block",
		RawAction:   "block",
		Severity:    "HIGH",
		Mode:        "action",
		Reason:      "tool not allowed",
		WouldBlock:  true,
		ElapsedMs:   123,
		BodyBytes:   456,
		RawOrigin:   "hook",
		RawEventIDs: []string{"raw-abc", "raw-def"},
	}
	out := renderHookAuditEnvelope(env)

	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("decode envelope: %v\nraw=%s", err, out)
	}
	for _, want := range []string{
		"schema", "timestamp", "connector", "event", "result", "action",
		"raw_action", "severity", "mode", "reason", "would_block",
		"elapsed_ms", "body_bytes", "raw_origin", "raw_event_ids",
	} {
		if _, ok := decoded[want]; !ok {
			t.Errorf("envelope missing required field %q", want)
		}
	}
	if got := decoded["schema"]; got != HookAuditEnvelopeSchema {
		t.Errorf("schema = %v, want %q", got, HookAuditEnvelopeSchema)
	}
	if got := decoded["would_block"]; got != true {
		t.Errorf("would_block = %v, want true", got)
	}
}

// TestRenderHookAuditEnvelope_PreRedactsReason is the M2 regression
// test: free-form text fields (today, just Reason) must be pre-
// redacted before the envelope is folded into the audit row. Without
// this, the downstream sanitiseEvent → redaction.ForSinkReason path
// tokenises on ", " / "; " literals INSIDE the strconv.Quote'd JSON
// value and corrupts the JSON envelope every audit sink writes.
//
// We don't try to assert "this exact PII pattern got redacted" —
// that's the redaction package's job. We DO assert that the rendered
// envelope JSON remains parseable AND that PII-suggestive substrings
// survive only in already-redacted form (the ForSinkReason marker
// `<redacted-` prefix). That's the actionable invariant: downstream
// jq/SIEM rules need parseable JSON, regardless of what the operator
// puts in Reason.
func TestRenderHookAuditEnvelope_PreRedactsReason(t *testing.T) {
	env := HookAuditEnvelope{
		Connector: "codex",
		Event:     "PreToolUse",
		Reason:    "blocked: contact admin@example.com, see ticket TKT-1234; key=AKIAABCDEFGHIJKLMNOP",
	}
	rendered := renderHookAuditEnvelope(env)
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(rendered), &decoded); err != nil {
		t.Fatalf("envelope JSON not parseable after Reason pre-redaction: %v\nraw=%s", err, rendered)
	}
	reasonOut, _ := decoded["reason"].(string)
	// The PII patterns must NOT appear verbatim — the redaction
	// pipeline replaces them with placeholder markers like
	// "<redacted-email-1>" or "<redacted-credential-1>". We do not
	// pin the exact marker text (that's an internal redaction
	// contract), only that the raw value is gone.
	for _, leaked := range []string{
		"admin@example.com",
		"AKIAABCDEFGHIJKLMNOP",
	} {
		if strings.Contains(reasonOut, leaked) {
			t.Errorf("reason field leaked raw PII %q\n  got=%q", leaked, reasonOut)
		}
	}
}

func TestRenderHookAuditEnvelope_PreRedactsExtra(t *testing.T) {
	env := HookAuditEnvelope{
		Connector: "codex",
		Event:     "PreToolUse",
		Extra: map[string]string{
			"operator_note": "user admin@example.com, token AKIAABCDEFGHIJKLMNOP",
		},
	}
	rendered := renderHookAuditEnvelope(env)
	var decoded struct {
		Extra map[string]string `json:"extra"`
	}
	if err := json.Unmarshal([]byte(rendered), &decoded); err != nil {
		t.Fatalf("envelope JSON not parseable after Extra pre-redaction: %v\nraw=%s", err, rendered)
	}
	got := decoded.Extra["operator_note"]
	for _, leaked := range []string{"admin@example.com", "AKIAABCDEFGHIJKLMNOP"} {
		if strings.Contains(got, leaked) {
			t.Errorf("extra field leaked raw PII %q\n  got=%q", leaked, got)
		}
	}
}

// TestRenderHookAuditEnvelope_LogInjection covers the codeguard-0-logging
// requirement: a hostile prompt that smuggles CR/LF/ANSI escapes into
// any string field must not be able to forge an extra log line or
// corrupt the operator's terminal.
func TestRenderHookAuditEnvelope_LogInjection(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"CR", "evil\rconnector=other"},
		{"LF", "evil\nconnector=other"},
		{"CRLF", "evil\r\nconnector=other"},
		{"ANSI", "evil\x1b[31mred"},
		{"NUL", "evil\x00before"},
		{"BEL", "evil\x07"},
		{"DEL", "evil\x7fbefore"},
		// 0x0B (vertical tab) — bypass attempts also flagged.
		{"VTAB", "evil\x0bnext"},
		// 0x0C (form feed).
		{"FF", "evil\x0cnext"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			env := HookAuditEnvelope{
				Connector:   tc.in,
				Event:       tc.in,
				Reason:      tc.in,
				Action:      tc.in,
				RawEventIDs: []string{tc.in},
				Extra:       map[string]string{tc.in: tc.in},
			}
			rendered := renderHookAuditEnvelope(env)
			// Renderer must not leak the raw control rune at all
			// — every dangerous rune is replaced with a space.
			for _, bad := range []string{"\r", "\n", "\x1b", "\x00", "\x07", "\x7f", "\x0b", "\x0c"} {
				if strings.Contains(rendered, bad) {
					t.Errorf("envelope leaked control rune %q in %s mode\nrendered=%q", bad, tc.name, rendered)
				}
			}
			// Must still be parseable JSON.
			var decoded map[string]interface{}
			if err := json.Unmarshal([]byte(rendered), &decoded); err != nil {
				t.Errorf("envelope parse failed after sanitization: %v\nraw=%s", err, rendered)
			}
		})
	}
}

// TestRenderHookAuditLegacyDetails_FormatStable freezes the legacy
// key=value ordering. logConnectorHookAuditEnvelope always emits
// both the JSON envelope AND this legacy tail in the audit row, so
// any reordering here would break operator log greps without
// warning.
func TestRenderHookAuditLegacyDetails_FormatStable(t *testing.T) {
	env := HookAuditEnvelope{
		Result:     "ok",
		Action:     "block",
		RawAction:  "block",
		Severity:   "HIGH",
		Mode:       "action",
		WouldBlock: true,
		ElapsedMs:  42,
		RawOrigin:  "hook",
	}
	got := renderHookAuditLegacyDetails(env)
	want := "result=ok action=block raw_action=block severity=HIGH mode=action would_block=true elapsed_ms=42 raw_origin=hook"
	if got != want {
		t.Errorf("legacy details mismatch:\n  got = %q\n  want = %q", got, want)
	}
}

func TestLogConnectorHookAuditEnvelope_PersistsStructuredPayload(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	api := &APIServer{logger: audit.NewLogger(store)}
	api.logConnectorHookAuditEnvelope(context.Background(), HookAuditEnvelope{
		Connector:  "codex",
		Event:      "PreToolUse",
		Result:     "ok",
		Action:     "block",
		RawAction:  "block",
		Severity:   "HIGH",
		Mode:       "action",
		Reason:     "matched policy",
		WouldBlock: true,
		ElapsedMs:  42,
	})

	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	got := events[0]
	if got.Action != string(audit.ActionConnectorHook) {
		t.Fatalf("Action = %q, want %q", got.Action, audit.ActionConnectorHook)
	}
	if !strings.Contains(got.Details, "details_json=") {
		t.Fatalf("details missing details_json payload: %q", got.Details)
	}
	if !strings.Contains(got.Details, "result=ok action=block raw_action=block") {
		t.Fatalf("details missing legacy hook tail: %q", got.Details)
	}
	if got.Structured["schema"] != HookAuditEnvelopeSchema {
		t.Fatalf("structured schema = %#v, want %q", got.Structured["schema"], HookAuditEnvelopeSchema)
	}
	if got.Structured["connector"] != "codex" || got.Structured["event"] != "PreToolUse" {
		t.Fatalf("structured hook identity did not round-trip: %#v", got.Structured)
	}
	if got.Structured["would_block"] != true {
		t.Fatalf("structured would_block = %#v, want true", got.Structured["would_block"])
	}
}

// TestRenderHookAuditLegacyDetails_LogInjection asserts the legacy
// formatter strips control runes per codeguard-0-logging.
func TestRenderHookAuditLegacyDetails_LogInjection(t *testing.T) {
	env := HookAuditEnvelope{
		Action: "block\nconnector=other action=allow",
		Reason: "evil\r\nfake_row=1",
	}
	got := renderHookAuditLegacyDetails(env)
	for _, bad := range []string{"\r", "\n"} {
		if strings.Contains(got, bad) {
			t.Errorf("legacy details leaked %q; got=%q", bad, got)
		}
	}
}

// TestRenderHookAuditLegacyDetails_ExtraKeysSortedDeterministically
// is the L3 regression test: Go's map iteration is intentionally
// randomized, so a naive `for k, v := range env.Extra` writes
// different output orderings across runs — breaking snapshot tests
// and confusing operators who grep for stable log lines. The
// formatter must sort Extra keys before emitting.
func TestRenderHookAuditLegacyDetails_ExtraKeysSortedDeterministically(t *testing.T) {
	env := HookAuditEnvelope{
		Action: "block",
		Extra: map[string]string{
			"zeta":    "1",
			"alpha":   "2",
			"middle":  "3",
			"omega":   "4",
			"bravo":   "5",
			"yankee":  "6",
			"charlie": "7",
		},
	}
	// 10 renders must produce byte-identical output. With un-sorted
	// iteration this would fail intermittently across Go runtimes.
	first := renderHookAuditLegacyDetails(env)
	for i := 0; i < 9; i++ {
		next := renderHookAuditLegacyDetails(env)
		if next != first {
			t.Fatalf("legacy details non-deterministic across runs:\n  first=%q\n  next =%q", first, next)
		}
	}

	// Verify sorted ascending: alpha < bravo < charlie < middle < omega < yankee < zeta.
	wantOrder := []string{"alpha=2", "bravo=5", "charlie=7", "middle=3", "omega=4", "yankee=6", "zeta=1"}
	pos := 0
	for _, want := range wantOrder {
		idx := strings.Index(first[pos:], want)
		if idx < 0 {
			t.Fatalf("legacy details missing %q (or out of order):\n  got=%q", want, first)
		}
		pos += idx + len(want)
	}
}
