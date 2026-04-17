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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The /inspect handler has historically echoed the entire match
// window back to the caller in DetailedFindings[].Evidence. When a
// downstream operator pipes the response body to a log aggregator
// that (correctly) ignores DefenseClaw's audit redactor, that raw
// PII bypasses the persistent-sink redaction invariant.
//
// These tests lock in the new behavior:
//
//  1. By default, Evidence is replaced with the ForSinkEvidence
//     placeholder shape.
//  2. A client that opts in by setting the X-DefenseClaw-Reveal-PII
//     header to exactly "1" receives the original evidence, and the
//     reveal is recorded in the audit store.
//  3. Any other header value (including "true", "yes", empty) keeps
//     the default redacted response.

// piiPayload is a message body that reliably produces
// DetailedFindings with raw Evidence containing PII. We target the
// Anthropic API key pattern because ScanAllRules ships with a
// high-confidence regex for it and the literal is unique enough
// that substring assertions are not ambiguous.
const piiPayload = `{"tool":"message","args":{},` +
	`"content":"leaked secret sk-ant-api03-abcdefghij1234567890abcdefghij",` +
	`"direction":"outbound"}`

// piiLiteral is the substring we assert is or is not present in
// response bodies and audit rows. Must match piiPayload exactly.
const piiLiteral = "sk-ant-api03-abcdefghij1234567890abcdefghij"

func TestInspectHandler_RedactsEvidenceByDefault(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool",
		bytes.NewBufferString(piiPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleInspectTool(w, req)

	raw, _ := readBody(w)
	if strings.Contains(raw, piiLiteral) {
		t.Fatalf("default response leaked secret: %s", raw)
	}

	var verdict ToolInspectVerdict
	if err := json.Unmarshal([]byte(raw), &verdict); err != nil {
		t.Fatalf("decode verdict: %v", err)
	}
	if len(verdict.DetailedFindings) == 0 {
		t.Fatalf("expected DetailedFindings for secret payload; got none. body=%s", raw)
	}
	for i, f := range verdict.DetailedFindings {
		if strings.Contains(f.Evidence, piiLiteral) {
			t.Errorf("finding[%d].Evidence leaked secret: %q", i, f.Evidence)
		}
		if !strings.HasPrefix(f.Evidence, "<redacted-evidence") {
			t.Errorf("finding[%d].Evidence = %q, want <redacted-evidence ...> placeholder",
				i, f.Evidence)
		}
	}
}

func TestInspectHandler_RevealHeaderOptsIntoRawEvidence(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool",
		bytes.NewBufferString(piiPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Reveal-PII", "1")
	w := httptest.NewRecorder()
	api.handleInspectTool(w, req)

	raw, _ := readBody(w)
	var verdict ToolInspectVerdict
	if err := json.Unmarshal([]byte(raw), &verdict); err != nil {
		t.Fatalf("decode verdict: %v", err)
	}
	if len(verdict.DetailedFindings) == 0 {
		t.Fatalf("expected DetailedFindings; body=%s", raw)
	}
	found := false
	for _, f := range verdict.DetailedFindings {
		if strings.Contains(f.Evidence, piiLiteral) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("reveal header did not produce raw Evidence: %s", raw)
	}
}

func TestInspectHandler_RevealHeaderIgnoresNonOneValues(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")

	cases := []string{"", "0", "true", "yes", "on", "  1  "}
	for _, val := range cases {
		t.Run("header="+val, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool",
				bytes.NewBufferString(piiPayload))
			req.Header.Set("Content-Type", "application/json")
			if val != "" {
				req.Header.Set("X-DefenseClaw-Reveal-PII", val)
			}
			w := httptest.NewRecorder()
			api.handleInspectTool(w, req)

			raw, _ := readBody(w)
			if strings.Contains(raw, piiLiteral) {
				t.Errorf("header %q caused leak: %s", val, raw)
			}
		})
	}
}

// Sanity check: the reveal path must not disable persistent-sink
// redaction. The audit store is a persistent sink, so even when a
// caller asks for raw evidence in the response body, the
// corresponding audit event details must still be scrubbed. We
// piggy-back on the existing SQLite-backed test logger and assert
// the event reason does not contain raw PII.
func TestInspectHandler_RevealDoesNotUnmaskAuditStore(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool",
		bytes.NewBufferString(piiPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Reveal-PII", "1")
	w := httptest.NewRecorder()
	api.handleInspectTool(w, req)

	events, err := api.store.ListEvents(50)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for _, e := range events {
		if strings.Contains(e.Details, piiLiteral) {
			t.Errorf("audit event %s leaked secret in Details: %q", e.ID, e.Details)
		}
	}
}

func readBody(w *httptest.ResponseRecorder) (string, int) {
	return w.Body.String(), w.Result().StatusCode
}
