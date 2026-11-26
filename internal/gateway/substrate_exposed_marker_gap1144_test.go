// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-1144 (the name clause of GAP-0504): the marker that replaces an
// exposed actor_secrets value read [actor_secret:NAME], and the audit
// redactor took actor_secret:NAME for a secret assignment, so the row
// carried <redacted type=secrets.assignment ...> in place of the name (with
// a per-replica key, so not even comparable across replicas). The audit must
// name the secret by its key name and never hold the value: the marker
// survives the sensitive profile's detectors and the guardrail secret
// classifier the audit engine adds (GAP-0426) in every context a tool result
// or a prompt puts it in.
func TestGAP1144ExposedSecretMarkerNamesTheSecretInTheAudit(t *testing.T) {
	values := map[string]string{
		"sv17-exposed": "Qm7rTz4wXc9bVn2kLp8sYd5hGf3jRa6e",
		"github-token": "9f3c1a7e5b2d4c6a8e0f1b3d5a7c9e2f",
		"db_password":  "pW9-xK2vL7qR4nT8mZ3s",
		"API_KEY":      "AbCdEf0123456789GhIjKlMn",
	}
	profile, ok := redaction.BuiltInProfile(redaction.ProfileSensitive)
	if !ok {
		t.Fatal("no sensitive profile")
	}
	key := bytes.Repeat([]byte{0x42}, 32)
	// The detectors replace a whole quoted or header credential value,
	// marker included: there only the value's absence is asserted, and the
	// audit row of the next test names the secret.
	forms := map[string]bool{
		"%s\n": true, "token=%s": true, "My token is %s": true, "the secret is %s.": true, "export API_KEY=%s": true,
		"password: %s": true, "https://x.example/?api_key=%s": true, `{"secret":"%s"}`: false, "Authorization: Bearer %s": false,
	}
	for name, value := range values {
		for form, readable := range forms {
			text := fmt.Sprintf(form, value)
			masked, names := substrateMaskExposed([]byte(text), map[string]string{name: value})
			if len(names) != 1 || strings.Contains(string(masked), value) {
				t.Fatalf("%s in %q: not masked: %s", name, form, masked)
			}
			for _, class := range []observability.FieldClass{observability.FieldClassContent, observability.FieldClassEvidence} {
				result, err := redaction.DetectAndRedact(string(masked), class, profile.DetectorGroups(), key, nil)
				if err != nil {
					t.Fatalf("%s in %q: %v", name, form, err)
				}
				if readable && !strings.Contains(result.Value, name) {
					t.Errorf("%s in %q (%s): the audit text does not name the secret: %s", name, form, class, result.Value)
				}
				if strings.Contains(result.Value, value) {
					t.Errorf("%s in %q: the value reached the audit text", name, form)
				}
			}
			at := strings.Index(string(masked), name)
			for _, span := range guardrailSecretSpans(string(masked)) {
				if !readable {
					break
				}
				if span[0] < at+len(name) && at < span[1] {
					t.Errorf("%s in %q: the guardrail secret classifier flags the name: %q", name, form, string(masked)[span[0]:span[1]])
				}
			}
		}
	}
}

// The hook call that carried an exposed value writes one audit row naming
// the secret, the actor and the person, never the value, whatever the
// value's position in the text (GAP-1144).
func TestGAP1144ExposedSecretAuditRowNamesTheSecretActorAndPerson(t *testing.T) {
	const value = "9f3c1a7e5b2d4c6a8e0f1b3d5a7c9e2f"
	f := newSubstrateFixture(t)
	st := f.api.substrateState()
	st.cfg.LLM = &substrateLLM{cfg: SubstrateLLMConfig{ExposedValues: func(string) map[string]string {
		return map[string]string{"sv17-exposed": value}
	}}}
	type row struct {
		summary string
		details map[string]any
	}
	var rows []row
	st.audit = func(_ context.Context, _, summary string, details map[string]any) {
		rows = append(rows, row{summary, details})
	}
	h := substrateEnvelopeMiddleware(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	reg := registry.Registration{Atespace: "eng-web", Name: "alice-1", UID: subUID1, Connector: "claudecode", Profile: "eng",
		Person: registry.Person{Kind: "oidc", Issuer: "https://idp.example", Subject: "s-1", Principal: "alice@example.com"}}
	send := func(payload map[string]any) {
		ctx := context.WithValue(context.Background(), substrateRegistrationKey{}, reg)
		ctx = withSubstrateRoute(ctx, substrateActorRoute{class: sandboxauth.RouteHook, connector: "claudecode"})
		req := httptest.NewRequest(http.MethodPost, substrateHookPrefix+"claudecode", strings.NewReader(envelope("claudecode", payload))).WithContext(ctx)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	send(map[string]any{"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": "cat build-note.txt"},
		"tool_response": map[string]any{"stdout": `{"secret":"` + value + `"}`}})
	if len(rows) != 1 {
		t.Fatalf("%d audit rows for a hook call that carried the exposed value, want 1", len(rows))
	}
	raw, _ := json.Marshal(rows[0].details)
	profile, _ := redaction.BuiltInProfile(redaction.ProfileSensitive)
	for _, text := range []string{rows[0].summary, string(raw)} {
		if strings.Contains(text, value) {
			t.Fatalf("the audit row holds the value: %s", text)
		}
		result, err := redaction.DetectAndRedact(text, observability.FieldClassContent, profile.DetectorGroups(), bytes.Repeat([]byte{0x42}, 32), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"sv17-exposed", "alice-1"} {
			if !strings.Contains(result.Value, want) {
				t.Errorf("the redacted audit row does not name %s: %s", want, result.Value)
			}
		}
	}
	if rows[0].details["event"] != "substrate.exposed_secret_masked" || rows[0].details["person_id"] != "https://idp.example#s-1" ||
		rows[0].details["principal"] != "alice@example.com" || !strings.Contains(rows[0].summary, "alice@example.com") {
		t.Errorf("row details %v", rows[0].details)
	}
	// A call without the value writes no row.
	rows = nil
	send(map[string]any{"hook_event_name": "UserPromptSubmit", "prompt": "hello"})
	if len(rows) != 0 {
		t.Errorf("a call without the value wrote %d rows", len(rows))
	}
}
