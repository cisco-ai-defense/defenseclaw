// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// geminiCapture is one request a fake Decisions API saw.
type geminiCapture struct {
	body   map[string]json.RawMessage
	raw    string
	apiKey string
	bearer string
}

// fakeGeminiDecisions answers like the Decisions API: it refuses a "state"
// field the way the real endpoint does, and otherwise returns status and
// answer.
func fakeGeminiDecisions(t *testing.T, status int, answer string, seen *atomic.Value) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]json.RawMessage
		_ = json.Unmarshal(raw, &body)
		if seen != nil {
			seen.Store(geminiCapture{body: body, raw: string(raw), apiKey: r.Header.Get("x-goog-api-key"), bearer: r.Header.Get("Authorization")})
		}
		if _, ok := body["state"]; ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"code":"invalid_request","message":"Unknown parameter 'state'"}}`)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
}

func testGeminiDecisionModel(t *testing.T, url string) *decisionModel {
	t.Helper()
	cfg := &config.Config{DecisionModel: config.DecisionModelConfig{
		Enabled: true, Model: "gemini-decision-1", BaseURL: url, Timeout: 1,
		Protocol: config.DecisionModelProtocolGeminiDecisions,
	}}
	dm := newDecisionModel(cfg, "")
	if dm == nil {
		t.Fatal("newDecisionModel returned nil for an active gemini-decisions block")
	}
	return dm
}

const geminiBlockAnswer = `{"answers":{"disposition":{"type":"choice","choice":"block","probabilities":{"allow":0.01,"confirm":0.04,"block":0.95},"confidence":0.9},"risk":{"type":"score","score":1.9},"context_sufficient":{"type":"noul","noul":0.9}},"usage":{"total_input_tokens":480}}`

// TestGeminiDecisionsRequestContract: the state goes in a labeled input
// string (no state field), the key in x-goog-api-key (no Bearer), and the
// question set and answer parsing are the System One ones.
func TestGeminiDecisionsRequestContract(t *testing.T) {
	var seen atomic.Value
	srv := fakeGeminiDecisions(t, http.StatusOK, geminiBlockAnswer, &seen)
	defer srv.Close()
	t.Setenv(config.DefenseClawDecisionModelKeyEnv, "g-secret")
	dm := testGeminiDecisionModel(t, srv.URL)
	state := decisionModelState{
		SessionUserIntent: "fix the tests",
		CurrentToolCall:   decisionModelToolCall{Tool: "Bash", Arguments: `{"command":"go test ./... 2>&1 | tail"}`},
	}
	got := dm.decide(context.Background(), state)
	if got.route != decisionBlock || got.failure != "" || got.choice != "block" {
		t.Fatalf("decide = %+v, want a confident block", got)
	}
	c, _ := seen.Load().(geminiCapture)
	if c.apiKey != "g-secret" || c.bearer != "" {
		t.Fatalf("auth headers: x-goog-api-key set=%v, Authorization set=%v", c.apiKey != "", c.bearer != "")
	}
	for _, k := range []string{"model", "input", "questions"} {
		if _, ok := c.body[k]; !ok {
			t.Fatalf("request lacks %s: %s", k, c.raw)
		}
	}
	if len(c.body) != 3 {
		t.Fatalf("request has extra fields: %s", c.raw)
	}
	var input string
	if err := json.Unmarshal(c.body["input"], &input); err != nil {
		t.Fatal(err)
	}
	want, _ := decisionModelInput(state)
	if input != want || !strings.HasPrefix(input, "STATE (untrusted JSON):\n{\n \"session_user_intent\": \"fix the tests\",") {
		t.Fatalf("input = %q", input)
	}
	// No HTML escaping inside the text the model reads.
	if !strings.Contains(input, `2>&1`) {
		t.Fatalf("input escapes the command: %q", input)
	}
	var questions map[string]json.RawMessage
	_ = json.Unmarshal(c.body["questions"], &questions)
	for _, k := range []string{"disposition", "risk", "f_user_authorized", "f_serves_latest"} {
		if _, ok := questions[k]; !ok {
			t.Fatalf("questions lack %s", k)
		}
	}
	if len(questions) != 4 {
		t.Fatalf("questions = %d, want disposition, risk and the two flow questions", len(questions))
	}
}

// TestDecisionWireBodyIsDeterministic: the same call sends the same bytes
// (a replay cache keys on them), and System One keeps its state field.
func TestDecisionWireBodyIsDeterministic(t *testing.T) {
	state := decisionModelState{
		RecentToolCalls: []decisionModelToolCall{{Tool: "Read", Arguments: `{"file_path":"a<b>&c"}`}},
		CurrentToolCall: decisionModelToolCall{Tool: "Bash", Arguments: "ls"},
	}
	first, err := decisionWireBody(config.DecisionModelProtocolGeminiDecisions, "m", state, decisionModelQuestions)
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, _ := decisionWireBody(config.DecisionModelProtocolGeminiDecisions, "m", state, decisionModelQuestions)
		if string(again) != string(first) {
			t.Fatal("gemini-decisions body is not deterministic")
		}
	}
	so, _ := decisionWireBody(config.DecisionModelProtocolSystemOne, "m", state, decisionModelQuestions)
	if !strings.Contains(string(so), `"state":{`) || strings.Contains(string(so), `"input"`) {
		t.Fatalf("system-one body = %s", so)
	}
}

// TestGeminiDecisionsFailures: a rate limit, a server error and a
// wrong-type answer each escalate with a failure (never a block or an
// allow). Refusals are not failures (TestGeminiRefusals).
func TestGeminiDecisionsFailures(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		class     gatewaylog.JudgeFailureClass
		causeHint string
	}{
		{"other 400", http.StatusBadRequest, `{"error":{"code":"invalid_request"}}`, gatewaylog.JudgeFailureProvider, "HTTP 400"},
		{"numeric code", http.StatusBadRequest, `{"error":{"code":400,"status":"INVALID_ARGUMENT"}}`, gatewaylog.JudgeFailureProvider, "HTTP 400"},
		{"rate limit", http.StatusTooManyRequests, `{"error":{"code":"rate_limited"}}`, gatewaylog.JudgeFailureProvider, "HTTP 429"},
		{"server", http.StatusInternalServerError, `oops`, gatewaylog.JudgeFailureProvider, "HTTP 500"},
		{"wrong type", http.StatusOK, `{"answers":{"disposition":{"type":"score","score":0.2}}}`, gatewaylog.JudgeFailureOutputParse, "not a choice"},
		{"no probabilities", http.StatusOK, `{"answers":{"disposition":{"type":"choice","choice":"allow"}}}`, gatewaylog.JudgeFailureOutputParse, "sum to one"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeGeminiDecisions(t, tc.status, tc.body, nil)
			defer srv.Close()
			got := testGeminiDecisionModel(t, srv.URL).decide(context.Background(), decisionModelState{})
			if got.route != decisionEscalate || got.failure != tc.class || !strings.Contains(got.failureCause, tc.causeHint) {
				t.Fatalf("route=%v failure=%q cause=%q, want escalate %q with %q", got.route, got.failure, got.failureCause, tc.class, tc.causeHint)
			}
		})
	}
}

// TestGeminiRefusals: a safety refusal escalates without a failure and
// keeps its code. The shapes come from the API documentation (the Decisions
// API string error.code, and Google's general form with a numeric code and
// the class in status or details[].reason); none has been seen live yet
// (0 in the first 25k benchmark calls).
func TestGeminiRefusals(t *testing.T) {
	for _, tc := range []struct{ body, code string }{
		{`{"error":{"code":"safety","message":"x"}}`, "safety"},
		{`{"error":{"code":"prohibited_content"}}`, "prohibited_content"},
		{`{"error":{"code":400,"status":"BLOCKLIST","message":"x"}}`, "blocklist"},
		{`{"error":{"code":400,"status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SAFETY"}]}}`, "safety"},
	} {
		srv := fakeGeminiDecisions(t, http.StatusBadRequest, tc.body, nil)
		got := testGeminiDecisionModel(t, srv.URL).decide(context.Background(), decisionModelState{})
		srv.Close()
		if got.route != decisionEscalate || got.failure != "" || got.refusal != tc.code || got.skipped {
			t.Fatalf("%s: route=%v failure=%q refusal=%q skipped=%v", tc.body, got.route, got.failure, got.refusal, got.skipped)
		}
	}
	// A refusal on system-one (not a Decisions API) stays an HTTP 400 failure.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"code":"safety"}}`)
	}))
	defer srv.Close()
	if got := testDecisionModel(t, srv.URL, "").decide(context.Background(), decisionModelState{}); got.refusal != "" || got.failure != gatewaylog.JudgeFailureProvider {
		t.Fatalf("system-one 400: %+v", got)
	}
}

// TestGeminiRefusalAloneIsAConfirm (GAP-0342): in cascade 2 a refusal is
// the unsure answer, a HIGH confirm (an alert where the agent cannot ask),
// never the rule verdict alone, a block or an allow.
func TestGeminiRefusalAloneIsAConfirm(t *testing.T) {
	srv := fakeGeminiDecisions(t, http.StatusBadRequest, `{"error":{"code":"safety"}}`, nil)
	defer srv.Close()
	dm := testGeminiDecisionModel(t, srv.URL)
	dm.alone = true
	j := &LLMJudge{cfg: &config.JudgeConfig{ToolInjection: true}, decision: dm, decisionOnly: true}
	v := j.runToolDecision(context.Background(), "Bash", `{"command":"ls"}`, "sample")
	if v == nil || v.JudgeFailed || v.Action != guardrailActionConfirm || v.Severity != "HIGH" || !v.decisionConfirm ||
		!strings.Contains(v.Reason, "declined (safety)") {
		t.Fatalf("verdict = %+v, want a HIGH decision-model confirm", v)
	}
	if got := decisionConfirmWithoutAsk(&ToolInspectVerdict{decisionConfirm: true}, guardrailActionBlock); got != guardrailActionAlert {
		t.Fatalf("no-ask fallback of a refusal confirm = %q, want alert", got)
	}
}

// TestGeminiRefusalsLeaveTheBreakerClosed (GAP-0343): three refusals from
// one session do not pause the model for the next call of another
// session; three 429s still do.
func TestGeminiRefusalsLeaveTheBreakerClosed(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n <= 3 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"code":"safety"}}`)
			return
		}
		_, _ = io.WriteString(w, geminiBlockAnswer)
	}))
	defer srv.Close()
	dm := testGeminiDecisionModel(t, srv.URL)
	sessionA := ContextWithSessionID(context.Background(), "session-a")
	for range 3 {
		if got := dm.decide(sessionA, decisionModelState{}); got.refusal != "safety" {
			t.Fatalf("refusal not seen: %+v", got)
		}
	}
	sessionB := ContextWithSessionID(context.Background(), "session-b")
	if got := dm.decide(sessionB, decisionModelState{}); got.skipped || got.route != decisionBlock || calls.Load() != 4 {
		t.Fatalf("after 3 refusals the next call = %+v (upstream calls %d), want answered", got, calls.Load())
	}

	limited := fakeGeminiDecisions(t, http.StatusTooManyRequests, `{"error":{"code":"rate_limited"}}`, nil)
	defer limited.Close()
	dm2 := testGeminiDecisionModel(t, limited.URL)
	for range 3 {
		dm2.decide(sessionA, decisionModelState{})
	}
	if got := dm2.decide(sessionB, decisionModelState{}); !got.skipped {
		t.Fatalf("three 429s must open the breaker: %+v", got)
	}
}

// TestRouterSystemOneRefusalIsNotABreakerFailure (GAP-0343): the router
// classifier does not count a refusal against its breaker either.
func TestRouterSystemOneRefusalIsNotABreakerFailure(t *testing.T) {
	srv := fakeGeminiDecisions(t, http.StatusBadRequest, `{"error":{"code":"safety"}}`, nil)
	defer srv.Close()
	c := &systemOneClassifier{model: "gemini-decision-1", endpoint: srv.URL, protocol: config.DecisionModelProtocolGeminiDecisions,
		timeout: time.Second, client: srv.Client(), now: time.Now}
	for range 5 {
		_, _ = c.Classify(context.Background(), engine.ClassifyInput{Text: "x", Categories: []string{"code"}})
	}
	if c.breakerOpen() {
		t.Fatal("refusals opened the router breaker")
	}
}

// TestDecisionWireBodySystemOneMatchesBase pins the default request bytes
// to what the base sent (json.Marshal of {model, state, questions}).
func TestDecisionWireBodySystemOneMatchesBase(t *testing.T) {
	state := decisionModelState{SessionUserIntent: "fix <it> & ship",
		RecentToolCalls: []decisionModelToolCall{{Tool: "Read", Arguments: `{"file_path":"a.go"}`}},
		CurrentToolCall: decisionModelToolCall{Tool: "Bash", Arguments: `{"command":"go test 2>&1"}`}}
	got, err := decisionWireBody(config.DecisionModelProtocolSystemOne, "jev", state, decisionModelQuestions)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := json.Marshal(map[string]any{"model": "jev", "state": state, "questions": decisionModelQuestions})
	if string(got) != string(base) {
		t.Fatalf("system-one bytes changed:\n%s\n%s", got, base)
	}
}

// TestGeminiSystemOneStateIsRefused: the real API refuses a state field;
// a system-one client pointed at it fails (escalates), which is why the
// protocol must be set.
func TestGeminiSystemOneStateIsRefused(t *testing.T) {
	srv := fakeGeminiDecisions(t, http.StatusOK, geminiBlockAnswer, nil)
	defer srv.Close()
	got := testDecisionModel(t, srv.URL, "").decide(context.Background(), decisionModelState{})
	if got.route != decisionEscalate || got.failure != gatewaylog.JudgeFailureProvider {
		t.Fatalf("system-one against the Decisions API: %+v", got)
	}
}
