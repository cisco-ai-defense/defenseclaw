// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func resetOpenClawSessionAliases(t *testing.T) {
	t.Helper()
	reset := func() {
		openClawSessionAliases.mu.Lock()
		openClawSessionAliases.byID, openClawSessionAliases.now = nil, nil
		openClawSessionAliases.mu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

// An OpenClaw tool check is judged with the user's task the event router
// recorded under the session key of session.message, whether the plugin names
// the session by its key (the plugin of this release) or by the transcript's
// session id the stream gave for that key (an older plugin still loaded after
// an upgrade). A session id the stream never named finds no task
// (rel-1-0-10:GAP-0148).
func TestGAP0148OpenClawToolCheckIsJudgedWithTheUsersTask(t *testing.T) {
	resetOpenClawSessionAliases(t)
	const (
		sessionKey = "agent:main:main"
		transcript = "transcript-0148"
		task       = "summarize the README of this repository for the release notes"
	)
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, ToolInjection: true, HookConnectors: []string{"openclaw"}}
	cfg.Guardrail.DetectionStrategy = "judge_first"
	cfg.Guardrail.Connector = "openclaw"
	mock := injectionHitProvider()
	judge := &LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: mock, rp: &guardrail.RulePack{}}
	a := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	a.SetHookJudge(judge)
	// The generic route caps its scan at 200 ms; no judge round-trip fits in
	// it, and the judge's reading of the session is what is under test.
	a.inspectToolScanTimeout = time.Minute
	router := NewEventRouter(nil, store, logger, false)
	router.SetJudge(judge)

	router.scanInboundPrompt(sessionKey, "", "gpt-5.5", task)
	router.handleAgentEvent(EventFrame{Payload: mustMarshal(map[string]any{
		"runId": "run-0148", "stream": "lifecycle", "data": map[string]any{"phase": "start"},
		"sessionKey": sessionKey, "sessionId": transcript, "seq": 1, "ts": int64(1763337600000),
	})})

	handler := CorrelationMiddleware(nil)(http.HandlerFunc(a.handleInspectTool))
	judgedWithTask := func(t *testing.T, session string) bool {
		t.Helper()
		before := len(mock.captured)
		body, _ := json.Marshal(map[string]any{
			"tool": "fetch_url", "args": json.RawMessage(benignToolArgs),
			"session_id": session, "approval_surface": "native",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(SessionIDHeader, session)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("session %q: status %d: %s", session, w.Code, w.Body.String())
		}
		if len(mock.captured) == before {
			t.Fatalf("session %q: the tool judge never ran", session)
		}
		msgs := mock.captured[len(mock.captured)-1].Messages
		return strings.Contains(msgs[len(msgs)-1].Content, task)
	}

	if !judgedWithTask(t, sessionKey) {
		t.Error("a tool check under the session key was judged without the user's task")
	}
	if !judgedWithTask(t, transcript) {
		t.Error("a tool check under the session id the stream named for the key was judged without the user's task")
	}
	if judgedWithTask(t, "transcript-unknown") {
		t.Error("a tool check under a session id the stream never named was judged with another session's task")
	}
}

// The alias table keeps only what the stream named in the last hour, at most
// openClawSessionAliasCap ids, and never maps a key to itself.
func TestGAP0148OpenClawSessionAliasBounds(t *testing.T) {
	resetOpenClawSessionAliases(t)
	now := time.Unix(1763337600, 0)
	openClawSessionAliases.now = func() time.Time { return now }

	learnOpenClawSessionAlias("agent:main:main", "agent:main:main")
	learnOpenClawSessionAlias("", "agent:main:main")
	learnOpenClawSessionAlias("id-x", "")
	if n := len(openClawSessionAliases.byID); n != 0 {
		t.Fatalf("%d aliases from empty or self names", n)
	}

	learnOpenClawSessionAlias("id-0", "agent:main:k0")
	if got := openClawSessionKeyFor("id-0"); got != "agent:main:k0" {
		t.Fatalf("id-0 maps to %q", got)
	}
	now = now.Add(openClawSessionAliasTTL)
	if got := openClawSessionKeyFor("id-0"); got != "" {
		t.Fatalf("an alias past its hour still maps to %q", got)
	}

	for i := 0; i < openClawSessionAliasCap+10; i++ {
		now = now.Add(time.Millisecond)
		learnOpenClawSessionAlias(fmt.Sprintf("id-%d", i+1), fmt.Sprintf("agent:main:k%d", i+1))
	}
	if n := len(openClawSessionAliases.byID); n > openClawSessionAliasCap {
		t.Fatalf("%d aliases, cap %d", n, openClawSessionAliasCap)
	}
	if got := openClawSessionKeyFor(fmt.Sprintf("id-%d", openClawSessionAliasCap+10)); got != fmt.Sprintf("agent:main:k%d", openClawSessionAliasCap+10) {
		t.Fatalf("the newest alias maps to %q", got)
	}
	if got := openClawSessionKeyFor("id-1"); got != "" {
		t.Fatalf("the oldest alias over the cap still maps to %q", got)
	}
}
