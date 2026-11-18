// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The substrate fixture (substrate_listener_test.go) is not built on Windows.

//go:build !windows

package gateway

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

const authCanary = "SUB-J21-CANARY-7f3a"

// canaryPeople refuses every token; its message carries attacker text (a
// header alg), as the real verifier's does.
type canaryPeople struct{}

func (canaryPeople) Verify(context.Context, string) (identity.Person, error) {
	return identity.Person{}, &identity.Error{Reason: identity.ReasonAlgorithm, Message: `alg "` + authCanary + `" is not accepted`}
}

// waitAuthRefusalRows waits up to 3 s for n auth_refused rows, then a
// little longer for the log lines written after them.
func waitAuthRefusalRows(t *testing.T, store *audit.Store, n int) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if len(authRefusalRows(t, store)) >= n {
			break
		}
	}
	time.Sleep(100 * time.Millisecond)
}

func authRefusalRows(t *testing.T, store *audit.Store) []audit.Event {
	t.Helper()
	events, err := store.ListEvents(1000)
	if err != nil {
		t.Fatal(err)
	}
	var rows []audit.Event
	for _, e := range events {
		if strings.Contains(e.Details, `"event":"auth_refused"`) {
			rows = append(rows, e)
		}
	}
	return rows
}

// GAP-0407, GAP-0408: a refused token on either listener (no token, a
// forged one, one whose verifier message carries attacker text) leaves a
// gateway log line and a substrate audit row with the listener, the closed
// reason and the client address class, and never the token, a claim or
// the verifier's message. A flood is bounded: one row per listener and
// reason per window, which names how many refusals it stands for.
func TestSubstrateRefusedTokensAreLoggedAndAuditedGAP0407GAP0408(t *testing.T) {
	f := newSubstrateFixture(t)
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger

	logs := captureStderr(t, func() {
		// GAP-0407: a hook and a model call with no actor token.
		if rec := f.do(t, f.actor, http.MethodPost, substrateHookPrefix+"claudecode", "", envelope("claudecode", map[string]any{})); rec.Code != http.StatusUnauthorized || reasonOf(t, rec) != "missing_token" {
			t.Fatalf("hook with no token: %d %s", rec.Code, rec.Body)
		}
		if rec := f.do(t, f.actor, http.MethodPost, substrateLLMPrefix+"bedrock/model/x/converse", "", "{}"); rec.Code != http.StatusUnauthorized || reasonOf(t, rec) != "missing_token" {
			t.Fatalf("model call with no token: %d %s", rec.Code, rec.Body)
		}
		// GAP-0408: the admin listener, no token and a forged one.
		if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "", ""); rec.Code != http.StatusUnauthorized || reasonOf(t, rec) != "missing_token" {
			t.Fatalf("admin with no token: %d %s", rec.Code, rec.Body)
		}
		if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", authCanary+".forged.sig", ""); rec.Code != http.StatusUnauthorized || reasonOf(t, rec) != "signature" {
			t.Fatalf("admin with a forged token: %d %s", rec.Code, rec.Body)
		}
		// A flood of forged person tokens.
		for range 200 {
			f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", authCanary+".flood.sig", "")
		}
		// Rows and lines are written off the request path.
		waitAuthRefusalRows(t, store, 3)
	})

	for _, want := range []string{
		"actor listener refused a token: missing_token",
		"admin listener refused a token: missing_token",
		"admin listener refused a token: signature",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("gateway log has no %q:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, authCanary) {
		t.Errorf("the gateway log carries token bytes:\n%s", logs)
	}
	rows := authRefusalRows(t, store)
	per := map[string]int{}
	for _, e := range rows {
		if strings.Contains(e.Details, authCanary) {
			t.Errorf("an audit row carries token bytes: %s", e.Details)
		}
		if !strings.Contains(e.Details, `"source":"substrate"`) || !strings.Contains(e.Details, `"client":"private"`) {
			t.Errorf("row without the substrate source or the client class: %s", e.Details)
		}
		for _, k := range []string{`"listener":"actor","reason":"missing_token"`, `"listener":"admin","reason":"missing_token"`, `"listener":"admin","reason":"signature"`} {
			if strings.Contains(e.Details, strings.Split(k, ",")[0]) && strings.Contains(e.Details, strings.Split(k, ",")[1]) {
				per[k]++
			}
		}
	}
	for _, k := range []string{`"listener":"actor","reason":"missing_token"`, `"listener":"admin","reason":"missing_token"`, `"listener":"admin","reason":"signature"`} {
		// One row per listener, reason, route and client class per window:
		// the actor's two refused routes (hook, llm) are two rows; the
		// admin flood of 201 is one.
		want := 1
		if strings.HasPrefix(k, `"listener":"actor"`) {
			want = 2
		}
		if per[k] != want {
			t.Errorf("%s: %d audit rows, want exactly %d (a flood is one row per window); rows: %d", k, per[k], want, len(rows))
		}
	}
	// The forged-token row is an alert (MEDIUM); a missing token is INFO.
	for _, e := range rows {
		forged := strings.Contains(e.Details, `"reason":"signature"`)
		if forged && e.Severity != "MEDIUM" || !forged && e.Severity != "INFO" {
			t.Errorf("severity %s for %s", e.Severity, e.Details)
		}
	}
}
