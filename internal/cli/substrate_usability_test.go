// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
)

// The first sign-in needs only --admin-url: the cluster says how people
// sign in to it (GET /info, no token).
func TestSubstrateLoginReadsTheSignInServerFromTheCluster(t *testing.T) {
	info := map[string]any{}
	status := http.StatusOK
	var bearer []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer = append(bearer, r.Header.Get("Authorization"))
		if r.URL.Path != "/api/v1/substrate/info" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer srv.Close()
	ctx := t.Context()

	info = map[string]any{"sign_in": "oidc", "issuer": "https://sso.example.test/realms/corp", "client_id": "defenseclaw-launcher"}
	c := auth.Context{AdminURL: srv.URL}
	if err := substrateLoginInfo(ctx, &c, io.Discard); err != nil {
		t.Fatal(err)
	}
	if c.Issuer != "https://sso.example.test/realms/corp" || c.ClientID != "defenseclaw-launcher" {
		t.Fatalf("context = %+v", c)
	}
	// A flag that was given wins.
	c = auth.Context{AdminURL: srv.URL, ClientID: "my-client"}
	if err := substrateLoginInfo(ctx, &c, io.Discard); err != nil || c.ClientID != "my-client" || c.Issuer == "" {
		t.Fatalf("context = %+v, %v", c, err)
	}
	for _, b := range bearer {
		if b != "" {
			t.Fatalf("GET /info carried a bearer: %q", b)
		}
	}

	for _, tc := range []struct {
		name   string
		info   map[string]any
		status int
		want   string
		code   int
	}{
		{"kubernetes", map[string]any{"sign_in": "kubernetes"}, 200, "defenseclaw substrate login --kube --admin-url " + srv.URL, 2},
		{"none", map[string]any{"sign_in": "none"}, 200, "ask your administrator", substrateExitRefused},
		{"half oidc", map[string]any{"sign_in": "oidc", "issuer": "https://sso.example.test"}, 200, "--client-id ID", 2},
		{"old cluster", map[string]any{"reason": "not_found"}, 404, "give --issuer URL and --client-id ID", 2},
	} {
		info, status = tc.info, tc.status
		c := auth.Context{AdminURL: srv.URL}
		err := substrateLoginInfo(ctx, &c, io.Discard)
		if err == nil || !strings.Contains(err.Error(), tc.want) || commandExitCode(err) != tc.code {
			t.Errorf("%s: err = %v (exit %d), want %q (exit %d)", tc.name, err, commandExitCode(err), tc.want, tc.code)
		}
	}
}

// run adds a fresh suffix to every --name (GAP-0133); the name a person gave
// still finds the agent when only one has it.
func TestSubstrateNameFindsTheAgentRunNamed(t *testing.T) {
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET actors": jsonReply(map[string]any{"actors": []map[string]any{
			{"atespace": "eng-web", "name": "fix-tests-7f3a09c1"},
			{"atespace": "eng-web", "name": "docs-0a1b2c3d"},
			{"atespace": "eng-web", "name": "docs-99887766"},
			{"atespace": "eng-web", "name": "web-1"},
		}}),
	}}
	useFakeAdmin(t, f)
	s, err := substrateOpen(nil, &substrateCommon{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	for ref, want := range map[string]string{
		"fix-tests":          "fix-tests-7f3a09c1",
		"fix-tests-7f3a09c1": "fix-tests-7f3a09c1",
		"eng-web/web-1":      "web-1",
	} {
		a, err := resolveSubstrateActor(ctx, s.Client, ref)
		if err != nil || a.Name != want {
			t.Errorf("%s: got %q, %v; want %s", ref, a.Name, err, want)
		}
	}
	if _, err := resolveSubstrateActor(ctx, s.Client, "docs"); err == nil || !strings.Contains(err.Error(), "more than one agent") {
		t.Errorf("docs names two agents: %v", err)
	}
	for _, ref := range []string{"fix", "web", "eng-web/fix-tests"} {
		if _, err := resolveSubstrateActor(ctx, s.Client, ref); err == nil {
			t.Errorf("%s must not match", ref)
		}
	}
}

// GAP-0166: run with no profile anywhere asks the cluster, which gives the
// person the profile their groups map to.
func TestSubstrateRunNeedsNoProfile(t *testing.T) {
	t.Setenv("DEFENSECLAW_SUBSTRATE_PROFILE", "")
	tg, err := resolveSubstrateRunTarget(&substrateSession{}, &substrateRunFlags{}, "claude")
	if err != nil {
		t.Fatalf("run without a profile: %v", err)
	}
	if tg.profile != "" {
		t.Errorf("profile %q, want empty (the cluster picks)", tg.profile)
	}
}

// GAP-0184: OpenCode runs (proven in an actor although its OpenShell harness
// is unverified); the connectors with no Substrate proof stay refused.
func TestSubstrateRunVerifiedConnectors(t *testing.T) {
	t.Setenv("DEFENSECLAW_SUBSTRATE_PROFILE", "")
	t.Setenv("DEFENSECLAW_SUBSTRATE_TEMPLATE", "")
	tg, err := resolveSubstrateRunTarget(&substrateSession{}, &substrateRunFlags{}, "opencode")
	if err != nil {
		t.Fatalf("run opencode refused: %v", err)
	}
	if tg.connName != "opencode" {
		t.Errorf("connector %q, want opencode", tg.connName)
	}
	for _, agent := range []string{"amp", "cursor-agent", "devin"} {
		_, err := resolveSubstrateRunTarget(&substrateSession{}, &substrateRunFlags{}, agent)
		if err == nil || !strings.Contains(err.Error(), "not verified yet") {
			t.Errorf("run %s: %v, want the not-verified refusal", agent, err)
		}
	}
}

// GAP-0167: no free worker says what to do.
func TestSubstrateNoFreeWorkerMessage(t *testing.T) {
	msg := substrateAPIMessage(&api.Error{Status: 503, Reason: "no_free_worker"})
	for _, want := range []string{"no free worker", "nothing was started", "defenseclaw substrate list", "defenseclaw substrate delete NAME"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
}

// GAP-0167: the message counts the person own running agents.
func TestSubstrateNoWorkerCountsRunningAgents(t *testing.T) {
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET actors": jsonReply(map[string]any{"actors": []map[string]any{
			{"atespace": "eng-web", "name": "a1", "state": "running"},
			{"atespace": "eng-web", "name": "a2", "state": "running"},
			{"atespace": "eng-web", "name": "a3", "state": "suspended"},
		}}),
	}}
	useFakeAdmin(t, f)
	s, err := substrateOpen(nil, &substrateCommon{})
	if err != nil {
		t.Fatal(err)
	}
	msg := substrateNoWorkerMessage(t.Context(), s)
	for _, want := range []string{"no free worker", "nothing was started", "2 of your agents are running (a1, a2)", "defenseclaw substrate delete NAME"} {
		if !strings.Contains(msg, want) {
			t.Errorf("%q lacks %q", msg, want)
		}
	}
}
