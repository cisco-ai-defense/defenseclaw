// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// GAP-0527: a contractor (group dc-r102-contractors, profile ops) whose
// login saved --default-profile eng ran "run claude" with no --profile and
// got "you may not use that profile ... leave --profile out", while policy
// show said ops and "run claude --profile ops" worked. The cluster resolves
// the person's profile from their token groups; the launcher sent the
// login's saved default, which is not theirs. That saved default is a
// preference: refused, the run asks again with no profile and the cluster
// picks the person's own. A profile the person named is not replaced, and a
// person with no profile at all is told so instead of "leave --profile out".
func TestRunLoginDefaultProfileNotTheCallersGAP0527(t *testing.T) {
	t.Setenv("DEFENSECLAW_SUBSTRATE_PROFILE", "")
	t.Setenv("DEFENSECLAW_SUBSTRATE_TEMPLATE", "")
	var mu sync.Mutex
	var sent []string
	assigned := "ops"
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"POST actors": func(w http.ResponseWriter, r *http.Request) {
			var req api.CreateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			sent = append(sent, req.Profile)
			own := assigned
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			// The gateway's rule: no profile is the caller's own; a named
			// one must be it.
			if own == "" || (req.Profile != "" && req.Profile != own) {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"Forbidden","reason":"profile_not_allowed"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(api.Actor{Atespace: "dc-ops", Name: req.Name, Profile: own})
		},
	}}
	useFakeAdmin(t, f) // the login context saved profile eng
	s, err := substrateOpen(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Ctx.Profile != "eng" {
		t.Fatalf("fixture: the login context saves profile %q, want eng", s.Ctx.Profile)
	}
	got := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), sent...)
	}
	create := func(fl *substrateRunFlags) (api.Actor, string, error) {
		t.Helper()
		target, err := resolveSubstrateRunTarget(s, fl, "claude")
		if err != nil {
			t.Fatal(err)
		}
		cmd := &cobra.Command{}
		var errOut strings.Builder
		cmd.SetOut(new(strings.Builder))
		cmd.SetErr(&errOut)
		mu.Lock()
		sent = nil
		mu.Unlock()
		a, err := substrateCreate(t.Context(), cmd, s, target, fl, api.CreateRequest{Name: "j26pf"}, "")
		return a, errOut.String(), err
	}

	a, out, err := create(&substrateRunFlags{})
	if err != nil {
		t.Fatalf("run with no --profile after a login that saved another's profile: %v (sent %v)", err, got())
	}
	if ps := got(); a.Atespace != "dc-ops" || len(ps) != 2 || ps[0] != "eng" || ps[1] != "" {
		t.Fatalf("started in %q, profiles sent %v; want dc-ops after [eng, \"\"]", a.Atespace, ps)
	}
	for _, want := range []string{"default profile eng from login is not one you may use", "profile ops"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q lacks %q", out, want)
		}
	}

	// A profile the person named is theirs to fix: it is not replaced.
	if _, _, err := create(&substrateRunFlags{profile: "eng"}); err == nil || len(got()) != 1 || !strings.Contains(err.Error(), "you may not use that profile") {
		t.Fatalf("--profile eng: err %v, sent %v; want one refused create", err, got())
	}

	// Nobody's profile: the answer says so, not "leave --profile out".
	mu.Lock()
	assigned = ""
	mu.Unlock()
	_, _, err = create(&substrateRunFlags{})
	if err == nil || strings.Contains(err.Error(), "leave --profile out") || !strings.Contains(err.Error(), "no profile that runs agents is assigned to you") {
		t.Fatalf("no profile at all: %v", err)
	}
}
