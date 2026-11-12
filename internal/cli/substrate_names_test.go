// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxcli"
)

var dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// The launcher never reuses an actor name (GAP-0133): Substrate's egress
// caches the actor token by name.
func TestSubstrateActorNamesAreNeverReused(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		n := uniqueSubstrateActorName("Fix the Tests!", "claude")
		if !dnsLabelRE.MatchString(n) || !strings.HasPrefix(n, "fix-the-tests-") {
			t.Fatalf("name %q", n)
		}
		if seen[n] {
			t.Fatalf("name %q was made twice", n)
		}
		seen[n] = true
	}
	for in, prefix := range map[string]string{"": "claude-", "   ": "claude-", "###": "claude-", strings.Repeat("a", 90): strings.Repeat("a", 40) + "-", "ünï": "n-"} {
		n := uniqueSubstrateActorName(in, "claude")
		if !strings.HasPrefix(n, prefix) || !dnsLabelRE.MatchString(n) || len(n) > 63 {
			t.Errorf("label %q gave %q", in, n)
		}
	}
	if n := uniqueSubstrateActorName("", ""); !strings.HasPrefix(n, "agent-") {
		t.Errorf("no label and no agent gave %q", n)
	}
}

// Two runs with the same --name create two different actors, and a failed
// run's clean-up does not free its name for the next one.
func TestSubstrateCreateNeverSendsTheSameNameTwice(t *testing.T) {
	var mu sync.Mutex
	var names []string
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"POST actors": func(w http.ResponseWriter, r *http.Request) {
			var req api.CreateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			names = append(names, req.Name)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(api.Actor{Atespace: "eng-web", Name: req.Name, Profile: req.Profile})
		},
	}}
	useFakeAdmin(t, f)
	spec, err := sandboxcli.ResolveHarness("claude")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := substrateOpen(nil, nil)
	target := substrateRunTarget{spec: spec, connName: spec.Name, profile: "eng", template: "claude"}
	cmd := &cobra.Command{}
	cmd.SetOut(new(strings.Builder))
	cmd.SetErr(new(strings.Builder))
	for i := 0; i < 5; i++ {
		if _, err := substrateCreate(t.Context(), cmd, s, target, &substrateRunFlags{}, api.CreateRequest{Name: "fix-tests"}, ""); err != nil {
			t.Fatal(err)
		}
	}
	uniq := map[string]bool{}
	for _, n := range names {
		if !strings.HasPrefix(n, "fix-tests-") {
			t.Errorf("the label is not the readable part of %q", n)
		}
		uniq[n] = true
	}
	if len(names) != 5 || len(uniq) != 5 {
		t.Fatalf("names sent: %v", names)
	}
}
