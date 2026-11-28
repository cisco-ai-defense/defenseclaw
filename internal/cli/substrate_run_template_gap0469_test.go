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

// GAP-0469: after a login that saved the claude template, run codex sent
// that template and failed with a bare 400 connector_mismatch. The login's
// default template is the default for its own agent: another agent runs
// its own template, with a note; a template someone named still fails,
// with the fix.
func TestRunAnotherAgentAfterLoginUsesItsOwnTemplateGAP0469(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"POST actors": func(w http.ResponseWriter, r *http.Request) {
			var req api.CreateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			sent = append(sent, req.Template)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if req.Template != "codex" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"Bad Request","reason":"connector_mismatch"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(api.Actor{Atespace: "eng-web", Name: req.Name, Profile: req.Profile})
		},
	}}
	useFakeAdmin(t, f)
	s, err := substrateOpen(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Ctx.Template = "claude"
	target, err := resolveSubstrateRunTarget(s, &substrateRunFlags{}, "codex")
	if err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	var errOut strings.Builder
	cmd.SetOut(new(strings.Builder))
	cmd.SetErr(&errOut)
	if _, err := substrateCreate(t.Context(), cmd, s, target, &substrateRunFlags{}, api.CreateRequest{Name: "x"}, ""); err != nil {
		t.Fatalf("run codex after a claude login: %v", err)
	}
	if len(sent) != 2 || sent[0] != "claude" || sent[1] != "codex" || !strings.Contains(errOut.String(), "using codex") {
		t.Fatalf("templates sent %v, output %q", sent, errOut.String())
	}

	// A template the person named is not replaced.
	sent = nil
	named, err := resolveSubstrateRunTarget(s, &substrateRunFlags{template: "claude"}, "codex")
	if err != nil {
		t.Fatal(err)
	}
	_, err = substrateCreate(t.Context(), cmd, s, named, &substrateRunFlags{}, api.CreateRequest{Name: "y"}, "")
	if err == nil || !strings.Contains(err.Error(), "--template") || len(sent) != 1 {
		t.Fatalf("a named template: err %v, sent %v", err, sent)
	}
}
