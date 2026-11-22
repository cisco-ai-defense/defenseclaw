// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

// GAP-0492: an approval given with approve --always was listed nowhere
// (approvals --json printed {"asks": []}) and could not be taken back.
// approvals --standing lists it (agent, host, what it covers, who approved
// it and when; --all for an administrator), and revoke NAME HOST takes it
// back. Before the fix approvals had no --standing flag and there was no
// revoke command.
func TestApprovalsStandingAndRevokeGAP0492(t *testing.T) {
	var queries, revoked []string
	gone := false
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET actors": jsonReply(sampleActors()),
		"GET approvals": func(w http.ResponseWriter, r *http.Request) {
			queries = append(queries, r.URL.RawQuery)
			list := []map[string]any{{"atespace": "eng-web", "actor": "fix-tests-1", "host": "registry.example.test", "scope": "host",
				"approved_by": "you", "approved_at": time.Now().Add(-2 * time.Hour), "ask_id": "ask-a1"}}
			if gone {
				list = nil
			}
			jsonReply(map[string]any{"approvals": list})(w, r)
		},
		"DELETE approvals/eng-web/fix-tests-1/registry.example.test": func(w http.ResponseWriter, r *http.Request) {
			revoked = append(revoked, r.URL.Path)
			if gone {
				jsonStatus(http.StatusNotFound, "approval_not_found")(w, r)
				return
			}
			gone = true
			jsonReply(map[string]any{"state": "revoked", "asks": 1, "registration": true})(w, r)
		},
	}}
	useFakeAdmin(t, f)

	out, _, err := runSubstrate(t, newSubstrateApprovalsCmd(), "--standing")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"eng-web/fix-tests-1", "registry.example.test", "every request to the host", "you", "2h", "substrate revoke NAME HOST"} {
		if !strings.Contains(out, want) {
			t.Errorf("approvals --standing output lacks %q:\n%s", want, out)
		}
	}
	out, _, err = runSubstrate(t, newSubstrateApprovalsCmd(), "--standing", "--all", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Approvals []map[string]any `json:"approvals"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil || len(doc.Approvals) != 1 || doc.Approvals[0]["host"] != "registry.example.test" {
		t.Fatalf("approvals --standing --json: %s", out)
	}
	if len(queries) != 2 || queries[0] != "" || queries[1] != "all=1" {
		t.Fatalf("queries %q, want [\"\", all=1]", queries)
	}

	// revoke resolves the name the person gave, like every other command.
	out, _, err = runSubstrate(t, newSubstrateRevokeCmd(), "fix-tests-1", "Registry.Example.Test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Took back the approval of registry.example.test for eng-web/fix-tests-1") {
		t.Errorf("revoke output %q", out)
	}
	if out, _, _ = runSubstrate(t, newSubstrateApprovalsCmd(), "--standing"); !strings.Contains(out, "No approval given with --always is in force.") {
		t.Errorf("approvals --standing after the revoke: %q", out)
	}
	// Nothing left to take back: a refusal (exit 3) that says where to look.
	_, _, err = runSubstrate(t, newSubstrateRevokeCmd(), "eng-web/fix-tests-1", "registry.example.test")
	if err == nil || cliusage.ExitCode(err) != substrateExitRefused || !strings.Contains(err.Error(), "approvals --standing") {
		t.Fatalf("second revoke: %v (exit %d)", err, cliusage.ExitCode(err))
	}
	if len(revoked) != 2 {
		t.Fatalf("revoke calls %v", revoked)
	}
}
