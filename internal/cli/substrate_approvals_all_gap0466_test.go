// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/http"
	"strings"
	"testing"
)

// GAP-0466: an administrator could answer another person's ask by ID but
// not list it; approvals --all asks the gateway for every person's pending
// asks (all=1, admin only and audited there), and without --all it asks for
// the caller's own.
func TestApprovalsAllListsEveryonesAsksGAP0466(t *testing.T) {
	var queries []string
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET asks": func(w http.ResponseWriter, r *http.Request) {
			queries = append(queries, r.URL.RawQuery)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"asks":[{"id":"ask-a1","actor":"dc-eng/l4priv","summary":"GET https://example.com/","severity":"MEDIUM"}]}`))
		},
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateApprovalsCmd(), "--all")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ask-a1") {
		t.Errorf("approvals --all output %q", out)
	}
	if _, _, err := runSubstrate(t, newSubstrateApprovalsCmd()); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || queries[0] != "all=1" || queries[1] != "" {
		t.Fatalf("queries %q, want [all=1, \"\"]", queries)
	}
}
