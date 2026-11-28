// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// GAP-0930: substrate recover clears a running agent's relay certificate
// record from the CLI (the route answers not_crashed after clearing it),
// and brings a crashed one back.
func TestGAP0930RecoverClearsTheRelayCertRecord(t *testing.T) {
	running := map[string]any{"actors": []map[string]any{
		{"atespace": "eng-web", "name": "fix-tests-1", "uid": "u1", "profile": "eng", "connector": "claudecode",
			"created_at": time.Now().Add(-5 * time.Minute), "state": "running"},
	}}
	for _, c := range []struct {
		name, body, want string
	}{
		{"cleared", `{"error":"Conflict","reason":"not_crashed","relay_cert_record_cleared":true}`, "relay certificate record is cleared"},
		{"no record", `{"error":"Conflict","reason":"not_crashed","relay_cert_record_cleared":false}`, "nothing changed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
				"GET actors": jsonReply(running),
				"POST actors/eng-web/fix-tests-1/recover": func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(c.body))
				},
			}}
			useFakeAdmin(t, f)
			out, _, err := runSubstrate(t, newSubstrateRecoverCmd(), "fix-tests-1")
			if err != nil || !strings.Contains(out, c.want) {
				t.Fatalf("recover of a running agent: %v %q", err, out)
			}
		})
	}
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET actors": jsonReply(crashedActors()),
		"POST actors/eng-web/fix-tests-1/recover": jsonReply(map[string]any{"atespace": "eng-web", "name": "fix-tests-1", "state": "running"}),
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateRecoverCmd(), "fix-tests-1", "--yes")
	if err != nil || !strings.Contains(out, "back at its last snapshot") {
		t.Fatalf("recover of a crashed agent: %v %q", err, out)
	}
}
