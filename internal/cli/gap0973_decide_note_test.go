// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/http"
	"strings"
	"testing"
)

// GAP-0973: when the cluster answers that no binding names the ask, approve
// prints the cluster message under "Approved ID." so the answer is not read
// as a secret gone live; a plain answer prints the one line only.
func TestSubstrateApprovePrintsTheBindingGoneNote(t *testing.T) {
	note := "No binding names this ask now. If it was removed, nothing changed."
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"POST asks/gone":  jsonReply(map[string]any{"id": "gone", "state": "approved", "binding_gone": true, "message": note}),
		"POST asks/plain": jsonReply(map[string]any{"id": "plain", "state": "approved"}),
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateApproveCmd(), "gone")
	if err != nil || !strings.Contains(out, "Approved gone.") || !strings.Contains(out, note) {
		t.Fatalf("approve of a gone binding = %q, %v; want the note", out, err)
	}
	out, _, err = runSubstrate(t, newSubstrateApproveCmd(), "plain")
	if err != nil || strings.TrimSpace(out) != "Approved plain." {
		t.Fatalf("plain approve = %q, %v; want only the Approved line", out, err)
	}
}
