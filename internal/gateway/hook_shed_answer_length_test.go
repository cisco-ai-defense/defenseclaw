// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// GAP-1065: a hook reads the whole 429 before it sends the call again. A
// shed answer without a length ends only when the handler returns, which is
// after the shed call audit row is written, so under a flood every retry
// waited for a SQLite write. The refusal now carries its length and is
// complete when it is flushed; the row is still written.
func TestShedAnswerCarriesItsLengthAndTheRowIsStillWritten(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	f.api.hookCallerLimits = hookCallerLimiter{rate: 1, burst: 1}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	guarded := f.api.managedHookPeerAuth(machinePolicyAuthorizer(), next)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guarded.ServeHTTP(w, r.WithContext(withManagedHookPeer(r.Context(), managedHookPeer{UID: 1004, Name: "shed-alice"})))
	}))
	t.Cleanup(server.Close)
	post := func(session string) (*http.Response, []byte) {
		t.Helper()
		resp, err := http.Post(server.URL+goneHookPath, "application/json", strings.NewReader(managedHookBody(session, "PreToolUse")))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp, data
	}
	// Benign twin: the admitted call is served as before.
	if resp, _ := post("shed-len-warm"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the first call was refused: %d", resp.StatusCode)
	}
	resp, data := post("shed-len-a")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d, want the 429", resp.StatusCode)
	}
	if resp.ContentLength != int64(len(data)) || len(resp.TransferEncoding) != 0 {
		t.Fatalf("429 content length %d, transfer encoding %v, body %d bytes: the answer must carry its length",
			resp.ContentLength, resp.TransferEncoding, len(data))
	}
	var refusal map[string]string
	if err := json.Unmarshal(data, &refusal); err != nil || refusal["error"] != "rate_limited" || refusal["reason"] != managedHookReasonRateLimited || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("429 body %q (%v), Retry-After %q", data, err, resp.Header.Get("Retry-After"))
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(shedRows(t, f, "shed-len-a")) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if rows := shedRows(t, f, "shed-len-a"); len(rows) != 1 || !strings.Contains(rows[0].Details, "hook_shed") {
		t.Fatalf("shed rows = %v, want the one hook_shed row", rows)
	}
}
