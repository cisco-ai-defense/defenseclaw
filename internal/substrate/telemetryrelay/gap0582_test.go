// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetryrelay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

func leaderCall(t *testing.T, srv *leader.Server, method, id string) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, leader.PathPrefix+method, strings.NewReader(`{"request_id":"`+id+`","body":{}}`))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s: %d %s", method, id, rec.Code, rec.Body.String()[:min(rec.Body.Len(), 200)])
	}
	return rec.Body.Bytes()
}

// GAP-0582: every take used a new request id and the leader kept its
// answer (up to 2,000 records) in the replay cache, so a few replicas
// taking every 3 s filled the cache's 64 MiB and pushed hook-call answers
// out before their 10-minute replay window. Take answers are no longer
// kept there; a retry of the same take still gets the same records.
func TestGAP0582TakeAnswersDoNotPushHookAnswersOutOfTheReplayCache(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	srv := &leader.Server{IsLeader: func() bool { return true }, Now: func() time.Time { return now }}
	s := &Store{}
	Serve(srv, s)
	var runs atomic.Int64
	srv.Handle("Hook", leader.Typed(func(context.Context, struct{}) (int64, error) { return runs.Add(1), nil }))

	leaderCall(t, srv, "Hook", "req-gap0582-hook")
	path := "/" + strings.Repeat("p", 20<<10)
	for i := 0; i < 3500; i++ {
		s.Add(Record{Kind: KindEgress, Host: "pypi.org", Path: path, Decision: "allow"})
	}
	first := leaderCall(t, srv, MethodTake, "req-gap0582-take-1")
	// A retry of the same take gets the same records, not the next batch.
	if again := leaderCall(t, srv, MethodTake, "req-gap0582-take-1"); string(again) != string(first) {
		t.Fatal("a retried take got other records")
	}
	for i := 2; i < 40; i++ {
		var resp leader.Response
		if err := json.Unmarshal(leaderCall(t, srv, MethodTake, fmt.Sprintf("req-gap0582-take-%d", i)), &resp); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}
	leaderCall(t, srv, "Hook", "req-gap0582-hook")
	if n := runs.Load(); n != 1 {
		t.Fatalf("a retried hook call ran again (%d runs): take answers pushed it out of the replay cache", n)
	}
}
