// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetryrelay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// substrate-1:GAP-0606 (review 3). A batch the leader refused with
// bad_request was dropped with a log line only. The poster now counts the
// dropped records (Dropped, also in Run's log line).
func TestGAP0606RefusedBatchesAreCounted(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = w.Write([]byte(`{"error":{"code":"bad_request","message":"body too large"}}`))
	}))
	t.Cleanup(hs.Close)
	p := &Poster{Leader: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: 200 * time.Millisecond}, Method: MethodPostEgress}
	p.Add(Record{Kind: KindEgress, Host: "a"}, Record{Kind: KindEgress, Host: "b"})
	_ = p.Flush(context.Background())
	p.Add(Record{Kind: KindEgress, Host: "c"})
	_ = p.Flush(context.Background())
	if got := p.Dropped(); got != 3 {
		t.Fatalf("Dropped() = %d, want 3", got)
	}
}
