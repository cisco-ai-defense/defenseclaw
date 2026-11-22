// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0301: a 429 (the actor's request budget, which the agent shares) is
// retried, honoring Retry-After; a pool that keeps refusing stays bounded.
func TestReportRetriesTooManyRequests(t *testing.T) {
	if got := retryAfter("3"); got != 3*time.Second {
		t.Fatalf("Retry-After 3: %s", got)
	}
	for _, v := range []string{"", "x", "-1", "Wed, 21 Oct 2026 07:28:00 GMT"} {
		if retryAfter(v) != 0 {
			t.Fatalf("Retry-After %q is not 0", v)
		}
	}
	var calls atomic.Int32
	var gap atomic.Int64
	last := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 2 {
			gap.Store(int64(time.Since(last)))
		}
		last = time.Now()
		if n == 1 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	cfg := kit.DefaultConfig()
	cfg.GatewayURL = srv.URL
	cfg.MaxTimeMS, cfg.RetryMaxTimeMS = 2000, 2000
	tr, err := kit.NewTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := ReportTaskEnd(context.Background(), GatewayReport(tr), TaskEnd{ExitCode: 1}); err != nil || calls.Load() != 2 {
		t.Fatalf("err %v calls %d", err, calls.Load())
	}
	if time.Duration(gap.Load()) < 3*time.Second {
		t.Fatalf("retried after %s, before the Retry-After of 3s", time.Duration(gap.Load()))
	}
	// Always 429: the report gives up when its context ends, not before.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }))
	defer srv2.Close()
	cfg.GatewayURL = srv2.URL
	tr2, _ := kit.NewTransport(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = ReportTaskEnd(ctx, GatewayReport(tr2), TaskEnd{})
	var later *reportLater
	if !errors.As(err, &later) || later.status != http.StatusTooManyRequests {
		t.Fatalf("a pool that keeps refusing: %v", err)
	}
}
