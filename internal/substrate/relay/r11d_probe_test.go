// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// R11 delta probes on 96109ceaab (relay).

package relay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// The agent itself is silent (a hung model call), but a tool it left running
// in the background stays busy: is the task still ended?
func TestR11DBusyBackgroundToolKeepsHungAgentAlive(t *testing.T) {
	script := `setsid sh -c 'end=$(($(date +%s)+20)); while [ $(date +%s) -lt $end ]; do :; done' & exec sleep 12`
	var log eventLog
	start := time.Now()
	end := runWithin(t, 40*time.Second, func() TaskEnd {
		return RunHeadless(context.Background(), shConfig(script), TaskRequest{Prompt: "p"},
			HeadlessOptions{Stall: 3 * time.Second, Tick: 500 * time.Millisecond}, log.emit)
	})
	t.Logf("R11D busy background tool, silent agent, stall 3s: %+v after %s", end, time.Since(start))
	if !end.Stalled {
		t.Logf("R11D NOTE: a busy background tool keeps a silent agent alive past the stall bound (it ran to its own end)")
	}
}

// The actor listener answers 429 when the actor is over its request budget
// (the agent shares the token): is the relay's real end retried?
func TestR11DReportIsRetriedAfter429(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = ReportTaskEnd(ctx, GatewayReport(tr), TaskEnd{ExitCode: ExitStalled, Stalled: true, Cause: "real"})
	t.Logf("R11D report after one 429: calls %d err %v", calls.Load(), err)
	if err != nil {
		t.Errorf("R11D FINDING: a 429 from the actor listener is final for the task-end report: the relay's real end is dropped (calls %d, err %v)", calls.Load(), err)
	}
}
