// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A try with a connect deadline reads the owner of a connection that sat in
// the accept queue shortly before the deadline. A slow read (the record
// lookup of a busy host) is not cut by the deadline: the own frozen gateway
// of the account stays an outage and is not blamed on another process.
func TestSlowOwnerReadOfTheOwnFrozenGatewayStaysAnOutage(t *testing.T) {
	addr := frozenListener(t)
	dataDir := recordGateway(t, os.Getpid(), nil)
	for _, tc := range []struct {
		name       string
		lookup     time.Duration
		firstRead  bool // the first read of the record finds nothing
		wantOutage bool
	}{
		{"prompt lookup", 0, false, true},
		{"first read finds no record", 0, true, true},
		{"lookup past the connect deadline", 1200 * time.Millisecond, false, true},
		{"lookup that outlasts the grace", ownerScanGrace + 600*time.Millisecond, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads atomic.Int32
			homes := func() []string {
				time.Sleep(tc.lookup)
				if tc.firstRead && reads.Add(1) == 1 {
					return nil
				}
				return []string{dataDir}
			}
			tryCtx, release := connectBy(withPerUserGatewayHomes(context.Background(), homes), time.Now().Add(perUserConnectedWait), nil)
			defer release()
			_, err := PostPerUserHook(tryCtx, addr, "/api/v1/claude-code/hook", nil, []byte("{}"))
			if err == nil {
				t.Fatal("a frozen listener answered")
			}
			if got := PerUserPostListenerUnanswered(err); got != tc.wantOutage {
				t.Fatalf("unanswered own listener = %v, want %v: %v", got, tc.wantOutage, err)
			}
			if !tc.wantOutage && !PerUserPostPeerUnverified(err) {
				t.Fatalf("a scan the grace did not hold was not refused as unverified: %v", err)
			}
		})
	}
}

// A gateway that accepts the queued connection before the connect budget ends
// answers the call: the owner of the queue is not decided early, so its own
// answer (here a policy block) is the one the hook gets.
func TestGatewayAcceptingBeforeTheConnectBudgetEndsKeepsItsAnswer(t *testing.T) {
	for _, accept := range []time.Duration{500 * time.Millisecond, 2200 * time.Millisecond, 2450 * time.Millisecond} {
		t.Run(accept.String(), func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			go func() {
				time.Sleep(accept)
				_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"action":"block","raw_action":"block"}`))
				}))
			}()
			dataDir := recordGateway(t, os.Getpid(), nil)
			tryCtx, release := connectBy(WithPerUserGatewayDataDir(context.Background(), dataDir), time.Now().Add(perUserConnectedWait), nil)
			defer release()
			reply, err := PostPerUserHook(tryCtx, listener.Addr().String(), "/api/v1/claude-code/hook", nil, []byte("{}"))
			if err != nil {
				t.Fatalf("a gateway that accepted after %s was treated as an outage: %v", accept, err)
			}
			if reply.Status != http.StatusOK || !strings.Contains(reply.Body, `"block"`) {
				t.Fatalf("the gateway answer was not kept: status=%d body=%q", reply.Status, reply.Body)
			}
		})
	}
}
