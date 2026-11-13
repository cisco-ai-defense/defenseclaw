// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
)

// The first API bind notes a held port even when a retry wins, so a
// managed Windows gateway rotates its route epoch only then (P2-3).
func TestListenWithRetryNotesAHeldPort(t *testing.T) {
	prev := apiListenTCP
	t.Cleanup(func() { apiListenTCP = prev })
	failures := 0
	apiListenTCP = func(ctx context.Context, addr string) (net.Listener, error) {
		if failures > 0 {
			failures--
			return nil, &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE}
		}
		var lc net.ListenConfig
		return lc.Listen(ctx, "tcp", "127.0.0.1:0")
	}
	for _, tc := range []struct {
		failures int
		want     bool
	}{{0, false}, {1, true}} {
		failures = tc.failures
		held := false
		ln, err := listenWithRetryNotingHeld(context.Background(), "127.0.0.1:18970", 5*time.Second, &held)
		if err != nil {
			t.Fatal(err)
		}
		_ = ln.Close()
		if held != tc.want {
			t.Fatalf("%d failed attempts: held = %v, want %v", tc.failures, held, tc.want)
		}
	}
	a := &APIServer{addr: "127.0.0.1:18970", apiBindFoundHeld: true}
	failures = 0
	ln, err := a.acquireAPIListener(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	if a.apiBindFoundHeld {
		t.Fatal("a clean first bind must clear the held note of an earlier run")
	}
}
