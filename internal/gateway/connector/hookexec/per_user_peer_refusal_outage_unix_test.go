// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
)

// A listener the connected-peer check refused is never a gateway outage,
// whatever the check's own error wraps (T12b loop 2). A foreign listener that
// closes or unbinds while its owner is read gives the check an ENOENT, EOF,
// reset or refused error; before errPerUserPeerUnverified those read as a
// restart, so hook-post exited 7 and a default per-user hook let the call
// through as an outage. The bearer and body never reach the listener.
func TestPerUserPeerRefusalIsNeverAnOutage(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	addr := server.Listener.Addr().String()
	previous := perUserConnectedPeer
	t.Cleanup(func() { perUserConnectedPeer = previous })
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"owner process gone", &os.PathError{Op: "open", Path: "/proc/4242/status", Err: syscall.ENOENT}},
		{"socket row gone", io.EOF},
		{"table cut off", io.ErrUnexpectedEOF},
		{"listener reset", fmt.Errorf("read: %w", syscall.ECONNRESET)},
		{"listener unbound", fmt.Errorf("probe: %w", syscall.ECONNREFUSED)},
		{"check at the restart deadline", fmt.Errorf("%w: owner check", errGatewayNotConnected)},
		{"foreign owner", errors.New("connected socket belongs to another account")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			perUserConnectedPeer = func(_, _ *net.TCPAddr) error { return tc.err }
			_, err := PostPerUserHook(context.Background(), addr, "/api/v1/claude-code/hook",
				map[string]string{"Authorization": "Bearer secret"}, []byte(`{"private":"event"}`))
			if err == nil || received.Load() != 0 {
				t.Fatalf("refused listener received %d posts; error = %v", received.Load(), err)
			}
			if !errors.Is(err, errPerUserPeerUnverified) {
				t.Fatalf("peer refusal is not marked unverified: %v", err)
			}
			// notConnectedError adds errGatewayNotConnected to a try that
			// ends at the restart deadline; the refusal still decides.
			for _, got := range []error{err, fmt.Errorf("%w: %w", errGatewayNotConnected, err)} {
				if PerUserPostOutage(got) {
					t.Errorf("hook-post would exit %d (outage) for a refused listener: %v", PerUserPostOutageExit, got)
				}
				if perUserOutageError(Options{}, got) {
					t.Errorf("native per-user hook reads a refused listener as an outage: %v", got)
				}
			}
		})
	}
	// The same-account gateway still answers through the same transport.
	perUserConnectedPeer = func(_, _ *net.TCPAddr) error { return nil }
	if _, err := PostPerUserHook(context.Background(), addr, "/api/v1/claude-code/hook",
		map[string]string{"Authorization": "Bearer secret"}, []byte(`{}`)); err != nil || received.Load() != 1 {
		t.Fatalf("same-account gateway received %d posts; error = %v", received.Load(), err)
	}
}
