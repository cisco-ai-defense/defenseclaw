// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func fastManagedPeerRetries(t *testing.T) {
	t.Helper()
	old := managedEnterprisePeerRetryDelay
	managedEnterprisePeerRetryDelay = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() {
		managedTransportTestMu.Lock()
		defer managedTransportTestMu.Unlock()
		managedEnterprisePeerRetryDelay = old
	})
}

// A connection whose row has not reached the owner-PID table yet is retried
// within the hook's deadline and then verified.
func TestManagedEnterpriseTransportRetriesUnconfirmedOwnerThenConnects(t *testing.T) {
	managedTransportTestMu.Lock()
	defer managedTransportTestMu.Unlock()
	fastManagedPeerRetries(t)

	listener := listenManagedTransportTest(t)
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				buffer := make([]byte, 4096)
				if n, _ := conn.Read(buffer); n == 0 {
					return
				}
				_, _ = io.WriteString(conn,
					"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"action\":\"allow\"}")
			}(conn)
		}
	}()
	lookups := 0
	restoreManagedTransportSeams(t,
		func(string) (uint32, error) { return 505, nil },
		func(net.Conn) (uint32, error) {
			lookups++
			if lookups < 3 {
				return 0, errors.New("no ESTABLISHED reverse tuple")
			}
			return 505, nil
		},
	)
	client, err := managedEnterpriseHTTPClient(2*time.Second, listener.Addr().String(), "DefenseClawGateway")
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Post("http://"+listener.Addr().String()+"/api/v1/hook", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("retried verification failed: %v", err)
	}
	_ = response.Body.Close()
	if lookups != 3 {
		t.Fatalf("owner lookups = %d, want 3", lookups)
	}
}

// An owner that stays unconfirmed (an unreadable table, a zero owner, a
// service PID that keeps moving) follows the fail mode after the retries,
// and nothing is written to the port.
func TestManagedEnterpriseTransportUnconfirmedOwnerFollowsFailMode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		connected func(lastQueried uint32) (uint32, error)
		moving    bool
	}{
		{
			name: "owner table unreadable",
			connected: func(uint32) (uint32, error) {
				return 0, errors.New("read IPv4 owner-PID table: busy")
			},
		},
		{
			name:      "owner PID zero",
			connected: func(uint32) (uint32, error) { return 0, nil },
		},
		{
			// The connection belongs to the PID the first query of each
			// attempt returned; the re-query already sees the next one.
			name:      "service PID keeps moving",
			connected: func(lastQueried uint32) (uint32, error) { return lastQueried, nil },
			moving:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			managedTransportTestMu.Lock()
			defer managedTransportTestMu.Unlock()
			fastManagedPeerRetries(t)
			listener := listenManagedTransportTest(t)
			defer listener.Close()
			bytesRead := acceptManagedTransportBytes(t, listener)
			lastQueried := uint32(700)
			restoreManagedTransportSeams(t,
				func(string) (uint32, error) {
					if tc.moving {
						lastQueried++
					}
					return lastQueried, nil
				},
				func(net.Conn) (uint32, error) { return tc.connected(lastQueried) },
			)

			client, err := managedEnterpriseHTTPClient(time.Second, listener.Addr().String(), "DefenseClawGateway")
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Post("http://"+listener.Addr().String()+"/api/v1/hook", "application/json",
				strings.NewReader(`{"secret":"must-not-leak"}`))
			if !errors.Is(err, errManagedGatewayPeerUnverified) || !errors.Is(err, errManagedGatewayPeerUnconfirmed) {
				t.Fatalf("unconfirmed owner error = %v", err)
			}
			if got := managedPeerFailureReason(err); got != managedGatewayPeerUnconfirmedReason {
				t.Fatalf("reason = %q", got)
			}
			for _, failMode := range []string{"open", "closed"} {
				if got := managedPeerFailMode(failMode, err); got != failMode {
					t.Fatalf("fail mode %q became %q", failMode, got)
				}
			}
			if got := <-bytesRead; len(got) != 0 {
				t.Fatalf("unconfirmed listener received %d request bytes: %q", len(got), got)
			}
		})
	}
}

// A positively identified foreign owner is not retried away: it stays closed.
func TestManagedEnterpriseTransportForeignOwnerIsNotRetried(t *testing.T) {
	managedTransportTestMu.Lock()
	defer managedTransportTestMu.Unlock()
	fastManagedPeerRetries(t)
	listener := listenManagedTransportTest(t)
	defer listener.Close()
	lookups := 0
	restoreManagedTransportSeams(t,
		func(string) (uint32, error) { return 101, nil },
		func(net.Conn) (uint32, error) {
			lookups++
			return 202, nil
		},
	)
	client, err := managedEnterpriseHTTPClient(time.Second, listener.Addr().String(), "DefenseClawGateway")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Post("http://"+listener.Addr().String()+"/api/v1/hook", "application/json", strings.NewReader(`{}`))
	if !errors.Is(err, errManagedGatewayPortHeld) || managedPeerFailMode("open", err) != "closed" {
		t.Fatalf("foreign owner error = %v", err)
	}
	if lookups != 1 {
		t.Fatalf("foreign owner looked up %d times, want 1", lookups)
	}
}

// A transport the authenticated runtime's endpoint cannot build sends nothing
// and follows the fail mode, with a durable record.
func TestManagedEnterpriseRunEndpointBuildFailureFollowsFailMode(t *testing.T) {
	for _, tc := range []struct {
		failMode string
		wantCode int
	}{
		{failMode: "open", wantCode: 0},
		{failMode: "closed", wantCode: blockExit},
	} {
		t.Run(tc.failMode, func(t *testing.T) {
			records := captureManagedHookDecisions(t)
			home := t.TempDir()
			token := "authenticated-token"
			var out, errb bytes.Buffer
			code := Run(context.Background(), Options{
				Connector:                 "codex",
				APIAddr:                   "127.0.0.1:18970",
				Home:                      home,
				HookDir:                   filepath.Join(home, "hooks"),
				FailMode:                  tc.failMode,
				ManagedEnterprise:         true,
				ManagedGatewayServiceName: `bad\name`,
				AuthenticatedManagedToken: &token,
				Stdin:                     strings.NewReader(`{}`),
				Stdout:                    &out,
				Stderr:                    &errb,
			})
			if code != tc.wantCode {
				t.Fatalf("code = %d, want %d; stderr=%q", code, tc.wantCode, errb.String())
			}
			requireOneManagedRecord(t, *records, managed.MarkerDegraded,
				`reason="`+managedGatewayEndpointInvalidReason+`"`)
			if (*records)[0].source != managedHookDecisionRecordDefaultSource {
				t.Fatalf("invalid service name selected event source %q", (*records)[0].source)
			}
		})
	}
}

func TestManagedHookDecisionRecordSourceUsesProtectedServiceName(t *testing.T) {
	if got := managedHookDecisionRecordSource("DefenseClawGatewayCert"); got != "DefenseClawGatewayCert" {
		t.Fatalf("source = %q", got)
	}
	for _, invalid := range []string{"", " padded", `a\b`, "a/b"} {
		if got := managedHookDecisionRecordSource(invalid); got != managedHookDecisionRecordDefaultSource {
			t.Fatalf("source(%q) = %q", invalid, got)
		}
	}
}
