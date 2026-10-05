// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// GAP-1967: readiness sends the gateway token only after the API port's
// listener is known to be the launched gateway, so another account's process
// that took the port after the start check never receives it.
func TestWaitForGatewayReadinessSendsTokenOnlyToLaunchedGatewayListener(t *testing.T) {
	const pid = 42
	cases := []struct {
		name      string
		holder    daemon.PortHolder
		holderErr error
		wantReady bool
		lookups   int
	}{
		{name: "another account", holder: daemon.PortHolder{PID: 7, UID: os.Getuid() + 1}, lookups: 1},
		{name: "another process", holder: daemon.PortHolder{PID: 7, UID: os.Getuid()}, lookups: 1},
		{name: "unlisted holder that answers", holder: daemon.PortHolder{UID: -1}, holderErr: daemon.ErrNoListener, lookups: 2},
		{name: "launched gateway", holder: daemon.PortHolder{PID: pid, UID: os.Getuid()}, wantReady: true, lookups: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tokenRequests atomic.Int32
			status := gatewayStatusEnvelope{Health: readinessSnapshot(gateway.StateDisabled, gateway.StateDisabled)}
			status.Runtime.PID = pid
			status.Runtime.DataDir = "/data"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" || r.Header.Get("X-DefenseClaw-Token") != "" {
					tokenRequests.Add(1)
				}
				_ = json.NewEncoder(w).Encode(status)
			}))
			defer srv.Close()
			lookups := 0
			requirements := daemonReadinessRequirements{
				expectedPID:     pid,
				expectedDataDir: "/data",
				token:           func() string { return strings.Repeat("t", 64) },
				tokenHost:       "127.0.0.1",
				listenerPort:    1,
				portHolder: func(string, int) (daemon.PortHolder, error) {
					lookups++
					return tc.holder, tc.holderErr
				},
				portAnswers: func(string) bool { return true },
			}
			_, ready, err := waitForGatewayReadiness(srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
				requirements, func() bool { return true })
			if ready != tc.wantReady || lookups != tc.lookups {
				t.Fatalf("ready = %v, lookups = %d (err %v); want %v, %d", ready, lookups, err, tc.wantReady, tc.lookups)
			}
			if tc.wantReady {
				if err != nil || tokenRequests.Load() == 0 {
					t.Fatalf("err = %v, token requests = %d; want the launched gateway checked", err, tokenRequests.Load())
				}
				return
			}
			if !errors.Is(err, errGatewayIdentityMismatch) || !strings.Contains(err.Error(), "token was not sent") {
				t.Fatalf("err = %v, want an identity mismatch that says the token was not sent", err)
			}
			if n := tokenRequests.Load(); n != 0 {
				t.Fatalf("token reached the foreign listener %d times", n)
			}
		})
	}
	if runtime.GOOS != "windows" {
		if daemonReadinessRequirementsFromConfig(&config.Config{}, time.Time{}).portHolder == nil {
			t.Fatal("start readiness does not check the listener before it sends the token")
		}
	}
}
