// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

// The watchdog polls without a token, then posts a bearer on recovery. Both
// calls must be bound to the connected per-user socket, even after the
// gateway stops and another account takes its port.
func TestWatchdogUsesTheConnectedGatewayPeerTransport(t *testing.T) {
	previous := perUserGatewayClientFactory
	t.Cleanup(func() { perUserGatewayClientFactory = previous })
	called := 0
	perUserGatewayClientFactory = func(time.Duration, string) (*http.Client, error) {
		called++
		return nil, errors.New("connected gateway peer belongs to another account")
	}
	for _, call := range []struct {
		target  string
		timeout time.Duration
	}{
		{"http://127.0.0.1:18970/health", watchdogProbeTimeout},
		{"http://127.0.0.1:18970/api/v1/watchdog/recovery", 5 * time.Second},
	} {
		if _, err := watchdogPeerClient(call.target, call.timeout); err == nil {
			t.Errorf("watchdog accepted unverified target %s", call.target)
		}
	}
	if called != 2 {
		t.Fatalf("watchdog skipped connected peer proof on %d of 2 calls", 2-called)
	}
}
