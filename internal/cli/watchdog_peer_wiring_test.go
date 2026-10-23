// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchdogHealthLoopDoesNotPollAnUnverifiedGateway(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	var received atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"gateway":{"status":"healthy"}}`))
	}))
	defer peer.Close()
	previous := perUserGatewayClientFactory
	t.Cleanup(func() { perUserGatewayClientFactory = previous })
	perUserGatewayClientFactory = func(time.Duration, string) (*http.Client, error) {
		return nil, errors.New("connected gateway peer belongs to another account")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	runWatchdogLoop(ctx, peer.URL+"/health", 10*time.Millisecond, 100,
		watchdogHealthRequirements{}, nil, nil)
	if received.Load() != 0 {
		t.Fatalf("watchdog sent %d health requests to an unverified account", received.Load())
	}
}
