// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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
		if _, err := watchdogPeerClient(nil, call.target, call.timeout); err == nil {
			t.Errorf("watchdog accepted unverified target %s", call.target)
		}
	}
	if called != 2 {
		t.Fatalf("watchdog skipped connected peer proof on %d of 2 calls", 2-called)
	}
}

func TestWatchdogRecoveryRecorderRefusesAnUnverifiedGateway(t *testing.T) {
	previous := perUserGatewayClientFactory
	t.Cleanup(func() { perUserGatewayClientFactory = previous })
	called := false
	perUserGatewayClientFactory = func(time.Duration, string) (*http.Client, error) {
		called = true
		return nil, errors.New("connected gateway peer belongs to another account")
	}
	recorder, err := newWatchdogAPIRecoveryRecorder(nil, "http://127.0.0.1:18970/api/v1/watchdog/recovery", "private-token")
	if !called || recorder != nil || err == nil {
		t.Fatalf("unverified recovery target was accepted: called=%t recorder=%v error=%v", called, recorder, err)
	}
}

func TestWatchdogManagedServiceKeepsItsManagedTransport(t *testing.T) {
	previous := perUserGatewayClientFactory
	t.Cleanup(func() { perUserGatewayClientFactory = previous })
	perUserGatewayClientFactory = func(time.Duration, string) (*http.Client, error) {
		t.Fatal("managed watchdog selected the per-user peer transport")
		return nil, errors.New("unexpected per-user transport")
	}
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	for _, target := range []string{
		"http://127.0.0.1:18970/health",
		"http://127.0.0.1:18970/api/v1/watchdog/recovery",
	} {
		if client, err := watchdogPeerClient(cfg, target, watchdogProbeTimeout); err != nil || client == nil {
			t.Fatalf("managed watchdog transport for %s: client=%v error=%v", target, client, err)
		}
	}
}

func TestWatchdogManagedLoopPollsThroughItsManagedTransport(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	previous := perUserGatewayClientFactory
	t.Cleanup(func() { perUserGatewayClientFactory = previous })
	perUserGatewayClientFactory = func(time.Duration, string) (*http.Client, error) {
		t.Fatal("managed watchdog loop selected the per-user peer transport")
		return nil, errors.New("unexpected per-user transport")
	}
	requests := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case requests <- struct{}{}:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWatchdogLoop(ctx, server.URL+"/health", 5*time.Millisecond, 100,
			watchdogHealthRequirements{transportConfig: cfg}, nil, nil)
	}()
	select {
	case <-requests:
		cancel()
	case <-ctx.Done():
		t.Fatal("managed watchdog did not poll its gateway")
	}
	<-done
}
