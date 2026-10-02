// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package gateway

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A Windows standalone gateway whose API port another process holds
// keeps retrying the bind, reports the API as failed meanwhile, and binds
// the port once it is released, instead of ending the API after 30 s while
// the service stays Running.
func TestStandaloneHeldAPIPortKeepsRetryingWithoutAHookSocket(t *testing.T) {
	holder, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := holder.Addr().String()
	restoreAPI, restoreBudget, restoreInterval := inheritedAPIListener, apiListenRetryBudget, apiListenHeldRetryInterval
	t.Cleanup(func() {
		inheritedAPIListener, apiListenRetryBudget, apiListenHeldRetryInterval = restoreAPI, restoreBudget, restoreInterval
	})
	inheritedAPIListener = func() (net.Listener, bool, error) { return nil, false, nil }
	apiListenRetryBudget = 200 * time.Millisecond
	apiListenHeldRetryInterval = 50 * time.Millisecond

	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{DeploymentMode: "managed_enterprise", DataDir: t.TempDir()}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.Mode = "observe"
	if !cfg.StandaloneEnterprise() {
		t.Fatal("test config does not resolve the standalone profile")
	}
	health := NewSidecarHealth()
	api := NewAPIServer(addr, health, nil, store, logger, cfg)
	api.SetConnectorRegistry(connector.NewDefaultRegistry())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- api.Run(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for health.Snapshot().API.Details["tcp_bind_retrying"] != true {
		select {
		case err := <-runErr:
			t.Fatalf("Run returned with the API port held: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("API health never reported the retried bind: %+v", health.Snapshot().API)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if snap := health.Snapshot().API; snap.State != StateError {
		t.Fatalf("API health while the port is held = %+v, want error", snap)
	}
	select {
	case err := <-runErr:
		t.Fatalf("Run returned after the bind budget with the API port held: %v", err)
	case <-time.After(time.Second):
	}

	_ = holder.Close()
	deadline = time.Now().Add(10 * time.Second)
	for health.Snapshot().API.State != StateRunning {
		if time.Now().After(deadline) {
			t.Fatalf("the API never bound the released port: %+v", health.Snapshot().API)
		}
		time.Sleep(20 * time.Millisecond)
	}
	conn, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("the rebound API does not accept connections: %v", err)
	}
	_ = conn.Close()
	cancel()
	select {
	case <-runErr:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// When another account holds the API port on the wildcard address,
// Windows fails the gateway's 127.0.0.1 bind with WSAEACCES, not "address in
// use". A Windows standalone gateway keeps retrying that bind too, reports
// the API as failed meanwhile, and binds the port once it is released.
func TestStandaloneAPIPortHeldByAnotherAccountKeepsRetrying(t *testing.T) {
	restoreAPI, restoreBudget, restoreInterval, restoreListen := inheritedAPIListener, apiListenRetryBudget, apiListenHeldRetryInterval, apiListenTCP
	t.Cleanup(func() {
		inheritedAPIListener, apiListenRetryBudget, apiListenHeldRetryInterval, apiListenTCP = restoreAPI, restoreBudget, restoreInterval, restoreListen
	})
	inheritedAPIListener = func() (net.Listener, bool, error) { return nil, false, nil }
	apiListenRetryBudget = 200 * time.Millisecond
	apiListenHeldRetryInterval = 50 * time.Millisecond
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	var held atomic.Bool
	held.Store(true)
	apiListenTCP = func(ctx context.Context, bindAddr string) (net.Listener, error) {
		if held.Load() {
			return nil, &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.WSAEACCES)}
		}
		return restoreListen(ctx, bindAddr)
	}

	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{DeploymentMode: "managed_enterprise", DataDir: t.TempDir()}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.Mode = "observe"
	health := NewSidecarHealth()
	api := NewAPIServer(addr, health, nil, store, logger, cfg)
	api.SetConnectorRegistry(connector.NewDefaultRegistry())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- api.Run(ctx) }()

	deadline := time.Now().Add(10 * time.Second)
	for health.Snapshot().API.Details["tcp_bind_retrying"] != true {
		select {
		case err := <-runErr:
			t.Fatalf("Run returned while another account holds the API port: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("API health never reported the retried bind: %+v", health.Snapshot().API)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-runErr:
		t.Fatalf("Run returned while another account holds the API port: %v", err)
	case <-time.After(time.Second):
	}

	held.Store(false)
	deadline = time.Now().Add(10 * time.Second)
	for health.Snapshot().API.State != StateRunning {
		if time.Now().After(deadline) {
			t.Fatalf("the API never bound the released port: %+v", health.Snapshot().API)
		}
		time.Sleep(20 * time.Millisecond)
	}
	conn, err := net.DialTimeout("tcp4", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("the rebound API does not accept connections: %v", err)
	}
	_ = conn.Close()
	cancel()
	select {
	case <-runErr:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
