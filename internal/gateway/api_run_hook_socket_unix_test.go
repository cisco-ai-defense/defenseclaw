//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
	"net/http"
	"os"
	osuser "os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// runHookSocketTestServer wires a standalone (or, with standalone=false, a
// managed Secure Client) APIServer whose TCP address is held by another
// listener, and starts Run.
func runHookSocketTestServer(t *testing.T, standalone bool, heldAddr string) (socket string, health *SidecarHealth, runErr <-chan error, cancel context.CancelFunc) {
	t.Helper()
	return runHookSocketTestServerAt(t, standalone, heldAddr, filepath.Join(shortGatewaySocketDir(t), "hook.sock"))
}

// runHookSocketTestServerAt is runHookSocketTestServer with the hook socket
// at socket, so two gateways can share one.
func runHookSocketTestServerAt(t *testing.T, standalone bool, heldAddr, socket string) (string, *SidecarHealth, <-chan error, context.CancelFunc) {
	t.Helper()
	dataDir := filepath.Join(filepath.Dir(socket), "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	current, err := osuser.Current()
	if err != nil {
		t.Fatal(err)
	}
	restoreDescriptor := loadStandaloneRuntimeDescriptor
	restoreHook := inheritedHookListener
	restoreAPI := inheritedAPIListener
	restoreBudget := apiListenRetryBudget
	restoreInterval := apiListenHeldRetryInterval
	t.Cleanup(func() {
		loadStandaloneRuntimeDescriptor = restoreDescriptor
		inheritedHookListener = restoreHook
		inheritedAPIListener = restoreAPI
		apiListenRetryBudget = restoreBudget
		apiListenHeldRetryInterval = restoreInterval
	})
	loadStandaloneRuntimeDescriptor = func(string) (*managed.RuntimeDescriptor, error) {
		return &managed.RuntimeDescriptor{
			SchemaVersion: managed.RuntimeDescriptorSchemaVersion,
			Profile:       managed.ProfileStandalone,
			ServiceUser:   current.Username,
			ServiceUID:    os.Getuid(),
			APIAddr:       managed.StandaloneAPIAddr,
			HookSocket:    socket,
		}, nil
	}
	inheritedHookListener = func() (net.Listener, bool, error) { return nil, false, nil }
	inheritedAPIListener = func() (net.Listener, bool, error) { return nil, false, nil }
	apiListenRetryBudget = 200 * time.Millisecond
	apiListenHeldRetryInterval = 50 * time.Millisecond

	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{DeploymentMode: "managed_enterprise", DataDir: dataDir}
	if standalone {
		cfg.Enterprise.Profile = managed.ProfileStandalone
	}
	cfg.Guardrail.Mode = "observe"
	health := NewSidecarHealth()
	api := NewAPIServer(heldAddr, health, nil, store, logger, cfg)
	api.SetConnectorRegistry(connector.NewDefaultRegistry())

	ctx, cancelRun := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- api.Run(ctx) }()
	t.Cleanup(cancelRun)
	return socket, health, errCh, cancelRun
}

func hookSocketRoundTrip(socket string) error {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
	}
	response, err := client.Get("http://127.0.0.1:18970/api/v1/inspect/tool")
	if err != nil {
		return err
	}
	return response.Body.Close()
}

// TestStandaloneHookSocketServesWhileTheAPIPortIsHeld: on a host without
// socket activation another process can hold the API port while the gateway
// restarts. The hook socket must come up and stay up anyway, the API must
// report the failed bind, and the gateway must take the port once it is
// released instead of returning (which exits the sidecar and takes the
// socket down for every user). A bind retry still pending when the gateway
// stops must not take the port afterwards.
func TestStandaloneHookSocketServesWhileTheAPIPortIsHeld(t *testing.T) {
	holder, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := holder.Addr().String()
	socket, health, runErr, cancel := runHookSocketTestServer(t, true, addr)

	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case err := <-runErr:
			_ = holder.Close()
			t.Fatalf("Run returned while only the TCP port was held: %v", err)
		default:
		}
		if hookSocketRoundTrip(socket) == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = holder.Close()
			t.Fatal("hook socket never served while the API port was held")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Past the first bind's retry budget, the socket still serves and the
	// API reports the held port.
	time.Sleep(3 * apiListenRetryBudget)
	if err := hookSocketRoundTrip(socket); err != nil {
		_ = holder.Close()
		t.Fatalf("hook socket stopped serving while the API port was held: %v", err)
	}
	if snap := health.Snapshot().API; snap.State != StateError || snap.Details["tcp_bind_retrying"] != true || snap.Details["hook_socket"] == nil {
		_ = holder.Close()
		t.Fatalf("API health while the port is held = %+v, want error with the hook socket and a retrying bind", snap)
	}

	_ = holder.Close()
	for health.Snapshot().API.State != StateRunning {
		if time.Now().After(deadline) {
			t.Fatalf("API never bound after the port was released: %+v", health.Snapshot().API)
		}
		time.Sleep(20 * time.Millisecond)
	}
	conn, err := net.DialTimeout("tcp4", addr, time.Second)
	if err != nil {
		t.Fatalf("API port not served after it was released: %v", err)
	}
	_ = conn.Close()
	if err := hookSocketRoundTrip(socket); err != nil {
		t.Fatalf("hook socket lost after the API bound: %v", err)
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run after cancel = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	// A bind retry still pending when the gateway stops must not take the
	// port afterwards.
	if holder, err = net.Listen("tcp4", addr); err != nil {
		t.Fatal(err)
	}
	socket, _, runErr, cancel = runHookSocketTestServer(t, true, addr)
	deadline = time.Now().Add(10 * time.Second)
	for hookSocketRoundTrip(socket) != nil {
		if time.Now().After(deadline) {
			_ = holder.Close()
			t.Fatal("hook socket never served while the API port was held")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-runErr:
	case <-time.After(10 * time.Second):
		_ = holder.Close()
		t.Fatal("Run did not return after cancel")
	}
	_ = holder.Close()
	time.Sleep(5 * apiListenHeldRetryInterval)
	again, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("the stopped gateway took the API port after shutdown: %v", err)
	}
	_ = again.Close()
}

// TestSecondStandaloneGatewayLeavesTheLiveHookSocketAlone: a second gateway
// under the same account must neither take over nor delete the hook socket
// a live gateway serves. With the API port held as well it gives up, the
// first gateway keeps serving the socket, and the path goes away only when
// the first gateway exits.
func TestSecondStandaloneGatewayLeavesTheLiveHookSocketAlone(t *testing.T) {
	free, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := free.Addr().String()
	_ = free.Close()
	socket := filepath.Join(shortGatewaySocketDir(t), "hook.sock")
	_, firstHealth, firstErr, cancelFirst := runHookSocketTestServerAt(t, true, addr, socket)
	deadline := time.Now().Add(10 * time.Second)
	for firstHealth.Snapshot().API.State != StateRunning || hookSocketRoundTrip(socket) != nil {
		select {
		case err := <-firstErr:
			t.Fatalf("first gateway returned: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("first gateway never served: %+v", firstHealth.Snapshot().API)
		}
		time.Sleep(20 * time.Millisecond)
	}

	_, _, secondErr, cancelSecond := runHookSocketTestServerAt(t, true, addr, socket)
	select {
	case err := <-secondErr:
		if err == nil {
			t.Fatal("second gateway returned nil while the first held the socket and the port")
		}
	case <-time.After(10 * time.Second):
		cancelSecond()
		t.Fatal("second gateway kept running while the first held the socket and the port")
	}
	cancelSecond()
	if err := hookSocketRoundTrip(socket); err != nil {
		t.Fatalf("the first gateway's hook socket stopped serving after the second gateway gave up: %v", err)
	}

	cancelFirst()
	select {
	case err := <-firstErr:
		if err != nil {
			t.Fatalf("first gateway after cancel = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first gateway did not return after cancel")
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatalf("the first gateway left its hook socket behind: %v", err)
	}
}
