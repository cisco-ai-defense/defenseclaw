// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestIsAddrInUse confirms a genuine double-bind is classified as
// address-in-use so listenWithRetry knows to retry it, while an unrelated
// error is not.
func TestIsAddrInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	_, err = net.Listen("tcp", ln.Addr().String())
	if err == nil {
		t.Fatal("expected second bind on the same address to fail")
	}
	if !isAddrInUse(err) {
		t.Fatalf("isAddrInUse(%v) = false, want true for a double-bind", err)
	}

	if isAddrInUse(context.Canceled) {
		t.Fatal("isAddrInUse(context.Canceled) = true, want false")
	}
}

// TestListenWithRetryReclaimsPort mirrors the setup --restart window: the port
// is held when the new gateway starts binding, then released shortly after.
// listenWithRetry must keep retrying and succeed once the port frees, instead
// of failing the way a bare net.Listen would.
func TestListenWithRetryReclaimsPort(t *testing.T) {
	occupier, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := occupier.Addr().String()

	// Release the port mid-flight, like the prior gateway exiting during a
	// restart, after listenWithRetry has already started retrying.
	go func() {
		time.Sleep(300 * time.Millisecond)
		occupier.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	ln, err := listenWithRetry(ctx, addr, 5*time.Second)
	if err != nil {
		t.Fatalf("listenWithRetry: %v", err)
	}
	defer ln.Close()
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Fatalf("bound suspiciously fast (%s); expected to wait for the port to free", elapsed)
	}
}

// TestListenWithRetryHonorsBudget ensures we give up (rather than hang) when the
// address never frees, so a wedged predecessor can't block startup forever.
func TestListenWithRetryHonorsBudget(t *testing.T) {
	occupier, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer occupier.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := listenWithRetry(ctx, occupier.Addr().String(), 200*time.Millisecond)
	if err == nil {
		ln.Close()
		t.Fatal("expected listenWithRetry to fail when the port never frees")
	}
}

// TestListenWithRetryHonorsContext ensures cancellation aborts the retry loop
// promptly instead of burning the full budget.
func TestListenWithRetryHonorsContext(t *testing.T) {
	occupier, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer occupier.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	ln, err := listenWithRetry(ctx, occupier.Addr().String(), 10*time.Second)
	if err == nil {
		ln.Close()
		t.Fatal("expected listenWithRetry to fail on context cancellation")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("listenWithRetry ignored context cancellation (took %s)", elapsed)
	}
}

// TestHeldAPIPortFailsRunForSecureClient pins the Secure Client
// (managed_enterprise without the standalone profile) API bind on every
// platform: there is no hook socket, so a held API port still ends Run with
// an error after the bind budget and reports the API as failed.
func TestHeldAPIPortFailsRunForSecureClient(t *testing.T) {
	holder, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	restoreAPI := inheritedAPIListener
	restoreBudget := apiListenRetryBudget
	t.Cleanup(func() {
		inheritedAPIListener = restoreAPI
		apiListenRetryBudget = restoreBudget
	})
	inheritedAPIListener = func() (net.Listener, bool, error) { return nil, false, nil }
	apiListenRetryBudget = 200 * time.Millisecond
	// A runtime descriptor that names a hook socket does not make a Secure
	// Client gateway bind one.
	socket := filepath.Join(t.TempDir(), "hook.sock")
	restoreDescriptor := loadStandaloneRuntimeDescriptor
	t.Cleanup(func() { loadStandaloneRuntimeDescriptor = restoreDescriptor })
	loadStandaloneRuntimeDescriptor = func(string) (*managed.RuntimeDescriptor, error) {
		return &managed.RuntimeDescriptor{Profile: managed.ProfileStandalone, HookSocket: socket}, nil
	}

	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{DeploymentMode: "managed_enterprise", DataDir: t.TempDir()}
	cfg.Guardrail.Mode = "observe"
	health := NewSidecarHealth()
	api := NewAPIServer(holder.Addr().String(), health, nil, store, logger, cfg)
	api.SetConnectorRegistry(connector.NewDefaultRegistry())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- api.Run(ctx) }()
	select {
	case err := <-runErr:
		if err == nil || !isAddrInUse(err) {
			t.Fatalf("Run with the API port held = %v, want an address-in-use error", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run kept running with the API port held outside the standalone profile")
	}
	if snap := health.Snapshot().API; snap.State != StateError || snap.Details["hook_socket"] != nil {
		t.Fatalf("API health = %+v, want error without a hook socket", snap)
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatalf("a hook socket was created outside the standalone profile: %v", err)
	}
}
