// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestListenWithRetryCallsOnHeldOnce(t *testing.T) {
	prev := apiListenTCP
	t.Cleanup(func() { apiListenTCP = prev })
	failures := 3
	apiListenTCP = func(ctx context.Context, addr string) (net.Listener, error) {
		if failures > 0 {
			failures--
			return nil, &net.OpError{Op: "listen", Net: "tcp", Err: syscall.EADDRINUSE}
		}
		var lc net.ListenConfig
		return lc.Listen(ctx, "tcp", "127.0.0.1:0")
	}
	held, calls := false, 0
	ln, err := listenWithRetryNotingHeld(context.Background(), "127.0.0.1:18970", 5*time.Second, &held, func() { calls++ })
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	if !held || calls != 1 {
		t.Fatalf("held=%v calls=%d: the holder is looked up once per bind", held, calls)
	}
}

// After another account held the port, the OSS gateway replaces its route
// key before serving: the old credential is refused at once, the staged key
// is dropped, the agent configs are rendered again, and the mark is gone.
func TestRotateRouteKeyAfterHeldPort(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir}
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly.Connectors = []string{"claudecode"}
	store := newRouteTokenStore(dir, "1000")
	old, err := store.Token("claudecode")
	if err != nil || !store.Valid("claudecode", old) {
		t.Fatalf("old token: %v", err)
	}
	hooks := filepath.Join(dir, "hooks")
	if err := safefile.WritePrivate(filepath.Join(hooks, routeTokenNextKeyName), []byte(strings.Repeat("cd", 32)+"\n")); err != nil {
		t.Fatal(err)
	}
	a := &APIServer{addr: "127.0.0.1:18970", scannerCfg: cfg}
	a.routeOnly.Store(&routeOnlyServer{tokens: store})
	renders := 0
	a.onRouteKeyRotated = func() { renders++ }

	a.rotateRouteKeyAfterHeldPort()
	if renders != 0 {
		t.Fatal("no mark, no rotation")
	}
	if err := safefile.WritePrivate(filepath.Join(hooks, routePortHeldName), []byte(`{"uid":4242,"addr":"127.0.0.1:18970"}`)); err != nil {
		t.Fatal(err)
	}
	a.rotateRouteKeyAfterHeldPort()
	if renders != 1 {
		t.Fatalf("renders=%d", renders)
	}
	if store.Valid("claudecode", old) {
		t.Fatal("the replaced credential is refused at once (no pending window)")
	}
	if fresh, err := store.Token("claudecode"); err != nil || fresh == old || !store.Valid("claudecode", fresh) {
		t.Fatalf("new credential: %v", err)
	}
	for _, name := range []string{routeTokenNextKeyName, routePortHeldName} {
		if _, err := os.Stat(filepath.Join(hooks, name)); !os.IsNotExist(err) {
			t.Fatalf("%s left behind: %v", name, err)
		}
	}
	a.rotateRouteKeyAfterHeldPort()
	if renders != 1 {
		t.Fatal("one rotation per held port")
	}

	// Managed hosts rotate through the route epoch and per-user keys.
	cfg.DeploymentMode, cfg.Enterprise.Profile = "managed_enterprise", "standalone"
	if err := safefile.WritePrivate(filepath.Join(hooks, routePortHeldName), []byte(`{"uid":4242}`)); err != nil {
		t.Fatal(err)
	}
	a.rotateRouteKeyAfterHeldPort()
	if _, err := os.Stat(filepath.Join(hooks, routePortHeldName)); err != nil || renders != 1 {
		t.Fatalf("managed: %v renders=%d", err, renders)
	}
}
