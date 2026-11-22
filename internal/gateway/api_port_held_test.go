// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
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

func TestListenWithRetryCallsOnHeldAtEveryConflict(t *testing.T) {
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
	ln, err := listenWithRetryNotingHeld(context.Background(), "127.0.0.1:18970", 5*time.Second, &held, func(err error) {
		if errors.Is(err, syscall.EADDRINUSE) {
			calls++
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	if !held || calls != 3 {
		t.Fatalf("held=%v calls=%d: the holder is looked up at every conflict (it can change between attempts)", held, calls)
	}
}

func useAPIPortHolder(t *testing.T, info apiPortHolderInfo) {
	t.Helper()
	prev := apiPortHolderLookup
	apiPortHolderLookup = func(string) (apiPortHolderInfo, error) { return info, nil }
	t.Cleanup(func() { apiPortHolderLookup = prev })
}

// OSS Windows: the listener table names another account (its SID when the
// token is readable) for a same-address or a wildcard listener alike. The
// mark is written with the SID, audited, and the route key is replaced
// once the gateway owns the port (S1 DESIGN 16.2, REVIEW-code-delta-d962
// P2-1).
func TestNoteAPIPortHolderMarksAnotherAccountListener(t *testing.T) {
	errForeign := errors.New("bind: only one usage of each socket address")
	useAPIPortHolder(t, apiPortHolderInfo{Found: true, Other: true, SID: "S-1-5-21-1-2-3-1001"})
	store, logger := testStoreAndV8Logger(t)
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir}
	cfg.Routing.Enabled = true
	cfg.Routing.RouteOnly.Connectors = []string{"claudecode"}
	tokens := newRouteTokenStore(dir, "1000")
	old, err := tokens.Token("claudecode")
	if err != nil {
		t.Fatal(err)
	}
	a := &APIServer{addr: "127.0.0.1:18970", scannerCfg: cfg, logger: logger}
	a.routeOnly.Store(&routeOnlyServer{tokens: tokens})
	renders := 0
	a.onRouteKeyRotated = func() { renders++ }

	a.noteHeldAPIPort(errForeign)
	a.noteHeldAPIPort(errForeign)
	raw, err := os.ReadFile(filepath.Join(dir, "hooks", routePortHeldName))
	if err != nil {
		t.Fatalf("held-port mark: %v", err)
	}
	var mark routePortHeld
	if json.Unmarshal(raw, &mark) != nil || mark.UID != nil || mark.SID != "S-1-5-21-1-2-3-1001" || mark.Addr != "127.0.0.1:18970" {
		t.Fatalf("mark: %s", raw)
	}
	if events, err := store.ListEvents(10); err != nil || len(events) != 1 || events[0].Severity != "HIGH" ||
		!strings.Contains(events[0].Details, "another account") {
		t.Fatalf("one audit per acquire: %+v %v", events, err)
	}
	a.rotateRouteKeyAfterHeldPort()
	if renders != 1 || tokens.Valid("claudecode", old) {
		t.Fatalf("renders=%d: the old credential is refused once the port is back", renders)
	}

	// Managed Windows rotates its route epoch instead: no mark.
	b := &APIServer{addr: "127.0.0.1:18970", scannerCfg: &config.Config{DataDir: t.TempDir(), DeploymentMode: "managed_enterprise"}}
	b.scannerCfg.Enterprise.Profile = "standalone"
	if !b.noteAPIPortHolder() {
		t.Fatal("managed: the holder is settled")
	}
	if _, err := os.Stat(filepath.Join(b.configDataDir(), "hooks", routePortHeldName)); !os.IsNotExist(err) {
		t.Fatalf("managed: no OSS mark: %v", err)
	}
}

// A refused bind with no listener in the table is a Windows excluded port
// range (or a holder already gone): no mark, no "another account" audit,
// and the next conflict looks again (REVIEW-code-delta-d962 P2-2). The
// gateway's own listener (a restart) is the same.
func TestNoteAPIPortHolderNoListenerOrOwnAccountIsNoHijack(t *testing.T) {
	for name, info := range map[string]apiPortHolderInfo{
		"reserved range": {},
		"own account":    {Found: true, SID: "S-1-5-21-1-2-3-1000"},
	} {
		t.Run(name, func(t *testing.T) {
			useAPIPortHolder(t, info)
			store, logger := testStoreAndV8Logger(t)
			cfg := &config.Config{DataDir: t.TempDir()}
			cfg.Routing.Enabled = true
			cfg.Routing.RouteOnly.Connectors = []string{"claudecode"}
			a := &APIServer{addr: "127.0.0.1:18970", scannerCfg: cfg, logger: logger}
			a.noteHeldAPIPort(syscall.Errno(10013))
			a.noteHeldAPIPort(syscall.Errno(10013))
			if a.apiPortHolderNoted.Load() {
				t.Fatal("not settled: the next conflict looks again")
			}
			if _, err := os.Stat(filepath.Join(a.configDataDir(), "hooks", routePortHeldName)); !os.IsNotExist(err) {
				t.Fatalf("no mark: %v", err)
			}
			if events, err := store.ListEvents(10); err != nil || len(events) != 0 {
				t.Fatalf("no audit: %+v %v", events, err)
			}
		})
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
