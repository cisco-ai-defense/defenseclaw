// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func useProcNetFixture(t *testing.T, tcp, tcp6 string) {
	t.Helper()
	if !littleEndianHost() {
		t.Skip("fixtures are little-endian /proc output")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"tcp": tcp, "tcp6": tcp6} {
		if body == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(root, "net", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prev := procNetRoot
	procNetRoot = root
	t.Cleanup(func() { procNetRoot = prev })
}

func TestAPIPortHolderUIDReadsProcNet(t *testing.T) {
	useProcNetFixture(t, procNetTCPFixture, procNetTCP6Fixture)
	if uid, found, err := apiPortHolderUID("127.0.0.1:18970", 1000); err != nil || !found || uid != 4242 {
		t.Fatalf("v4 holder: %d %v %v", uid, found, err)
	}
	// The [::] listener of uid 4243 on 18971 blocks a 127.0.0.1 bind.
	if uid, found, err := apiPortHolderUID("127.0.0.1:18971", 1000); err != nil || !found || uid != 4243 {
		t.Fatalf("v6 wildcard holder: %d %v %v", uid, found, err)
	}
	if _, found, err := apiPortHolderUID("127.0.0.1:18999", 1000); err != nil || found {
		t.Fatalf("free port: %v %v", found, err)
	}
	useProcNetFixture(t, "", "")
	if _, found, err := apiPortHolderUID("127.0.0.1:18970", 1000); err != nil || found {
		t.Fatalf("no tables (another namespace): %v %v", found, err)
	}
}

func heldPortServer(t *testing.T, routed bool) (*APIServer, *audit.Store) {
	t.Helper()
	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{DataDir: t.TempDir()}
	if routed {
		cfg.Routing.Enabled = true
		cfg.Routing.RouteOnly.Connectors = []string{"claudecode"}
	}
	prev := apiPortSelfUID
	apiPortSelfUID = func() int { return 1000 }
	t.Cleanup(func() { apiPortSelfUID = prev })
	return &APIServer{addr: "127.0.0.1:18970", scannerCfg: cfg, logger: logger}, store
}

// Another account holding the API port is audited and marked for the
// rotation; the route key itself is not touched yet (S1 DESIGN 17.1).
func TestNoteAPIPortHolderAuditsAnotherAccount(t *testing.T) {
	useProcNetFixture(t, procNetTCPFixture, "")
	a, store := heldPortServer(t, true)
	key := filepath.Join(a.configDataDir(), "hooks", routeTokenKeyName)
	if _, err := newRouteTokenStore(a.configDataDir(), "1000").Token("claudecode"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(key)
	a.noteAPIPortHolder()
	raw, err := os.ReadFile(filepath.Join(a.configDataDir(), "hooks", routePortHeldName))
	if err != nil {
		t.Fatalf("held-port mark: %v", err)
	}
	var mark routePortHeld
	if json.Unmarshal(raw, &mark) != nil || mark.UID == nil || *mark.UID != 4242 || mark.Addr != "127.0.0.1:18970" {
		t.Fatalf("mark: %s", raw)
	}
	if after, _ := os.ReadFile(key); string(after) != string(before) {
		t.Fatal("the route key must not rotate while another account holds the port")
	}
	events, err := store.ListEvents(10)
	if err != nil || len(events) != 1 || events[0].Action != string(audit.ActionGatewayDegraded) ||
		events[0].Severity != "HIGH" || !strings.Contains(events[0].Details, "uid 4242") {
		t.Fatalf("audit: %+v %v", events, err)
	}
}

func TestNoteAPIPortHolderIgnoresTheOwnAccount(t *testing.T) {
	useProcNetFixture(t, strings.ReplaceAll(procNetTCPFixture, "  4242  ", "  1000  "), "")
	a, store := heldPortServer(t, true)
	a.noteAPIPortHolder()
	if _, err := os.Stat(filepath.Join(a.configDataDir(), "hooks", routePortHeldName)); !os.IsNotExist(err) {
		t.Fatalf("own listener (a gateway still stopping) is no hijack: %v", err)
	}
	if events, _ := store.ListEvents(10); len(events) != 0 {
		t.Fatalf("audit: %+v", events)
	}
}

// Route-only off: audited, nothing to rotate.
func TestNoteAPIPortHolderWithoutRouteOnly(t *testing.T) {
	useProcNetFixture(t, procNetTCPFixture, "")
	b, store := heldPortServer(t, false)
	b.noteAPIPortHolder()
	if _, err := os.Stat(filepath.Join(b.configDataDir(), "hooks", routePortHeldName)); !os.IsNotExist(err) {
		t.Fatalf("no route-only, no mark: %v", err)
	}
	if events, err := store.ListEvents(10); len(events) != 1 {
		t.Fatalf("audit without route-only: %+v %v", events, err)
	}
}

// A restart: the first conflict is this account (its exiting gateway), and
// another account takes the port before the next attempt. The holder is
// looked up again, so the mark is written and audited once (REVIEW P2-3).
func TestNoteHeldAPIPortLooksAgainAfterTheOwnAccount(t *testing.T) {
	useProcNetFixture(t, strings.ReplaceAll(procNetTCPFixture, "  4242  ", "  1000  "), "")
	a, store := heldPortServer(t, true)
	mark := filepath.Join(a.configDataDir(), "hooks", routePortHeldName)
	a.noteHeldAPIPort(syscall.EADDRINUSE)
	if _, err := os.Stat(mark); !os.IsNotExist(err) {
		t.Fatalf("own listener: %v", err)
	}
	useProcNetFixture(t, procNetTCPFixture, "")
	a.noteHeldAPIPort(syscall.EADDRINUSE)
	a.noteHeldAPIPort(syscall.EADDRINUSE)
	if _, err := os.Stat(mark); err != nil {
		t.Fatalf("another account after the own one: %v", err)
	}
	if events, err := store.ListEvents(10); err != nil || len(events) != 1 {
		t.Fatalf("one audit: %+v %v", events, err)
	}
}
