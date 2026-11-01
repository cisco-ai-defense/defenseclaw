// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0963/1042: launchd holds the default API address. Standalone managed
// gateways must adopt it; a different profile may still bind its own
// configured port. A mismatched Linux socket unit always fails closed.
func TestInheritedAPIListenerOnAnotherAddress(t *testing.T) {
	restoreAPI, restoreMismatch := inheritedAPIListener, apiInheritedMismatchBinds
	t.Cleanup(func() { inheritedAPIListener, apiInheritedMismatchBinds = restoreAPI, restoreMismatch })
	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	inheritedAPIListener = func() (net.Listener, bool, error) { return held, true, nil }
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	configured := probe.Addr().String()
	_ = probe.Close()
	api := &APIServer{addr: configured}

	apiInheritedMismatchBinds = false
	if listener, err := api.acquireAPIListener(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match configured") {
		if listener != nil {
			_ = listener.Close()
		}
		t.Fatalf("a socket unit on another address = %v, want the mismatch refusal", err)
	}

	apiInheritedMismatchBinds = true
	managedCfg := config.DefaultConfig()
	managedCfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	managedCfg.Enterprise.Profile = "standalone"
	api.scannerCfg = managedCfg
	if listener, err := api.acquireAPIListener(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match configured") {
		if listener != nil {
			_ = listener.Close()
		}
		t.Fatalf("managed launchd socket on another address = %v, want the mismatch refusal", err)
	}
	api.scannerCfg = nil
	listener, err := api.acquireAPIListener(context.Background())
	if err != nil {
		t.Fatalf("launchd socket on the default address with another configured port: %v", err)
	}
	defer listener.Close()
	if listener.Addr().String() != configured {
		t.Fatalf("listener %s, want the configured %s", listener.Addr(), configured)
	}

	// GAP-1086: under an older launchd job (no API socket) a managed
	// standalone gateway does not bind the port itself; other profiles do.
	// The installed definition declares the socket: the loaded job is stale.
	restoreDefinition := apiLaunchdDefinitionDeclaresSocket
	t.Cleanup(func() { apiLaunchdDefinitionDeclaresSocket = restoreDefinition })
	apiLaunchdDefinitionDeclaresSocket = func() (bool, bool) { return true, true }
	inheritedAPIListener = func() (net.Listener, bool, error) { return nil, false, nil }
	api.scannerCfg = managedCfg
	if unheld, err := api.acquireAPIListener(context.Background()); err == nil || !strings.Contains(err.Error(), "holds no API socket") {
		if unheld != nil {
			_ = unheld.Close()
		}
		t.Fatalf("managed launchd job without the API socket = %v, want the reload refusal", err)
	}
	api.scannerCfg = nil

	// The configured address itself is adopted on every platform.
	inheritedAPIListener = func() (net.Listener, bool, error) { return listener, true, nil }
	adopted, err := api.acquireAPIListener(context.Background())
	if err != nil || adopted != listener {
		t.Fatalf("the inherited configured address was not adopted: %v", err)
	}
}

// GAP-2144: a rolled-back package upgrade restores the previous release's
// launchd definition, which declares no API socket, under this build's
// binary. That job is the one its definition describes: the managed gateway
// binds the configured port as the previous release did. A definition that
// cannot be read or trusted keeps the GAP-1086 refusal.
func TestManagedGatewayBindsUnderARolledBackLaunchdDefinition(t *testing.T) {
	restoreAPI, restoreMismatch, restoreDefinition := inheritedAPIListener, apiInheritedMismatchBinds, apiLaunchdDefinitionDeclaresSocket
	t.Cleanup(func() {
		inheritedAPIListener, apiInheritedMismatchBinds, apiLaunchdDefinitionDeclaresSocket = restoreAPI, restoreMismatch, restoreDefinition
	})
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	configured := probe.Addr().String()
	_ = probe.Close()
	managedCfg := config.DefaultConfig()
	managedCfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	managedCfg.Enterprise.Profile = "standalone"
	api := &APIServer{addr: configured, scannerCfg: managedCfg}
	inheritedAPIListener = func() (net.Listener, bool, error) { return nil, false, nil }
	apiInheritedMismatchBinds = true

	apiLaunchdDefinitionDeclaresSocket = func() (bool, bool) { return false, true }
	listener, err := api.acquireAPIListener(context.Background())
	if err != nil {
		t.Fatalf("managed gateway under a definition without the API socket = %v, want it to bind %s", err, configured)
	}
	if listener.Addr().String() != configured {
		t.Fatalf("listener %s, want %s", listener.Addr(), configured)
	}
	_ = listener.Close()

	apiLaunchdDefinitionDeclaresSocket = func() (bool, bool) { return false, false }
	if unheld, err := api.acquireAPIListener(context.Background()); err == nil || !strings.Contains(err.Error(), "holds no API socket") {
		if unheld != nil {
			_ = unheld.Close()
		}
		t.Fatalf("managed gateway with an unknown definition = %v, want the reload refusal", err)
	}
}

// The definition check reads only a root-owned XML plist nobody else can
// write; the gateway's renderer writes exactly that.
func TestLaunchdDefinitionDeclaresSocketReadsOnlyATrustedPlist(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	head := `<?xml version="1.0" encoding="UTF-8"?>` + "\n<plist version=\"1.0\"><dict><key>Label</key><string>com.cisco.defenseclaw.gateway</string>"
	with := write("with.plist", head+"<key>Sockets</key><dict/></dict></plist>\n", 0o644)
	without := write("without.plist", head+"</dict></plist>\n", 0o644)
	writable := write("writable.plist", head+"</dict></plist>\n", 0o666)
	binary := write("binary.plist", "bplist00", 0o644)
	root := os.Geteuid() == 0
	for _, tc := range []struct {
		path            string
		declares, known bool
	}{
		{with, root, root},
		{without, false, root},
		{writable, false, false},
		{binary, false, false},
		{filepath.Join(dir, "missing.plist"), false, false},
	} {
		if declares, known := launchdDefinitionDeclaresSocket(tc.path); declares != tc.declares || known != tc.known {
			t.Errorf("%s: declares=%v known=%v, want %v %v", filepath.Base(tc.path), declares, known, tc.declares, tc.known)
		}
	}
}
