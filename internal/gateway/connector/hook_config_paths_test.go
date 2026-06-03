// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// cursorTestSetup wires the cursor connector to a temp config path and returns
// a connector + opts ready for Setup. The path override is reset on cleanup so
// it never leaks across tests in this package.
func cursorTestSetup(t *testing.T) (Connector, SetupOpts, string) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "hooks.json")
	prev := CursorHooksPathOverride
	CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { CursorHooksPathOverride = prev })
	opts := SetupOpts{
		DataDir:      t.TempDir(),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: t.TempDir(),
	}
	return NewCursorConnector(), opts, cfgPath
}

func TestHookConfigPathsForConnector_ResolvesOverride(t *testing.T) {
	conn, opts, cfgPath := cursorTestSetup(t)

	paths := HookConfigPathsForConnector(conn, opts)
	if len(paths) != 1 {
		t.Fatalf("HookConfigPathsForConnector = %v, want exactly the cursor hooks path", paths)
	}
	if paths[0] != cfgPath {
		t.Fatalf("HookConfigPathsForConnector[0] = %q, want %q", paths[0], cfgPath)
	}
}

func TestHookConfigPathsForConnector_ProxyConnectorsAreInert(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir(), ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	for _, conn := range []Connector{NewOpenClawConnector(), NewZeptoClawConnector()} {
		if paths := HookConfigPathsForConnector(conn, opts); paths != nil {
			t.Errorf("%s: HookConfigPathsForConnector = %v, want nil (proxy/plugin connector must be inert)", conn.Name(), paths)
		}
	}
}

func TestHookConfigPathsForConnector_NilConnector(t *testing.T) {
	if paths := HookConfigPathsForConnector(nil, SetupOpts{}); paths != nil {
		t.Fatalf("HookConfigPathsForConnector(nil) = %v, want nil", paths)
	}
}

func TestOwnedHooksPresent_TrueAfterSetup_FalseAfterRemoval(t *testing.T) {
	conn, opts, cfgPath := cursorTestSetup(t)

	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	present, err := OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent after Setup: %v", err)
	}
	if !present {
		data, _ := os.ReadFile(cfgPath)
		t.Fatalf("OwnedHooksPresent=false after Setup; config:\n%s", data)
	}

	// Strip the hook block: an empty JSON object no longer references our
	// hook command.
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip config: %v", err)
	}
	present, err = OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent after strip: %v", err)
	}
	if present {
		t.Fatal("OwnedHooksPresent=true after stripping the hook block; want false")
	}
}

func TestOwnedHooksPresent_FalseWhenFileMissing(t *testing.T) {
	conn, opts, cfgPath := cursorTestSetup(t)

	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := os.Remove(cfgPath); err != nil {
		t.Fatalf("remove config: %v", err)
	}

	present, err := OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent with missing file returned error: %v", err)
	}
	if present {
		t.Fatal("OwnedHooksPresent=true for a deleted config file; want false")
	}
}

func TestOwnedHooksPresent_ProxyConnectorReportsPresent(t *testing.T) {
	// Proxy/plugin connectors have no guarded hook config paths, so they
	// are reported present (never heal-eligible).
	opts := SetupOpts{DataDir: t.TempDir(), ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	present, err := OwnedHooksPresent(NewOpenClawConnector(), opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent: %v", err)
	}
	if !present {
		t.Fatal("OwnedHooksPresent=false for proxy connector; want true (inert)")
	}
}
