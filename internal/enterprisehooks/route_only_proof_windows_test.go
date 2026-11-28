// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-1975: a LocalSystem verify (the guardian) that reads a route-only
// render back exact returns its RouteOnlyProof, and so does the read-back
// after an install writes it; any other caller, a render that differs and
// no render return none.
func TestWindowsRouteOnlyProofOnlyFromAnExactLocalSystemRead(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	account := currentWindowsTestSID(t)
	conn, ok := newWindowsEnterpriseConnectorRegistry().Get("codex")
	if !ok {
		t.Fatal("no codex connector")
	}
	route := &connector.RouteOnlySetup{BaseURL: "http://127.0.0.1:18970/r/codex", Token: "dcr1-codex", Custody: true}
	if err := connector.WithUserHomeDir(home, func() error { return applyWindowsRouteOnly(conn, dataDir, route) }); err != nil {
		t.Fatal(err)
	}
	previousSystem := windowsRouteOnlyVerifierIsLocalSystem
	t.Cleanup(func() { windowsRouteOnlyVerifierIsLocalSystem = previousSystem })

	windowsRouteOnlyVerifierIsLocalSystem = func() bool { return true }
	status, err := verifyWindowsRouteOnly(conn, account, home, dataDir, route)
	if err != nil || status != RouteOnlyProof(route) {
		t.Fatalf("LocalSystem verify of the exact render = %q, %v; want its proof", status, err)
	}
	if got := windowsRouteOnlyInstalledProof(conn, account, home, dataDir, route); got != RouteOnlyProof(route) {
		t.Fatalf("LocalSystem read-back after install = %q; want the proof", got)
	}
	rotated := &connector.RouteOnlySetup{BaseURL: route.BaseURL, Token: "dcr1-rotated", Custody: true}
	if got := windowsRouteOnlyInstalledProof(conn, account, home, dataDir, rotated); got != "" {
		t.Fatalf("read-back of a render that differs = %q; want none", got)
	}
	if got := windowsRouteOnlyInstalledProof(conn, account, home, dataDir, nil); got != "" {
		t.Fatalf("read-back with no render = %q; want none", got)
	}

	windowsRouteOnlyVerifierIsLocalSystem = func() bool { return false }
	if status, err := verifyWindowsRouteOnly(conn, account, home, dataDir, route); err != nil || status != "" {
		t.Fatalf("non-LocalSystem verify of the exact render = %q, %v; want no proof", status, err)
	}
	if got := windowsRouteOnlyInstalledProof(conn, account, home, dataDir, route); got != "" {
		t.Fatalf("non-LocalSystem read-back = %q; want none", got)
	}
}
