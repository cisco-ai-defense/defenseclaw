// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// writePathTokenFile is a tiny helper that mirrors what
// connector.EnsureOTLPPathToken writes — an owner-only file containing a
// hex-encoded token plus trailing newline — without taking the package-
// local mutex. We want the test to model the on-disk state the way
// `defenseclaw setup geminicli` leaves it: present, non-empty, mode 0o600.
func writePathTokenFile(t *testing.T, dataDir string, scope connector.OTLPPathTokenScope, token string) string {
	t.Helper()
	dir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir hooks dir: %v", err)
	}
	path, err := connector.OTLPPathTokenFilePath(dataDir, scope)
	if err != nil {
		t.Fatalf("OTLPPathTokenFilePath: %v", err)
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

// TestLookupOTLPPathToken_LazyReloadOnMiss is the F4 regression test:
// when the sidecar boots with no scoped tokens loaded and the operator
// subsequently runs `defenseclaw setup geminicli` (which mints a token
// on disk), the very next loopback OTLP request must succeed. Previously
// the in-memory snapshot only refreshed at sidecar boot, so every Gemini
// OTLP export returned 401 until the next gateway restart even though
// settings.json and the on-disk token were correct.
func TestLookupOTLPPathToken_LazyReloadOnMiss(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const minted = "deadbeef" + "cafef00d" + "deadbeef" + "cafef00d" +
		"deadbeef" + "cafef00d" + "deadbeef" + "cafef00d"
	writePathTokenFile(t, tmp, connector.OTLPScopeGeminiCLI, minted)

	cfg := &config.Config{}
	cfg.DataDir = tmp
	api := &APIServer{scannerCfg: cfg}
	// Intentionally do NOT call SetOTLPPathTokens — this is the
	// boot-vs-setup race we are fixing: gateway came up first, setup
	// minted the token after.

	got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI))
	if got != minted {
		t.Fatalf("lookupOTLPPathToken returned %q on first miss; want %q (lazy reload broken)", got, minted)
	}

	// Second call must serve from cache. We verify by removing the
	// file: a request that goes back to disk would now fail. The
	// cached value must still be returned.
	path, err := connector.OTLPPathTokenFilePath(tmp, connector.OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("OTLPPathTokenFilePath: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("rm token file: %v", err)
	}
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != minted {
		t.Fatalf("second lookup returned %q after file removed; cache lost (want %q)", got, minted)
	}
}

// TestLookupOTLPPathToken_IgnoresUnknownScopes ensures the lazy reload
// path NEVER touches disk for source segments outside the closed scope
// allow-list. A fuzzer / attacker probing /otlp/<random>/<token>/v1/* must
// not be able to convert the auth path into a disk-stampede primitive.
func TestLookupOTLPPathToken_IgnoresUnknownScopes(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	cfg := &config.Config{}
	cfg.DataDir = tmp
	api := &APIServer{scannerCfg: cfg}

	bogus := []string{
		"../etc/passwd",
		"unknown-vendor",
		"GEMINI", // wrong case — not in OTLPPathTokenScopes()
		"",
		"geminicli ",
	}
	for _, s := range bogus {
		if got := api.lookupOTLPPathToken(s); got != "" {
			t.Errorf("lookupOTLPPathToken(%q) = %q, want \"\" (unknown scope must skip disk)", s, got)
		}
	}
	// And no .otlp-* token file may have been touched by the lookup
	// for an unknown scope.
	hooksDir := filepath.Join(tmp, "hooks")
	if entries, err := os.ReadDir(hooksDir); err == nil && len(entries) != 0 {
		t.Errorf("hooks dir contains %d entries after unknown-scope lookups; want 0 (lazy reload touched disk)", len(entries))
	}
}

// TestLookupOTLPPathToken_RateLimitsRepeatedMisses guards against a
// pathological caller (or a misconfigured connector) that hammers
// /otlp/geminicli/<random>/v1/... with no on-disk token file: after the
// first miss attempts a reload we must NOT keep re-reading disk on every
// subsequent miss. The test files no token, then asserts that the second
// consecutive miss within the rate-limit window returns without setting
// a new reload-at entry beyond the first.
func TestLookupOTLPPathToken_RateLimitsRepeatedMisses(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	cfg := &config.Config{}
	cfg.DataDir = tmp
	api := &APIServer{scannerCfg: cfg}

	// First miss — must attempt the reload, no token to find.
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != "" {
		t.Fatalf("first lookup = %q, want \"\" (no token file present)", got)
	}
	api.otlpPathTokenMu.RLock()
	first := api.otlpPathTokenReloadAt[connector.OTLPScopeGeminiCLI]
	api.otlpPathTokenMu.RUnlock()
	if first.IsZero() {
		t.Fatalf("first miss did not record a reload-at timestamp; rate limiter inert")
	}

	// Second miss within the refractory window — must NOT update the
	// timestamp (proves no second disk read happened).
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != "" {
		t.Fatalf("second lookup = %q, want \"\"", got)
	}
	api.otlpPathTokenMu.RLock()
	second := api.otlpPathTokenReloadAt[connector.OTLPScopeGeminiCLI]
	api.otlpPathTokenMu.RUnlock()
	if !second.Equal(first) {
		t.Errorf("second miss re-issued disk reload (timestamp moved %v → %v); rate limiter not enforcing window", first, second)
	}
}

// TestLookupOTLPPathToken_ReloadAfterWindowAllowsRetry verifies that
// after the refractory window elapses, the next miss DOES attempt a
// fresh reload — which is required for operator flows like "I ran
// setup again to rotate the token, the gateway should pick it up
// within a second."
func TestLookupOTLPPathToken_ReloadAfterWindowAllowsRetry(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	cfg := &config.Config{}
	cfg.DataDir = tmp
	api := &APIServer{scannerCfg: cfg}

	// First miss with no file on disk.
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != "" {
		t.Fatalf("first lookup = %q, want \"\"", got)
	}
	// Backdate the rate-limit timestamp to simulate the window
	// elapsing. We rewind it past the configured min interval.
	api.otlpPathTokenMu.Lock()
	api.otlpPathTokenReloadAt[connector.OTLPScopeGeminiCLI] =
		time.Now().Add(-2 * otlpPathTokenReloadMinInterval)
	api.otlpPathTokenMu.Unlock()

	// Now drop a token file on disk and re-query — must succeed.
	const minted = "0011223344556677" + "8899aabbccddeeff" +
		"0011223344556677" + "8899aabbccddeeff"
	writePathTokenFile(t, tmp, connector.OTLPScopeGeminiCLI, minted)
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != minted {
		t.Errorf("lookup after window elapsed = %q, want minted token %q (operator rotate flow broken)", got, minted)
	}
}

// TestLookupOTLPPathToken_NoDataDirSkipsReload guards the defensive
// dataDir guard: if scannerCfg.DataDir is empty (test fixtures that
// haven't wired a real config), lookupOTLPPathToken must NOT panic or
// touch the working directory.
func TestLookupOTLPPathToken_NoDataDirSkipsReload(t *testing.T) {
	t.Parallel()
	api := &APIServer{scannerCfg: &config.Config{}}
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != "" {
		t.Errorf("lookup with empty DataDir returned %q, want \"\"", got)
	}
}
