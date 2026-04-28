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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// applyHermeticConnectorHomes redirects the four built-in connector
// home/path overrides at a tmpdir so a parallel parity test does not
// race against the developer's real ~/.openclaw, ~/.claude,
// ~/.codex, ~/.zeptoclaw on disk.
//
// The package-level *PathOverride globals are not mutex-protected, so
// every parallel subtest in this file MUST snapshot and restore
// them. We deliberately use t.Cleanup over defer so the previous
// override (when one is already in flight from another suite) is
// restored even if the subtest fails.
func applyHermeticConnectorHomes(t *testing.T) {
	t.Helper()
	tmpHome := t.TempDir()

	prevOC := connector.OpenClawHomeOverride
	connector.OpenClawHomeOverride = filepath.Join(tmpHome, ".openclaw")
	t.Cleanup(func() { connector.OpenClawHomeOverride = prevOC })

	prevZC := connector.ZeptoClawConfigPathOverride
	connector.ZeptoClawConfigPathOverride = filepath.Join(tmpHome, ".zeptoclaw", "config.json")
	t.Cleanup(func() { connector.ZeptoClawConfigPathOverride = prevZC })

	prevCC := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = filepath.Join(tmpHome, ".claude", "settings.json")
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = prevCC })

	prevCodex := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = filepath.Join(tmpHome, ".codex", "config.toml")
	t.Cleanup(func() { connector.CodexConfigPathOverride = prevCodex })

	// Plan A4 / S0.12: ZeptoClaw's Setup refuses to proceed when the
	// provider list is empty. Seed a single usable provider so the
	// matrix subtest reaches the persist step.
	if err := os.MkdirAll(filepath.Dir(connector.ZeptoClawConfigPathOverride), 0o755); err == nil {
		_ = os.WriteFile(
			connector.ZeptoClawConfigPathOverride,
			[]byte(`{"providers":{"openai":{"api_base":"https://api.openai.com","api_key":"sk-parity"}}}`),
			0o600,
		)
	}
	if err := os.MkdirAll(filepath.Dir(connector.ClaudeCodeSettingsPathOverride), 0o755); err != nil {
		// Test-only seam — log and move on; the test will fail
		// naturally if the dir really can't be created.
		t.Logf("hermetic claude-code dir mkdir warning: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(connector.CodexConfigPathOverride), 0o755); err != nil {
		t.Logf("hermetic codex dir mkdir warning: %v", err)
	}
}

// TestProxy_PerConnectorPrefixStrip is the connector-matrix variant of
// TestConnectorPrefixStripper (plan E1). The original asserts the
// happy-path strip for each name implicitly via a flat case list;
// this version reorganizes the cases as “t.Run“ subtests so a
// future regression that breaks one connector's strip surfaces
// independently in the test report.
func TestProxy_PerConnectorPrefixStrip(t *testing.T) {
	t.Parallel()
	reg := connector.NewDefaultRegistry()

	cases := []struct {
		connector string
		raw       string
		stripped  string
	}{
		{"openclaw", "/c/openclaw/v1/messages", "/v1/messages"},
		{"zeptoclaw", "/c/zeptoclaw/v1/chat/completions", "/v1/chat/completions"},
		{"claudecode", "/c/claudecode/v1/messages", "/v1/messages"},
		{"codex", "/c/codex/v1/responses", "/v1/responses"},
	}

	for _, tc := range cases {
		t.Run(tc.connector, func(t *testing.T) {
			t.Parallel()
			var got string
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.URL.Path
			})
			handler := connectorPrefixStripper(inner, reg)
			req := httptest.NewRequest("POST", "http://localhost"+tc.raw, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if got != tc.stripped {
				t.Errorf("%s: stripper(%q) inner saw %q, want %q",
					tc.connector, tc.raw, got, tc.stripped)
			}
		})
	}
}

// TestSwitchConnector_PerConnectorPersistsState parametrizes the
// existing TestSwitchConnectorLocked_TearsDownOldAndSetsUpNew over
// the full matrix (plan E1, item 2c). For each pair (from, to) the
// proxy must:
//  1. End with `to` as the active connector.
//  2. Persist the new active connector under DataDir/active_connector.json
//     so the sidecar honours the switch on next boot.
//
// Note: we don't sweep the full N×N grid — that's overkill — but we
// hit every "to" target at least once, which is what plan E1 calls
// for. "from" is fixed to codex so the assertion focuses on
// destination connector behaviour.
func TestSwitchConnector_PerConnectorPersistsState(t *testing.T) {
	// Intentionally NOT parallel: subtests call connector.Setup() which
	// touches the per-connector home dir. Even with applyHermeticConnectorHomes
	// the *PathOverride globals themselves are shared mutable state, so
	// running the connectors serially keeps the override semantics clean
	// under -race.
	applyHermeticConnectorHomes(t)

	cases := []string{"openclaw", "zeptoclaw", "claudecode", "codex"}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			reg := connector.NewDefaultRegistry()

			// Always start from codex (a different connector when
			// target != codex; same connector when target == codex
			// — the no-op path is also a valid parity case).
			start, _ := reg.Get("codex")
			start.SetCredentials("tok", "mk")

			p := &GuardrailProxy{
				connector:    start,
				registry:     reg,
				gatewayToken: "tok",
				masterKey:    "mk",
				setupOpts: connector.SetupOpts{
					DataDir:   dir,
					ProxyAddr: "127.0.0.1:4000",
					APIAddr:   "127.0.0.1:18970",
				},
				health: NewSidecarHealth(),
			}

			p.switchConnectorLocked(target)

			if p.connector.Name() != target {
				t.Errorf("connector after switchConnectorLocked(%q) = %q",
					target, p.connector.Name())
			}

			persisted := connector.LoadActiveConnector(dir)
			if target == "codex" {
				// No-op: same-connector switch is documented to skip
				// the persist step (TestSwitchConnectorLocked_SameConnectorIsNoop).
				if persisted != "" {
					t.Errorf("same-connector switch wrote state %q, want empty", persisted)
				}
				return
			}
			if persisted != target {
				t.Errorf("persisted state = %q, want %q", persisted, target)
			}
		})
	}
}

// TestApplyRuntime_PerConnectorSwitch is the parametrized E1
// counterpart to TestApplyRuntime_ConnectorSwitch — proves that the
// runtime config hot-swap path applies for every connector, not
// just openclaw.
func TestApplyRuntime_PerConnectorSwitch(t *testing.T) {
	// See note on TestSwitchConnector_PerConnectorPersistsState: the
	// *PathOverride globals are shared, so we serialize subtests rather
	// than parallelize them.
	applyHermeticConnectorHomes(t)

	for _, target := range []string{"openclaw", "zeptoclaw", "claudecode"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			reg := connector.NewDefaultRegistry()
			start, _ := reg.Get("codex")
			start.SetCredentials("tok", "mk")

			p := &GuardrailProxy{
				connector:    start,
				registry:     reg,
				gatewayToken: "tok",
				masterKey:    "mk",
				setupOpts: connector.SetupOpts{
					DataDir:   dir,
					ProxyAddr: "127.0.0.1:4000",
					APIAddr:   "127.0.0.1:18970",
				},
				health:    NewSidecarHealth(),
				inspector: NewGuardrailInspector("local", nil, nil, ""),
			}

			p.applyRuntime(map[string]string{"connector": target})

			if p.connector.Name() != target {
				t.Errorf("applyRuntime({connector=%q}) -> %q",
					target, p.connector.Name())
			}
		})
	}
}
