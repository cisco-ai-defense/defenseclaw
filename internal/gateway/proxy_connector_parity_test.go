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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
//
// Belt-and-suspenders: we ALSO call t.Setenv("HOME", tmpHome). Every
// connector's *Path() helper falls back to “os.Getenv("HOME")“
// when its override is empty, so if a future refactor (or a fresh
// test added here without the override goroutine) ever leaves a
// global at "" mid-test, the fallback path lands inside tmpHome
// instead of the developer's real home. Without this we have
// already seen ~/.claude/settings.json get polluted with hook
// commands pointing at long-deleted “/var/folders/.../T/Test...“
// dirs — Claude Code then logs "hook script: No such file or
// directory" on every session start.
//
// t.Setenv automatically restores HOME at test cleanup time and is
// disallowed in parallel tests (which is desirable here — both
// callers of applyHermeticConnectorHomes deliberately serialize
// their subtests).
func applyHermeticConnectorHomes(t *testing.T) {
	t.Helper()
	tmpHome := t.TempDir()

	// Defense in depth: also redirect HOME so any helper that
	// bypasses the *PathOverride seam still lands inside tmpHome.
	// Go's testing framework restores the previous HOME at test
	// completion automatically.
	t.Setenv("HOME", tmpHome)

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

// TestApplyHermeticConnectorHomes_RedirectsHOME guards the
// belt-and-suspenders defense added to applyHermeticConnectorHomes:
// dropping t.Setenv("HOME", tmpHome) would silently re-open the
// regression where ~/.claude/settings.json was getting polluted by
// test-temp hook paths (e.g. "/var/folders/.../T/Test.../001/hooks/
// claude-code-hook.sh"). Claude Code's hook bus reads those paths
// at every session start, so a leaked entry produces a "No such
// file or directory" error on every UserPromptSubmit until the
// developer manually edits settings.json.
//
// We assert the post-conditions of the helper directly rather than
// running a full Setup → settings.json round-trip, because the
// failure mode we are guarding against — fallback to
// `os.Getenv("HOME")` — surfaces in the resolved path, not in the
// connector's serialization logic.
func TestApplyHermeticConnectorHomes_RedirectsHOME(t *testing.T) {
	realHome := os.Getenv("HOME")
	applyHermeticConnectorHomes(t)
	got := os.Getenv("HOME")
	if got == realHome {
		t.Errorf("HOME still points at %q after applyHermeticConnectorHomes — t.Setenv defense missing", realHome)
	}
	// Every per-connector path override must now resolve UNDER the
	// new HOME (or under the dedicated tmpHome dir — same root).
	if !strings.HasPrefix(connector.ClaudeCodeSettingsPathOverride, got) {
		t.Errorf("ClaudeCodeSettingsPathOverride = %q does not live under tmp HOME %q",
			connector.ClaudeCodeSettingsPathOverride, got)
	}
	if !strings.HasPrefix(connector.CodexConfigPathOverride, got) {
		t.Errorf("CodexConfigPathOverride = %q does not live under tmp HOME %q",
			connector.CodexConfigPathOverride, got)
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

			// Plan E1 / round-3 follow-up: when the gateway binary
			// was built without the OpenClaw extension (CI runner
			// uses `make sync-openclaw-extension` which writes a
			// .placeholder), OpenClaw.Setup() returns "openclaw
			// extension is not bundled" and switchConnectorLocked
			// rolls back. That's an environment-not-built skip,
			// not a parity violation. Pre-flight the Setup against
			// a throwaway connector so we can skip cleanly instead
			// of fighting the rollback path.
			if target == "openclaw" {
				probe, _ := reg.Get("openclaw")
				probe.SetCredentials("tok", "mk")
				probeOpts := connector.SetupOpts{
					DataDir:   t.TempDir(),
					ProxyAddr: "127.0.0.1:4000",
					APIAddr:   "127.0.0.1:18970",
				}
				if err := probe.Setup(context.Background(), probeOpts); err != nil {
					if strings.Contains(err.Error(), "openclaw extension is not bundled") {
						t.Skipf("openclaw extension not bundled in this gateway build — same skip case as TestConnectorLifecycle_Matrix/openclaw")
					}
					// Best-effort cleanup; the test continues either
					// way and a real Setup error will surface again
					// from the actual switchConnectorLocked call below.
					_ = probe.Teardown(context.Background(), probeOpts)
				} else {
					_ = probe.Teardown(context.Background(), probeOpts)
				}
			}

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

			// Same OpenClaw extension probe as
			// TestSwitchConnector_PerConnectorPersistsState — skip
			// the openclaw cell when the gateway binary was built
			// with only the placeholder.
			if target == "openclaw" {
				probe, _ := reg.Get("openclaw")
				probe.SetCredentials("tok", "mk")
				probeOpts := connector.SetupOpts{
					DataDir:   t.TempDir(),
					ProxyAddr: "127.0.0.1:4000",
					APIAddr:   "127.0.0.1:18970",
				}
				if err := probe.Setup(context.Background(), probeOpts); err != nil {
					if strings.Contains(err.Error(), "openclaw extension is not bundled") {
						t.Skipf("openclaw extension not bundled in this gateway build")
					}
					_ = probe.Teardown(context.Background(), probeOpts)
				} else {
					_ = probe.Teardown(context.Background(), probeOpts)
				}
			}

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

			p.applyRuntime(map[string]any{"connector": target})

			if p.connector.Name() != target {
				t.Errorf("applyRuntime({connector=%q}) -> %q",
					target, p.connector.Name())
			}
		})
	}
}
