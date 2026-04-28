// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestConnectorLifecycle_Matrix runs the full Setup → VerifyClean →
// Teardown → VerifyClean sequence against every built-in connector
// using isolated tmpdir homes. This is the connector-package-level
// analog of the Python install-lifecycle smoke matrix in C5
// (cli/tests/test_install_smoke.py); it exercises the Go-side
// “Connector.Setup“ plumbing without spinning up a real sidecar.
//
// The expected lifecycle invariant is:
//
//  1. VerifyClean on a fresh DataDir + isolated home returns nil.
//  2. After Setup, VerifyClean MAY return a residual error (the
//     connector has now patched config / written hooks). We do not
//     assert on the specific shape — different connectors have
//     different surfaces.
//  3. After Teardown, VerifyClean returns nil again. Any leftover
//     residue is a teardown bug and must surface here.
//
// ZeptoClaw is special-cased: its Setup() requires at least one
// usable provider in the seeded config.json or it fails fast (plan
// A4 / S0.12 provider startup probe). We seed an OpenAI provider
// for the test so Setup completes and we can prove the round-trip.
func TestConnectorLifecycle_Matrix(t *testing.T) {
	for _, fx := range connectorMatrix(t) {
		t.Run(fx.Name, func(t *testing.T) {
			home, dataDir := fx.Apply(t)
			_ = home

			reg := connector.NewDefaultRegistry()
			c, ok := reg.Get(fx.Name)
			if !ok {
				t.Fatalf("connector %q not in registry", fx.Name)
			}

			opts := connector.SetupOpts{
				DataDir:   dataDir,
				ProxyAddr: "127.0.0.1:4000",
				APIAddr:   "127.0.0.1:18970",
				APIToken:  "lifecycle-matrix-token",
			}

			// Per-connector pre-Setup seeding:
			//   - ZeptoClaw needs at least one usable provider in the
			//     seeded config.json or Setup() fails the no-usable-
			//     providers guard from plan A4.
			//   - ClaudeCode needs the parent directory of its
			//     settings.json override to exist before Setup() can
			//     acquire its file lock.
			//   - Codex's config.toml override parent must exist for
			//     the same reason.
			//   - OpenClaw's home is already MkdirAll'd by the matrix
			//     fixture.
			switch fx.Name {
			case "zeptoclaw":
				seedZeptoClawProviderConfig(t)
			case "claudecode":
				seedClaudeCodeSettingsParentDir(t)
			case "codex":
				seedCodexConfigParentDir(t)
			}

			// Stage 1: pre-Setup, fresh DataDir + isolated home →
			// VerifyClean MUST be clean.
			if err := c.VerifyClean(opts); err != nil {
				t.Fatalf("[%s] VerifyClean before Setup: unexpected residue: %v",
					fx.Name, err)
			}

			// Stage 2: Setup. The actual error type is implementation
			// detail; we only care that the connector's *contract*
			// (round-trippable Setup → Teardown) holds. Skip the
			// stage if Setup fails for an environmental reason
			// (sandbox enforcement requires external binaries that
			// may not be present in CI), but never fail-open.
			if err := c.Setup(context.Background(), opts); err != nil {
				if isExternalDependencyError(err) {
					t.Skipf("[%s] Setup needs external dependency unavailable in this environment: %v",
						fx.Name, err)
				}
				t.Fatalf("[%s] Setup: %v", fx.Name, err)
			}

			// Stage 3: Teardown. MUST succeed even if Setup left
			// residual state — Teardown is the recovery path.
			if err := c.Teardown(context.Background(), opts); err != nil {
				t.Errorf("[%s] Teardown: %v", fx.Name, err)
			}

			// Stage 4: post-Teardown VerifyClean. The residual list
			// MUST be empty; any non-nil error here is a teardown
			// bug and the entire point of this matrix.
			if err := c.VerifyClean(opts); err != nil {
				t.Errorf("[%s] VerifyClean after Teardown: residue still present: %v",
					fx.Name, err)
			}
		})
	}
}

// seedZeptoClawProviderConfig writes a minimal
// “$ZeptoClawConfigPathOverride“ file with one usable provider so
// “ZeptoClawConnector.Setup“ doesn't trip the no-usable-providers
// guard from plan A4. The override is already pointed at a tmpdir
// by “connectorMatrix“; we just write the file.
func seedZeptoClawProviderConfig(t *testing.T) {
	t.Helper()
	path := connector.ZeptoClawConfigPathOverride
	if path == "" {
		t.Fatal("seedZeptoClawProviderConfig: ZeptoClawConfigPathOverride not set")
	}
	body := `{
		"providers": {
			"openai": {"api_base": "https://api.openai.com", "api_key": "sk-zc-lifecycle-matrix"}
		},
		"safety": {"allow_private_endpoints": false}
	}`
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir zeptoclaw config dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("seed zeptoclaw config: %v", err)
	}
}

// seedClaudeCodeSettingsParentDir creates the parent directory of
// the ClaudeCodeSettingsPathOverride so Setup()'s file-lock
// acquisition (withFileLock) can succeed. Setup is otherwise happy
// to receive a missing settings.json — it creates one.
func seedClaudeCodeSettingsParentDir(t *testing.T) {
	t.Helper()
	path := connector.ClaudeCodeSettingsPathOverride
	if path == "" {
		t.Fatal("seedClaudeCodeSettingsParentDir: override not set")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir claudecode settings dir: %v", err)
	}
}

// seedCodexConfigParentDir is the codex analog of
// seedClaudeCodeSettingsParentDir.
func seedCodexConfigParentDir(t *testing.T) {
	t.Helper()
	path := connector.CodexConfigPathOverride
	if path == "" {
		t.Fatal("seedCodexConfigParentDir: override not set")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir codex config dir: %v", err)
	}
}

// isExternalDependencyError tests whether *err* indicates the test
// environment is missing a non-DefenseClaw binary the connector
// shells out to (e.g. a sandbox runner). The matrix should skip
// rather than fail in those cases — the contract under test is
// connector lifecycle round-trip, not external tooling availability.
func isExternalDependencyError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, marker := range []string{
		"executable file not found",
		"no such file or directory",
		"command not found",
		"permission denied",
		// OpenClaw connector Setup refuses when the gateway binary
		// was built without the bundled extension (i.e. without a
		// prior `make extensions`/`make plugin`). The connector-matrix
		// CI job runs `make sync-openclaw-extension` which writes a
		// .placeholder — enough to satisfy the //go:embed pattern at
		// compile time, but Setup still rejects the placeholder at
		// runtime. That's an environment-not-built issue, not a
		// contract violation, so skip rather than fail. Other
		// connectors (zeptoclaw / claudecode / codex) don't need the
		// extension and this branch never matches their errors.
		"openclaw extension is not bundled",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
