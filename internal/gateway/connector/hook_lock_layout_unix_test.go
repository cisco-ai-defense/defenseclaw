// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0833: the CLI's doctor and fail-mode readers find a connector's sealed
// hook script in the lock's hook_script_paths. The lock lists the shared
// inspect-*.sh runtime and _hardening.sh beside each connector's own script,
// and doctor's Hermes probe once accepted the Hermes script alone, so every
// Hermes setup and upgrade failed doctor. The CLI tests seal the Hermes
// layout pinned here (_GATEWAY_HERMES_LOCKED_SCRIPTS in
// cli/tests/test_doctor_hermes_execution_probe.py); change both together.
func TestHookContractLockSealsEachConnectorScriptBesideTheSharedRuntime(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	testenv.SetHome(t, filepath.Join(root, "home"))
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = filepath.Join(root, "hermes", "config.yaml")
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	opts := SetupOpts{DataDir: filepath.Join(root, "dc"), APIAddr: "127.0.0.1:18970"}
	hooks := filepath.Join(opts.DataDir, "hooks")

	got := NewHookContractLockEntry(opts, NewHermesConnector(), "test-build").Locations.HookScriptPaths
	var want []string
	for _, name := range []string{
		"inspect-tool.sh", "inspect-request.sh", "inspect-response.sh", "inspect-tool-response.sh",
		"hermes-hook.sh", "_hardening.sh",
	} {
		want = append(want, filepath.Join(hooks, name))
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Hermes hook_script_paths = %v, want %v", got, want)
	}

	// Every connector with its own data-dir hook script seals it exactly
	// once, at this install's hooks folder: the readers look it up by that path.
	for _, conn := range newBuiltinConnectors() {
		owner, ok := conn.(HookScriptOwner)
		if _, plugin := conn.(HookRuntimeArtifactProvider); !ok || plugin {
			continue // Amp's runtime is its plugin, not data-dir scripts
		}
		paths := NewHookContractLockEntry(opts, conn, "test-build").Locations.HookScriptPaths
		for _, name := range owner.HookScriptNames(opts) {
			var found []string
			for _, path := range paths {
				if filepath.Base(path) == name {
					found = append(found, path)
				}
			}
			if !slices.Equal(found, []string{filepath.Join(hooks, name)}) {
				t.Errorf("%s: %s sealed at %v, want once at %s (all: %v)", conn.Name(), name, found, hooks, paths)
			}
		}
	}
}

// GAP-0833: an upgrade from 1.0.2 finds the 1.0.2 Hermes hook, which has no
// execution-probe branch. Verify must not take it as current, and the new
// gateway's Setup must render the current hook and seal its bytes, so the
// registration the agent runs is the one the lock and doctor check.
func TestHermesSetupOverA102HookRendersAndSealsTheCurrentScript(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	conn := NewHermesConnector()
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
		DataDir:  filepath.Join(root, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	})
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	script := filepath.Join(opts.DataDir, "hooks", "hermes-hook.sh")
	// The 1.0.2 hook: same path and registration, no probe branch.
	if err := os.WriteFile(script, []byte("#!/bin/sh\n# defenseclaw-managed-hook v5\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
		t.Fatalf("OwnedHooksPresent with the 1.0.2 hook = %v, %v; want absent", present, err)
	}

	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup after the upgrade: %v", err)
	}
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "--defenseclaw-execution-probe") {
		t.Fatalf("Setup left the 1.0.2 hook in place:\n%s", body)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("OwnedHooksPresent after the upgrade Setup = %v, %v; want present", present, err)
	}
	entry := NewHookContractLockEntry(opts, conn, "test-build")
	sum := sha256.Sum256(body)
	if got, want := entry.HookScriptDigests["hermes-hook.sh"], "sha256:"+hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("sealed hermes-hook.sh digest = %q, want %q of the rendered hook", got, want)
	}
	if !slices.Contains(entry.Locations.HookScriptPaths, script) {
		t.Fatalf("hook_script_paths = %v, want %s", entry.Locations.HookScriptPaths, script)
	}
}
