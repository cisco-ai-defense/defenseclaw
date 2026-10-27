// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-1945: the sysctls allow user namespaces, but a container seccomp
// profile (or another sandbox) refuses the one the contained probe needs, so
// the probe never runs. That is the GAP-1525 case: a sealed registration stays
// current, an edited script does not, and a probe that ran and failed is
// never read as unavailable.
func TestHermesRegistrationStaysCurrentWhenTheHostRefusesTheProbeNamespace(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root needs no user namespace for the probe")
	}
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	previous, previousCheck := HermesConfigPathOverride, hermesExecutionContainmentUnavailable
	HermesConfigPathOverride = configPath
	// The sysctls say nothing: only the namespace creation is refused.
	hermesExecutionContainmentUnavailable = func() string { return "" }
	t.Cleanup(func() { HermesConfigPathOverride, hermesExecutionContainmentUnavailable = previous, previousCheck })

	opts := SetupOpts{DataDir: filepath.Join(root, "dc")}
	script := filepath.Join(opts.DataDir, "hooks", "hermes-hook.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	// It fails the proof whenever it runs.
	body := []byte("#!/bin/sh\nexit 1\n")
	if err := os.WriteFile(script, body, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := patchHermesHooks(configPath, script, ""); err != nil {
		t.Fatal(err)
	}
	if err := patchHermesAllowlist(filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName),
		hermesConfiguredHookCommand(script, ""), script); err != nil {
		t.Fatal(err)
	}
	if err := SaveHookContractLockEntry(opts.DataDir, HookContractLockEntry{
		Connector:         "hermes",
		HookScriptDigests: map[string]string{"hermes-hook.sh": "sha256:" + sha256Hex(body)},
	}); err != nil {
		t.Fatal(err)
	}
	conn := NewHermesConnector()
	// The probe can run here: it ran and failed, so the registration is not current.
	if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("sealed registration whose probe ran and failed present=%v err=%v, want absent", present, err)
	}
	// The launcher's namespace creation is refused (the processutil test hook).
	t.Setenv("DC_PROCESSUTIL_TEST_FAIL_NAMESPACE", "1")
	if present, err := conn.ownedHookContractPresent(opts); err != nil || !present {
		t.Fatalf("sealed registration on a host that refuses the probe namespace present=%v err=%v, want current", present, err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("edited script on a host that refuses the probe namespace present=%v err=%v, want absent", present, err)
	}
}
