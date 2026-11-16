// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-1525: with unprivileged user namespaces disabled the contained probe
// cannot run, and a sealed, current Hermes registration read back as absent:
// reconcile exited 3 and the gateway start failed on Hermes. Without
// containment the registration stays current while its script keeps the
// digest setup sealed; an edited script is still not current.
func TestHermesRegistrationStaysCurrentWhereTheContainedProbeCannotRun(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	previous, previousCheck := HermesConfigPathOverride, hermesExecutionContainmentUnavailable
	HermesConfigPathOverride = configPath
	hermesExecutionContainmentUnavailable = func() string {
		return "unprivileged user namespaces are disabled (user.max_user_namespaces=0)"
	}
	t.Cleanup(func() { HermesConfigPathOverride, hermesExecutionContainmentUnavailable = previous, previousCheck })

	opts := SetupOpts{DataDir: filepath.Join(root, "dc")}
	script := filepath.Join(opts.DataDir, "hooks", "hermes-hook.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	// It would fail the proof if it ran: it must not run.
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
	conn := NewHermesConnector()
	if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("unsealed registration present=%v err=%v, want absent", present, err)
	}
	if err := SaveHookContractLockEntry(opts.DataDir, HookContractLockEntry{
		Connector:         "hermes",
		HookScriptDigests: map[string]string{"hermes-hook.sh": "sha256:" + sha256Hex(body)},
	}); err != nil {
		t.Fatal(err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err != nil || !present {
		t.Fatalf("sealed registration without containment present=%v err=%v, want current", present, err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("edited script without containment present=%v err=%v, want absent", present, err)
	}
}
