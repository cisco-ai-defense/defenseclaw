//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestGAP0083PendingHermesDigestIsScopedToInstallReadback(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	configPath := filepath.Join(root, "hermes", "config.yaml")
	previousConfig := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previousConfig })
	previousProbe := hermesExecutionContainmentUnavailable
	hermesExecutionContainmentUnavailable = func() string { return "test host has no contained probe" }
	t.Cleanup(func() { hermesExecutionContainmentUnavailable = previousProbe })

	opts := SetupOpts{DataDir: filepath.Join(root, "dc")}
	script := filepath.Join(opts.DataDir, "hooks", "hermes-hook.sh")
	if err := os.MkdirAll(filepath.Dir(script), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("#!/bin/sh\nexit 0\n")
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
	pending := HookContractLockEntry{
		Connector: "hermes",
		HookScriptDigests: map[string]string{
			"hermes-hook.sh": "sha256:" + sha256Hex(body),
		},
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
		t.Fatalf("ordinary read-back before publication = %v, %v; want absent", present, err)
	}
	if present, err := OwnedHooksPresentForPendingInstall(conn, opts, pending); err != nil || !present {
		t.Fatalf("pending install read-back = %v, %v; want present", present, err)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
		t.Fatalf("ordinary read-back after pending check = %v, %v; want absent", present, err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if present, err := OwnedHooksPresentForPendingInstall(conn, opts, pending); err != nil || present {
		t.Fatalf("changed script with pending digest = %v, %v; want absent", present, err)
	}
	pending.Connector = "codex"
	if present, err := OwnedHooksPresentForPendingInstall(conn, opts, pending); err == nil || present {
		t.Fatalf("other connector's pending digest = %v, %v; want refused", present, err)
	}
}
