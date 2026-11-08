//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// GAP-0782: a cycle announces the scan of the config generation it starts on
// before it loads the config and scans (the first macOS cycle took 38 s), so
// a change that restarted the enumerator sees the new generation at once. A
// dry run publishes nothing.
func TestEnumerateCycleAnnouncesTheScanBeforeRunningIt(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		name := "cycle"
		if dryRun {
			name = "dry run"
		}
		t.Run(name, func(t *testing.T) {
			configBytes := []byte("guardrail:\n  connectors:\n    opencode: {}\n")
			sha := configwrite.SHA256Hex(configBytes)
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			configPath := filepath.Join(f.root, "config.yaml")
			t.Setenv(managed.ConfigPathEnv, configPath)
			if err := os.WriteFile(configPath, configBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(configwrite.GenerationState{Generation: 7, ConfigSHA256: sha})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configwrite.GenerationPath(configPath), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			oldLoader, oldResolver, oldLocal, oldDirectory, oldSessions := enterpriseHooksEnumerateConfigLoader,
				enterpriseHooksEnumerateResolver, enterpriseHooksEnumerateLocalAccounts,
				enterpriseHooksEnumerateDirectoryConfigured, enterpriseHookSessionUIDs
			oldManifest, oldEligible, oldUnprotected, oldRefused, oldStarted := enterpriseHooksEnumerateManifestWriter,
				enterpriseHooksEnumerateEligibleWriter, enterpriseHooksEnumerateUnprotectedWriter,
				enterpriseHooksEnumerateRefusedWriter, enterpriseHooksEnumerateScanStartedWriter
			t.Cleanup(func() {
				enterpriseHooksEnumerateConfigLoader, enterpriseHooksEnumerateResolver = oldLoader, oldResolver
				enterpriseHooksEnumerateLocalAccounts, enterpriseHooksEnumerateDirectoryConfigured = oldLocal, oldDirectory
				enterpriseHookSessionUIDs = oldSessions
				enterpriseHooksEnumerateManifestWriter, enterpriseHooksEnumerateEligibleWriter = oldManifest, oldEligible
				enterpriseHooksEnumerateUnprotectedWriter, enterpriseHooksEnumerateRefusedWriter = oldUnprotected, oldRefused
				enterpriseHooksEnumerateScanStartedWriter = oldStarted
			})
			var gotGen uint64
			var gotSHA string
			announced, announcedBeforeLoad := false, false
			enterpriseHooksEnumerateScanStartedWriter = func(_ string, generation uint64, digest string) error {
				announced, gotGen, gotSHA = true, generation, digest
				return nil
			}
			loaded := standaloneTestConfig(f.dataDir)
			enterpriseHooksEnumerateConfigLoader = func() (*config.Config, string, error) {
				announcedBeforeLoad = announced
				return loaded, sha, nil
			}
			enterpriseHooksEnumerateResolver = func(context.Context) unixidentity.Resolver { return resolver }
			enterpriseHooksEnumerateLocalAccounts = func(context.Context) (map[string]int, error) { return map[string]int{}, nil }
			enterpriseHooksEnumerateDirectoryConfigured = func() bool { return false }
			enterpriseHookSessionUIDs = func() []int { return nil }
			enterpriseHooksEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) { return false, nil }
			enterpriseHooksEnumerateEligibleWriter = func(string, []enterprisehooks.UnixEligibleAccount, []enterprisehooks.UnixEligibleAccount) error {
				return nil
			}
			enterpriseHooksEnumerateUnprotectedWriter = func(string, []enterprisehooks.UnprotectedAgent, uint64, string) error { return nil }
			enterpriseHooksEnumerateRefusedWriter = func(string, []enterprisehooks.UnixRefusedSurface) error { return nil }
			if _, err := runEnterpriseHooksEnumerateCycle(context.Background(), io.Discard, f.manifest,
				enterpriseHooksEnumerateOptions{manifest: f.manifest, descriptor: filepath.Join(f.root, "absent.json"), dryRun: dryRun},
				&enterprisehooks.UnixEnumeratorState{Version: 1}); err != nil {
				t.Fatal(err)
			}
			if dryRun {
				if announced {
					t.Fatal("a dry run announced a scan")
				}
				return
			}
			if !announced || !announcedBeforeLoad || gotGen != 7 || gotSHA != sha {
				t.Fatalf("announced=%v before the load=%v stamp=(%d, %q); want an announcement of (7, %q) before the config load",
					announced, announcedBeforeLoad, gotGen, gotSHA, sha)
			}
		})
	}
}
