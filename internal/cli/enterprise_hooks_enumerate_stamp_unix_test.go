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

// The completed scan is stamped with the digest of the bytes the config
// load parsed (GAP-0640). A digest read in a separate step could name a file
// edited and restored around the load, and a generation number can repeat
// after the record is rebuilt; so the stamp is the loader digest, and the
// number counts only while the generation record named the same bytes.
func TestEnumerateCycleStampsScanWithTheBytesTheLoadParsed(t *testing.T) {
	configA := []byte("guardrail:\n  connectors:\n    opencode: {}\n")
	configB := []byte("guardrail:\n  connectors: {}\n")
	shaA, shaB := configwrite.SHA256Hex(configA), configwrite.SHA256Hex(configB)
	cases := []struct {
		name      string
		record    *configwrite.GenerationState
		loaderSHA string
		wantGen   uint64
		wantSHA   string
	}{
		{"loaded the bytes the record names", &configwrite.GenerationState{Generation: 7, ConfigSHA256: shaA}, shaA, 7, shaA},
		{"file changed between the snapshot and the load", &configwrite.GenerationState{Generation: 7, ConfigSHA256: shaA}, shaB, 0, ""},
		{"loader reports no digest", &configwrite.GenerationState{Generation: 7, ConfigSHA256: shaA}, "", 0, ""},
		{"no generation record", nil, shaA, 0, ""},
		{"record without a digest", &configwrite.GenerationState{Generation: 7}, shaA, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
			f := newStandaloneFixture(t, resolver)
			configPath := filepath.Join(f.root, "config.yaml")
			t.Setenv(managed.ConfigPathEnv, configPath)
			if err := os.WriteFile(configPath, configA, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.record != nil {
				raw, err := json.Marshal(tc.record)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(configwrite.GenerationPath(configPath), raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			oldLoader, oldResolver, oldLocal, oldDirectory, oldSessions := enterpriseHooksEnumerateConfigLoader,
				enterpriseHooksEnumerateResolver, enterpriseHooksEnumerateLocalAccounts,
				enterpriseHooksEnumerateDirectoryConfigured, enterpriseHookSessionUIDs
			oldManifest, oldEligible, oldUnprotected, oldRefused := enterpriseHooksEnumerateManifestWriter,
				enterpriseHooksEnumerateEligibleWriter, enterpriseHooksEnumerateUnprotectedWriter,
				enterpriseHooksEnumerateRefusedWriter
			t.Cleanup(func() {
				enterpriseHooksEnumerateConfigLoader, enterpriseHooksEnumerateResolver = oldLoader, oldResolver
				enterpriseHooksEnumerateLocalAccounts, enterpriseHooksEnumerateDirectoryConfigured = oldLocal, oldDirectory
				enterpriseHookSessionUIDs = oldSessions
				enterpriseHooksEnumerateManifestWriter, enterpriseHooksEnumerateEligibleWriter = oldManifest, oldEligible
				enterpriseHooksEnumerateUnprotectedWriter, enterpriseHooksEnumerateRefusedWriter = oldUnprotected, oldRefused
			})
			loaded := standaloneTestConfig(f.dataDir)
			enterpriseHooksEnumerateConfigLoader = func() (*config.Config, string, error) { return loaded, tc.loaderSHA, nil }
			enterpriseHooksEnumerateResolver = func(context.Context) unixidentity.Resolver { return resolver }
			enterpriseHooksEnumerateLocalAccounts = func(context.Context) (map[string]int, error) { return map[string]int{}, nil }
			enterpriseHooksEnumerateDirectoryConfigured = func() bool { return false }
			enterpriseHookSessionUIDs = func() []int { return nil }
			enterpriseHooksEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) { return false, nil }
			enterpriseHooksEnumerateEligibleWriter = func(string, []enterprisehooks.UnixEligibleAccount, []enterprisehooks.UnixEligibleAccount) error {
				return nil
			}
			var gotGen uint64
			var gotSHA string
			published := false
			enterpriseHooksEnumerateUnprotectedWriter = func(_ string, _ []enterprisehooks.UnprotectedAgent, generation uint64, sha string) error {
				published, gotGen, gotSHA = true, generation, sha
				return nil
			}
			enterpriseHooksEnumerateRefusedWriter = func(string, []enterprisehooks.UnixRefusedSurface) error { return nil }
			if _, err := runEnterpriseHooksEnumerateCycle(context.Background(), io.Discard, f.manifest,
				enterpriseHooksEnumerateOptions{manifest: f.manifest, descriptor: filepath.Join(f.root, "absent.json")},
				&enterprisehooks.UnixEnumeratorState{Version: 1}); err != nil {
				t.Fatal(err)
			}
			if !published || gotGen != tc.wantGen || gotSHA != tc.wantSHA {
				t.Fatalf("scan stamp = (published %v, generation %d, digest %q); want (generation %d, digest %q)",
					published, gotGen, gotSHA, tc.wantGen, tc.wantSHA)
			}
		})
	}
}
