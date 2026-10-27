// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// writeBundleRecord records raw at configPath as installed from bundleID at
// version (config.generation.json next to config.yaml).
func writeBundleRecord(t *testing.T, configPath string, raw []byte, bundleID string, version uint64) {
	t.Helper()
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	record := fmt.Sprintf(`{"generation":3,"config_sha256":"%x","actor":"bundle:%s","written_at":"2026-10-18T00:00:00Z","bundle_id":%q,"bundle_version":%d,"signer_key_id":"k1"}`,
		sum, bundleID, bundleID, version)
	if err := os.WriteFile(filepath.Join(filepath.Dir(configPath), "config.generation.json"), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A bundle whose config.yaml names no file under the bundle directory (only
// settings) is digested in the bundle scope with no bundle root passed in:
// the gateway leaves out the device's rule packs and digests the guardrail
// policy as the signer and the staged verifier do, so its digest equals the
// signed one and the apply confirms instead of rolling back.
func TestGenerationSettingsOnlyBundleDigestsInBundleScope(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	srcPack := filepath.Join(filepath.Dir(here), "..", "..", "policies", "guardrail", "default")
	root := t.TempDir()
	dataDir := filepath.Join(root, "runtime")
	if err := os.CopyFS(filepath.Join(dataDir, "policies", "guardrail", "default"), os.DirFS(srcPack)); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.yaml")
	const bundleID = "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z3D"
	raw := []byte("config_version: 9\ndata_dir: " + dataDir + "\nguardrail:\n  enabled: true\n  mode: action\n  block_at: HIGH\n  connectors:\n    codex: {}\n")
	writeBundleRecord(t, configPath, raw, bundleID, 12)
	cfg, err := config.LoadRuntimeV8InspectionCandidateFromBytes(configPath, raw)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	signed, err := ComputeEffectivePolicyFor(context.Background(), cfg, EffectivePolicyOptions{BundleRoot: t.TempDir(), Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	live, err := ComputeEffectivePolicyFor(context.Background(), cfg, EffectivePolicyOptions{Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	if live.Digest != signed.Digest {
		t.Fatalf("gateway digest %s != signed digest %s\ngateway=%v\nsigned=%v", live.Digest, signed.Digest, live.Components, signed.Components)
	}
	if live.Components["guardrail_policy"] == "" || live.Components["guardrail_policy"] != signed.Components["guardrail_policy"] {
		t.Fatalf("guardrail_policy: gateway %q, signed %q", live.Components["guardrail_policy"], signed.Components["guardrail_policy"])
	}
	for key := range live.Components {
		if strings.HasPrefix(key, "rule_pack:") {
			t.Fatalf("settings-only bundle digest kept the device rule pack %s", key)
		}
	}
}

// The installed config of a bundle names at most one version directory, and
// that directory must exist: either fault fails the build instead of
// digesting outside the bundle scope.
func TestGenerationBundleVersionDirectoryFaults(t *testing.T) {
	const bundleID = "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z3E"
	for name, tc := range map[string]struct {
		dirs    []string
		create  bool
		wantErr string
	}{
		"named directory missing": {dirs: []string{enterprisebundle.VersionDirNameForReceipt(4, bundleID, bundleID)}, wantErr: "is unavailable"},
		"two directories named": {dirs: []string{enterprisebundle.VersionDirNameForReceipt(4, bundleID, bundleID), enterprisebundle.VersionDirName(4, bundleID)},
			create: true, wantErr: "more than one bundle version directory"},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "config.yaml")
			var paths []string
			for _, dir := range tc.dirs {
				full := filepath.Join(root, enterprisebundle.BundlesDirName, dir)
				if tc.create {
					if err := os.MkdirAll(full, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				paths = append(paths, filepath.Join(full, "plugins"))
			}
			raw := []byte("config_version: 9\nplugin_dir: " + paths[0] + "\n")
			if len(paths) > 1 {
				raw = append(raw, []byte("policy_dir: "+paths[1]+"\n")...)
			}
			writeBundleRecord(t, configPath, raw, bundleID, 4)
			cfg := &config.Config{ConfigFilePath: configPath, DataDir: filepath.Join(root, "runtime"), PluginDir: paths[0]}
			_, err := ComputeEffectivePolicyFor(context.Background(), cfg, EffectivePolicyOptions{Raw: raw})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// GAP-1853: a YAML comment that names a bundle version directory is not
// configuration. It neither fails the build on a directory that does not
// exist nor counts as a second directory next to the one a value names.
func TestGenerationBundleVersionDirectoryIgnoresComments(t *testing.T) {
	const bundleID = "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z3F"
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yaml")
	bundles := filepath.Join(root, enterprisebundle.BundlesDirName)
	used := filepath.Join(bundles, enterprisebundle.VersionDirNameForReceipt(6, bundleID, bundleID))
	if err := os.MkdirAll(used, 0o700); err != nil {
		t.Fatal(err)
	}
	comment := "# note " + filepath.Join(bundles, enterprisebundle.VersionDirName(6, bundleID)) + "\n"
	for name, raw := range map[string]string{
		"comment only":            "config_version: 9\n" + comment,
		"comment next to a value": "config_version: 9\nplugin_dir: " + filepath.Join(used, "plugins") + "\n" + comment,
	} {
		t.Run(name, func(t *testing.T) {
			writeBundleRecord(t, configPath, []byte(raw), bundleID, 6)
			cfg := &config.Config{ConfigFilePath: configPath, DataDir: filepath.Join(root, "runtime")}
			if _, err := ComputeEffectivePolicyFor(context.Background(), cfg, EffectivePolicyOptions{Raw: []byte(raw)}); err != nil {
				t.Fatalf("a comment naming a version directory failed the build: %v", err)
			}
		})
	}
}
