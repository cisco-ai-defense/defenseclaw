// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// A device that takes a settings-only bundle, then a bundle that adds one
// policy file, then a settings-only bundle again: for each one the digest
// the signer computes is the digest the gateway computes from the installed
// config, and each delivery changes it.
func TestBundleDigestsMatchGatewayAcrossSettingsFileSettingsSequence(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	packs := filepath.Join(filepath.Dir(file), "..", "..", "policies", "guardrail", "default")
	if _, err := os.Stat(packs); err != nil {
		t.Skipf("policies not found: %v", err)
	}
	configDir, dataDir := t.TempDir(), t.TempDir()
	if err := os.CopyFS(filepath.Join(dataDir, "policies", "guardrail", "default"), os.DirFS(packs)); err != nil {
		t.Fatal(err)
	}
	layout := enterprisebundle.DeviceLayout{ConfigPath: filepath.Join(configDir, "config.yaml"), DataDir: dataDir, PolicyDir: filepath.Join(dataDir, "policies")}
	settings := func(blockAt string) string {
		return "config_version: 9\ndata_dir: " + dataDir + "\nguardrail:\n  enabled: true\n  mode: action\n  block_at: " + blockAt +
			"\n  connectors:\n    codex: {}\n    claudecode: {}\n"
	}
	steps := []struct {
		name  string
		files map[string][]byte
	}{
		{"settings only", map[string][]byte{enterprisebundle.ConfigName: []byte(settings("MEDIUM"))}},
		{"one policy file", map[string][]byte{
			enterprisebundle.ConfigName: []byte(settings("MEDIUM") + "ai_discovery:\n  confidence_policy_path: discovery/confidence.yaml\n"),
			"discovery/confidence.yaml": []byte("version: 1\n"),
		}},
		{"settings only again", map[string][]byte{enterprisebundle.ConfigName: []byte(settings("HIGH"))}},
	}
	seen := map[string]string{}
	for i, step := range steps {
		version := uint64(i + 1)
		b := &enterprisebundle.Bundle{Files: step.files}
		stage, cleanup, err := stageBundle(b)
		if err != nil {
			t.Fatal(err)
		}
		stagedCfg, stagedRaw, err := enterprisebundle.LoadConfigForDeviceLayout(b, stage, runtime.GOOS, layout)
		if err != nil {
			cleanup()
			t.Fatalf("%s: %v", step.name, err)
		}
		signed, err := bundleDigester(context.Background(), stagedCfg, stagedRaw, runtime.GOOS, stage)
		cleanup()
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}

		bundleID := fmt.Sprintf("b-01J9ZK3Q4R5S6T7V8W9X0Y1Z%02d", i)
		versionDir := filepath.Join(configDir, enterprisebundle.BundlesDirName, enterprisebundle.VersionDirNameForReceipt(version, bundleID, bundleID))
		for name, content := range step.files {
			path := filepath.Join(versionDir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			writeBundleTestFile(t, path, content)
		}
		installed, err := enterprisebundle.RenderConfig(b, versionDir)
		if err != nil {
			t.Fatal(err)
		}
		writeBundleTestFile(t, layout.ConfigPath, installed)
		sum := sha256.Sum256(installed)
		writeBundleTestFile(t, filepath.Join(configDir, "config.generation.json"), fmt.Appendf(nil,
			`{"generation":%d,"config_sha256":"%x","actor":"bundle:%s","written_at":"2026-10-21T00:00:00Z","bundle_id":%q,"bundle_version":%d,"signer_key_id":"k1"}`,
			10+i, sum, bundleID, bundleID, version))
		deviceCfg, err := config.LoadRuntimeV8InspectionCandidateForLayout(layout.ConfigPath, installed, layout.DataDir, runtime.GOOS)
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		live, err := gateway.ComputeEffectivePolicyFor(context.Background(), deviceCfg, gateway.EffectivePolicyOptions{Raw: installed})
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if live.Digest != signed {
			t.Fatalf("%s: gateway digest %s != signed digest %s (gateway components %v)", step.name, live.Digest, signed, live.Components)
		}
		if previous, ok := seen[signed]; ok {
			t.Fatalf("%s has the digest of %s", step.name, previous)
		}
		seen[signed] = step.name
	}
}
