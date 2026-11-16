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

// The digest the staged verifier computes (bundleDigester, with the staging
// copy as bundle root and the device layout) equals the digest the device's
// gateway computes for the installed settings-only config, which names no
// bundle file (GAP-0158). The lifecycle confirms an apply only when these two
// agree.
func TestBundleDigesterMatchesGatewayForSettingsOnlyBundle(t *testing.T) {
	packs := filepath.Join(cliTestRepoRoot(t), "policies", "guardrail", "default")
	if _, err := os.Stat(packs); err != nil {
		t.Skipf("policies not found: %v", err)
	}
	configDir, dataDir := t.TempDir(), t.TempDir()
	if err := os.CopyFS(filepath.Join(dataDir, "policies", "guardrail", "default"), os.DirFS(packs)); err != nil {
		t.Fatal(err)
	}
	layout := enterprisebundle.DeviceLayout{ConfigPath: filepath.Join(configDir, "config.yaml"), DataDir: dataDir, PolicyDir: filepath.Join(dataDir, "policies")}
	b := &enterprisebundle.Bundle{Files: map[string][]byte{enterprisebundle.ConfigName: []byte("config_version: 9\ndata_dir: " + dataDir +
		"\nguardrail:\n  enabled: true\n  mode: action\n  block_at: MEDIUM\n  connectors:\n    codex: {}\n    claudecode: {}\n")}}

	// Staged verifier: a private working copy is the bundle root.
	stage, cleanup, err := stageBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	stagedCfg, stagedRaw, err := enterprisebundle.LoadConfigForDeviceLayout(b, stage, runtime.GOOS, layout)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := bundleDigester(context.Background(), stagedCfg, stagedRaw, runtime.GOOS, stage)
	if err != nil {
		t.Fatal(err)
	}

	// Device: apply renders config.yaml against the receipt's version
	// directory and records the bundle in config.generation.json.
	const bundleID, receiptID = "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z2A", "r-01J9ZK3Q4R5S6T7V8W9X0Y1Z2B"
	versionDir := filepath.Join(configDir, enterprisebundle.BundlesDirName, enterprisebundle.VersionDirNameForReceipt(5, bundleID, receiptID))
	if err := os.MkdirAll(versionDir, 0o700); err != nil {
		t.Fatal(err)
	}
	installed, err := enterprisebundle.RenderConfig(b, versionDir)
	if err != nil {
		t.Fatal(err)
	}
	writeBundleTestFile(t, layout.ConfigPath, installed)
	sum := sha256.Sum256(installed)
	writeBundleTestFile(t, filepath.Join(configDir, "config.generation.json"), fmt.Appendf(nil,
		`{"generation":4,"config_sha256":"%x","actor":"bundle:%s","written_at":"2026-10-18T00:00:00Z","bundle_id":%q,"bundle_version":5,"signer_key_id":"k1"}`,
		sum, bundleID, bundleID))
	// This device's managed layout is the temporary one above, so its
	// gateway loads the installed config with that layout's defaults.
	deviceCfg, err := config.LoadRuntimeV8InspectionCandidateForLayout(layout.ConfigPath, installed, layout.DataDir, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	// The running gateway and `policy digest` pass no bundle root.
	live, err := gateway.ComputeEffectivePolicyFor(context.Background(), deviceCfg, gateway.EffectivePolicyOptions{Raw: installed})
	if err != nil {
		t.Fatal(err)
	}
	if live.Digest != signed {
		staged, _ := gateway.ComputeEffectivePolicyFor(context.Background(), stagedCfg, gateway.EffectivePolicyOptions{GOOS: runtime.GOOS, BundleRoot: stage, Raw: stagedRaw})
		t.Fatalf("gateway digest %s != staged digest %s\ngateway components %v\nstaged components  %v", live.Digest, signed, live.Components, staged.Components)
	}
}
