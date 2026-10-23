// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// gatewayDigester is the production digester (bundle sign and the staged
// verifier): the gateway's effective policy with the bundle root set.
func gatewayDigester(ctx context.Context, cfg *config.Config, raw []byte, goos, root string) (string, error) {
	policy, err := gateway.ComputeEffectivePolicyFor(ctx, cfg, gateway.EffectivePolicyOptions{GOOS: goos, BundleRoot: root, Raw: raw})
	if err == nil {
		enterprisebundle.ReportPolicyComponents(ctx, policy.Components)
	}
	return policy.Digest, err
}

// A bundle whose config.yaml names no file under the bundle directory goes
// through the real store (receive, stage, promote), the real digester on the
// staged copy, and the installed config recorded as the lifecycle records it.
// The digest the gateway then computes from the installed config alone must
// equal the staged one, or the apply never confirms (digest_mismatch).
func TestSettingsOnlyBundleStagedDigestMatchesGateway(t *testing.T) {
	for _, identicalBase := range []bool{false, true} {
		t.Run(fmt.Sprintf("identical-base=%t", identicalBase), func(t *testing.T) {
			testSettingsOnlyBundleStagedDigestMatchesGateway(t, identicalBase)
		})
	}
}

func testSettingsOnlyBundleStagedDigestMatchesGateway(t *testing.T, identicalBase bool) {
	_, here, _, _ := runtime.Caller(0)
	srcPack := filepath.Join(filepath.Dir(here), "..", "..", "policies", "guardrail", "default")
	root := t.TempDir()
	dataDir := filepath.Join(root, "runtime")
	if err := os.CopyFS(filepath.Join(dataDir, "policies", "guardrail", "default"), os.DirFS(srcPack)); err != nil {
		t.Fatal(err)
	}
	b := &enterprisebundle.Bundle{Files: map[string][]byte{enterprisebundle.ConfigName: []byte("config_version: 9\ndata_dir: " + dataDir +
		"\nguardrail:\n  enabled: true\n  mode: action\n  block_at: MEDIUM\n  connectors:\n    codex: {}\n    claudecode: {}\n")}}

	etc := filepath.Join(root, "etc")
	store := enterprisebundle.NewStore(filepath.Join(etc, enterprisebundle.BundlesDirName), filepath.Join(root, "lifecycle"))
	// Sealed version directories are read-only, which TempDir cannot remove;
	// the seal does not change any digested byte.
	store.SealVersion = func(string) error { return nil }
	const bundleID = "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z3F"
	rc, err := store.Receive(bundleID, 6, "")
	if err != nil {
		t.Fatal(err)
	}
	staging, err := store.Stage(rc, b)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	configPath := filepath.Join(etc, "config.yaml")
	// The device verifier loads the staged copy with the installed layout.
	layout := enterprisebundle.DeviceLayout{ConfigPath: configPath, DataDir: dataDir}
	stagedCfg, stagedRaw, err := enterprisebundle.LoadConfigForDeviceLayout(b, staging, runtime.GOOS, layout)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := gatewayDigester(ctx, stagedCfg, stagedRaw, runtime.GOOS, staging)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Advance(rc, enterprisebundle.StateVerified, func(r *enterprisebundle.Receipt) {
		r.SignerKeyID, r.Principal = "k1", "control-plane:t1/alice"
	}); err != nil {
		t.Fatal(err)
	}
	versionDir, err := store.Promote(rc)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := enterprisebundle.RenderConfig(b, versionDir)
	if err != nil {
		t.Fatal(err)
	}
	if names := enterprisebundle.VersionDirsNamed(installed, store.BundlesDir); len(names) != 0 {
		t.Fatalf("settings-only config names version directories %v", names)
	}
	opt, ok := enterprisebundle.GenerationOptions(rc)
	if !ok {
		t.Fatal("receipt has no principal to record")
	}
	if identicalBase {
		if err := os.WriteFile(configPath, installed, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := configwrite.ReplaceDocument(ctx, configPath, installed, opt); err != nil {
		t.Fatal(err)
	}

	// The gateway loads the installed config with the same device layout.
	deviceCfg, err := config.LoadRuntimeV8InspectionCandidateForLayout(configPath, installed, layout.DataDir, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	live, err := gateway.ComputeEffectivePolicyFor(ctx, deviceCfg, gateway.EffectivePolicyOptions{Raw: installed})
	if err != nil {
		t.Fatal(err)
	}
	if err := enterprisebundle.ConfirmPolicyDigests(staged, staged, live.Digest, true); err != nil || live.Digest != staged {
		t.Fatalf("gateway digest %s, staged digest %s: %v (gateway components %v)", live.Digest, staged, err, live.Components)
	}
}
