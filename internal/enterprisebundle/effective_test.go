// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// A signer and an installed device must hash a bundled custom rule pack the
// same way, despite their distinct staging and version directory paths.
func TestBundleCustomGuardrailPackSignedDigestMatchesAppliedDigest(t *testing.T) {
	const pack = "policies/guardrail/custom/rules/local-patterns.yaml"
	const rules = "version: 1\ninjection: []\n"
	packRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(packRoot, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packRoot, "rules/local-patterns.yaml"), []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	packDigest, err := guardrail.RulePackDigest(packRoot)
	if err != nil {
		t.Fatal(err)
	}
	configYAML := strings.Replace(bundleConfig(t), "guardrail:\n", "guardrail:\n  rule_pack: custom\n  custom_packs:\n    custom:\n      path: policies/guardrail/custom\n      digest: sha256:"+packDigest+"\n", 1)
	f := newFixture(t, configYAML, func(in *enterprisebundle.ComposeInput) {
		in.Bundle.Files[pack] = []byte(rules)
		full := filepath.Join(in.Root, filepath.FromSlash(pack))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(rules), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	spki, err := x509.MarshalPKIXPublicKey(f.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	anchorsRaw, err := json.Marshal(enterprisebundle.Anchors{SchemaVersion: 1, TenantID: "acme", DeviceGroups: []string{"eng"}, Keys: []enterprisebundle.AnchorKey{{
		KeyID: "k1", Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(spki), Status: enterprisebundle.KeyActive,
		NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	anchorsPath := filepath.Join(root, "trust", enterprisebundle.AnchorsName)
	if err := os.MkdirAll(filepath.Dir(anchorsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchorsPath, anchorsRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	store := enterprisebundle.NewStore(filepath.Join(root, "bundles"), filepath.Join(root, "lifecycle"))
	t.Cleanup(func() {
		_ = filepath.WalkDir(store.BundlesDir, func(path string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(path, 0o755)
			}
			return nil
		})
	})
	driver := &enterprisebundle.Driver{Store: store, AnchorsPath: anchorsPath, Platform: "linux", ProductVersion: "1.0.2", Digester: digester, Now: func() time.Time { return verifyAt }}
	prepared, err := driver.Prepare(context.Background(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	versionRoot := store.VersionDir(prepared.Receipt.Dir)
	installedBundle, err := enterprisebundle.ReadDir(versionRoot)
	if err != nil {
		t.Fatal(err)
	}
	installedConfig, installedRaw, err := enterprisebundle.LoadConfig(installedBundle, versionRoot)
	if err != nil {
		t.Fatal(err)
	}
	deviceDigest, err := digester(context.Background(), installedConfig, installedRaw, "linux", versionRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Finish(prepared, prepared.ConfigSHA256, nil, enterprisebundle.GatewayPolicy{Digest: deviceDigest, Applied: true}, false, nil); err != nil {
		t.Fatal(err)
	}
	if rc := prepared.Receipt; rc.State != enterprisebundle.StateConfirmed || rc.ExpectedDigest != deviceDigest || rc.EffectivePolicyDigest != deviceDigest {
		t.Fatalf("signed expected %s, device computed %s, receipt %+v", rc.ExpectedDigest, deviceDigest, rc)
	}
}

const bundleConfigBase = `config_version: 9
deployment_mode: managed_enterprise
enterprise:
  profile: standalone
  tetragon:
    mode: observe
guardrail:
  enabled: true
  mode: observe
ai_discovery:
  enabled: true
  signature_packs:
    - discovery/signature-packs/team.json
  confidence_policy_path: discovery/confidence.yaml
  runtime:
    enabled: true
    enable_host_plane: true
`

// bundleConfig is the test bundle config with policy_dir at this checkout's
// built-in packs (a device has them in its install; the bundle does not
// carry them).
func bundleConfig(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(file), "..", "..", "policies")
	if _, err := os.Stat(filepath.Join(dir, "guardrail", "default")); err != nil {
		t.Skipf("policies not found: %v", err)
	}
	return bundleConfigBase + fmt.Sprintf("policy_dir: %q\n", dir)
}

// writeBundle writes the test bundle under a new directory and reads it.
func writeBundle(t *testing.T, configYAML string) (string, *enterprisebundle.Bundle) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "bundle")
	for name, body := range map[string]string{
		"config.yaml":                         configYAML,
		"discovery/signature-packs/team.json": `{"version":1}`,
		"discovery/confidence.yaml":           "version: 1\n",
	} {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := enterprisebundle.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, b
}

func digester(ctx context.Context, cfg *config.Config, raw []byte, goos, root string) (string, error) {
	policy, err := gateway.ComputeEffectivePolicyFor(ctx, cfg, gateway.EffectivePolicyOptions{GOOS: goos, BundleRoot: root, Raw: raw})
	return policy.Digest, err
}

// The same bundle digests the same wherever it is unpacked: the signer's
// working copy and the versioned directory a device installs it to give one
// digest per platform, and the platforms differ where their policy does (the
// kernel control set is Linux only).
func TestEffectivePolicyDigestsIgnoreTheBundleRoot(t *testing.T) {
	ctx := context.Background()
	signerRoot, signer := writeBundle(t, bundleConfig(t))
	deviceRoot, device := writeBundle(t, bundleConfig(t))
	if signerRoot == deviceRoot {
		t.Fatal("test needs two roots")
	}
	platforms := enterprisebundle.Platforms
	signed, err := enterprisebundle.EffectivePolicyDigests(ctx, signer, signerRoot, platforms, digester)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := enterprisebundle.EffectivePolicyDigests(ctx, device, deviceRoot, platforms, digester)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range platforms {
		if signed[platform] == "" || signed[platform] != installed[platform] {
			t.Fatalf("%s: signer %s, device %s", platform, signed[platform], installed[platform])
		}
	}
	if signed["linux"] == signed["darwin"] || signed["darwin"] != signed["windows"] {
		t.Fatalf("platform digests %v: want linux to differ (kernel policy) and darwin = windows", signed)
	}

	// An edited policy file moves the digest of every platform.
	if err := os.WriteFile(filepath.Join(deviceRoot, "discovery", "signature-packs", "team.json"), []byte(`{"version":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	edited, err := enterprisebundle.ReadDir(deviceRoot)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := enterprisebundle.EffectivePolicyDigests(ctx, edited, deviceRoot, platforms, digester)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range platforms {
		if moved[platform] == signed[platform] {
			t.Fatalf("%s: an edited signature pack kept the digest", platform)
		}
	}
}

// Golden: the bundle-root canonicalisation of a digest component. The
// signature pack component is sha256 over "<canonical path>=<file digest>",
// and the canonical path starts with ${bundle_root}, so this value is the
// same on every host, in every directory.
func TestEffectivePolicyComponentGolden(t *testing.T) {
	root, b := writeBundle(t, bundleConfig(t))
	cfg, raw, err := enterprisebundle.LoadConfig(b, root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), filepath.Join(root, "discovery", "confidence.yaml")) {
		t.Fatalf("rendered config does not point into the bundle:\n%s", raw)
	}
	policy, err := gateway.ComputeEffectivePolicyFor(context.Background(), cfg, gateway.EffectivePolicyOptions{GOOS: "linux", BundleRoot: root, Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	const key = "signature_pack:${bundle_root}/discovery/signature-packs/team.json"
	const golden = "sha256:9c216b6317e8cc15f1d63e88c6ff51c5cdeaf9bacec02391f91fc84a0a00dded"
	if got := policy.Components[key]; got != golden {
		t.Fatalf("component %s = %q, want %s (components %v)", key, got, golden, policy.Components)
	}
	if _, ok := policy.Components["kernel_policy"]; !ok {
		t.Fatalf("linux digest has no kernel_policy component: %v", policy.Components)
	}
	darwin, err := gateway.ComputeEffectivePolicyFor(context.Background(), cfg, gateway.EffectivePolicyOptions{GOOS: "darwin", BundleRoot: root, Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := darwin.Components["kernel_policy"]; ok {
		t.Fatal("darwin digest has a kernel_policy component")
	}
	for key := range policy.Components {
		if strings.Contains(key, root) {
			t.Fatalf("component key %s holds the bundle root", key)
		}
	}
}

func TestRenderConfig(t *testing.T) {
	root, b := writeBundle(t, bundleConfig(t))
	b.Files["config.yaml"] = []byte(bundleConfig(t) + "x:\n  glob: discovery/signature-packs/*.json\n  other: policies-not-a-bundle-path\n")
	raw, err := enterprisebundle.RenderConfig(b, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		filepath.Join(root, "discovery", "signature-packs", "team.json"),
		filepath.Join(root, "discovery", "signature-packs", "*.json"),
		"policies-not-a-bundle-path",
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("rendered config lacks %s:\n%s", want, raw)
		}
	}
	for name, extra := range map[string]string{
		"missing file":   "x: policies/guardrail/absent\n",
		"traversal":      "x: discovery/../../etc/passwd\n",
		"pattern in dir": "x: discovery/*/team.json\n",
	} {
		t.Run(name, func(t *testing.T) {
			b.Files["config.yaml"] = []byte(bundleConfig(t) + extra)
			_, err := enterprisebundle.RenderConfig(b, root)
			if code := enterprisebundle.CodeOf(err); code != enterprisebundle.CodeFileMissing && code != enterprisebundle.CodeConfigInvalid {
				t.Fatalf("got %v, want file_missing or config_invalid", err)
			}
		})
	}
}
