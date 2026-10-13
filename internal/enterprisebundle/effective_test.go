// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

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
