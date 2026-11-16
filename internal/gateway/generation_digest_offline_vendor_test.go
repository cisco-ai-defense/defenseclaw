// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// An administrator signs a settings-only bundle made from a shipped managed
// template plus one tested change on a workstation that has no DefenseClaw
// install. The template sets policy_dir to the administrator folder, whose
// missing default pack falls back to the vendor folder, so the signer must
// load the shipped packs this binary embeds instead of its own /opt tree,
// and its digest must equal the one the device computes for the installed
// config (GAP-0223). The test runs on every CI host OS, so a Windows, macOS
// and Linux signer are all covered.
func TestOfflineSignShippedTemplateMatchesDeviceDigest(t *testing.T) {
	for _, tc := range []struct{ goos, template string }{
		{"linux", "linux-standalone.yaml"},
		{"darwin", "macos-standalone.yaml"},
	} {
		t.Run(tc.goos, func(t *testing.T) {
			b := shippedTemplateBundle(t, tc.template, false)
			var signed map[string]string
			var err error
			stderr := captureStderr(t, func() {
				signed, err = enterprisebundle.EffectivePolicyDigests(context.Background(), b, t.TempDir(), []string{tc.goos}, offlineTestDigester)
			})
			if strings.Contains(stderr, "OPA policy unavailable") {
				t.Fatalf("sign %s printed an OPA warning for the target policy_dir (GAP-0239): %s", tc.goos, stderr)
			}
			if err != nil {
				t.Fatalf("sign %s from %s: %v", tc.goos, tc.template, err)
			}
			if device := deviceBundleDigest(t, b, tc.goos); device != signed[tc.goos] {
				t.Fatalf("device digest %s != signed %s", device, signed[tc.goos])
			}
		})
	}

	// The Linux template's data_dir is the Linux one, so a macOS or Windows
	// target is refused for that setting, never for a rule pack the signer
	// lacks. Without data_dir and policy_dir the same settings sign for all
	// three platforms and match the Linux and macOS devices.
	b := shippedTemplateBundle(t, "linux-standalone.yaml", false)
	for _, goos := range []string{"darwin", "windows"} {
		_, err := enterprisebundle.EffectivePolicyDigests(context.Background(), b, t.TempDir(), []string{goos}, offlineTestDigester)
		if err == nil || !strings.Contains(err.Error(), "data_dir") || strings.Contains(err.Error(), "rule pack") {
			t.Fatalf("sign the Linux template for %s: %v, want the data_dir refusal", goos, err)
		}
	}
	portable := shippedTemplateBundle(t, "linux-standalone.yaml", true)
	var signed map[string]string
	var err error
	stderr := captureStderr(t, func() {
		signed, err = enterprisebundle.EffectivePolicyDigests(context.Background(), portable, t.TempDir(), []string{"linux", "darwin", "windows"}, offlineTestDigester)
	})
	if strings.Contains(stderr, "OPA policy unavailable") {
		t.Fatalf("sign the portable settings printed an OPA warning for the target policy_dir (GAP-0239): %s", stderr)
	}
	if err != nil {
		t.Fatalf("sign the portable settings for three platforms: %v", err)
	}
	for _, goos := range []string{"linux", "darwin"} {
		if device := deviceBundleDigest(t, portable, goos); device != signed[goos] {
			t.Fatalf("%s device digest %s != signed %s", goos, device, signed[goos])
		}
	}
}

// An offline bundle digest (sign and verify) does not read a policy_dir
// outside the bundle: that folder is the target device's, the signer need
// not have it, and its Rego is not digested. A missing folder and one with
// Rego that does not compile give the same digest and no OPA warning on
// stderr. Rego the bundle ships is still loaded and digested (GAP-0239).
func TestOfflineBundleDigestDoesNotReadTargetPolicyDir(t *testing.T) {
	root, dataDir := t.TempDir(), t.TempDir()
	digest := func(policyDir string) (EffectivePolicy, string) {
		t.Helper()
		cfg := &config.Config{DataDir: dataDir, PolicyDir: policyDir}
		var got EffectivePolicy
		var err error
		stderr := captureStderr(t, func() {
			got, err = ComputeEffectivePolicyFor(context.Background(), cfg, EffectivePolicyOptions{GOOS: "linux", BundleRoot: root, Raw: []byte("config_version: 9\n")})
		})
		if err != nil {
			t.Fatal(err)
		}
		return got, stderr
	}
	writeRego := func(dir string, files map[string][]byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, "rego"), 0o700); err != nil {
			t.Fatal(err)
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(dir, "rego", name), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	target := filepath.Join(t.TempDir(), "policies")
	missing, stderr := digest(target)
	if strings.Contains(stderr, "OPA policy unavailable") {
		t.Fatalf("missing target policy_dir printed an OPA warning: %s", stderr)
	}
	writeRego(target, map[string][]byte{"broken.rego": []byte("package defenseclaw.broken\nthis is not rego\n")})
	broken, stderr := digest(target)
	if strings.Contains(stderr, "OPA policy unavailable") {
		t.Fatalf("target policy_dir Rego was read offline: %s", stderr)
	}
	if missing.Digest != broken.Digest {
		t.Fatalf("target policy_dir contents changed the bundle digest: %s != %s", missing.Digest, broken.Digest)
	}
	if _, ok := broken.Components["rego"]; ok {
		t.Fatal("target policy_dir Rego entered the bundle components")
	}

	bundled := filepath.Join(root, "policies")
	shipped := map[string][]byte{}
	for _, name := range []string{"admission.rego", "guardrail.rego"} {
		body, err := os.ReadFile(filepath.Join(repoPolicyDir(t), "rego", name))
		if err != nil {
			t.Fatal(err)
		}
		shipped[name] = body
	}
	writeRego(bundled, shipped)
	inBundle, _ := digest(bundled)
	if inBundle.Components["rego"] == "" {
		t.Fatalf("bundled Rego was not digested: %v", inBundle.Components)
	}
}

func offlineTestDigester(ctx context.Context, cfg *config.Config, raw []byte, goos, root string) (string, error) {
	policy, err := ComputeEffectivePolicyFor(ctx, cfg, EffectivePolicyOptions{GOOS: goos, BundleRoot: root, Raw: raw})
	return policy.Digest, err
}

// shippedTemplateBundle is a settings-only bundle of a shipped template with
// one tested change (block_at), optionally without data_dir and policy_dir.
func shippedTemplateBundle(t *testing.T, template string, portable bool) *enterprisebundle.Bundle {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "enterprise-configs", template))
	if err != nil {
		t.Fatal(err)
	}
	const anchor = "guardrail:\n  enabled: true\n"
	if !strings.Contains(string(raw), anchor) {
		t.Fatalf("%s has no %q", template, anchor)
	}
	source := strings.Replace(string(raw), anchor, anchor+"  block_at: MEDIUM\n", 1)
	if portable {
		source = regexp.MustCompile(`(?m)^(data_dir|policy_dir):.*\n`).ReplaceAllString(source, "")
	}
	return &enterprisebundle.Bundle{Files: map[string][]byte{enterprisebundle.ConfigName: []byte(source)}}
}

// deviceBundleDigest is the digest a goos device's gateway publishes once
// apply installed b: apply renders config.yaml for its receipt directory, the
// gateway loads it from the layout config path, and the generation record
// names the bundle, so a settings-only config is digested in the bundle
// scope of the version directory (GAP-0158). The device's installed vendor
// tree is a copy of the source release policies.
func deviceBundleDigest(t *testing.T, b *enterprisebundle.Bundle, goos string) string {
	t.Helper()
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path.Join(layout.PolicyDir, "guardrail", "default")); err == nil {
		t.Skipf("this host has the device pack folder %s/guardrail/default", layout.PolicyDir)
	}
	const bundleID, receiptID, version = "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z2A", "r-01J9ZK3Q4R5S6T7V8W9X0Y1Z2B", 10324003
	bundles := path.Join(layout.ConfigDir, enterprisebundle.BundlesDirName)
	installed, err := enterprisebundle.RenderConfig(b, path.Join(bundles, enterprisebundle.VersionDirNameForReceipt(version, bundleID, receiptID)))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadRuntimeV8InspectionCandidateForLayout(layout.ConfigPath, installed, layout.DataDir, goos)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.ResolveRulePackDir(globalRulePackRef(cfg)), path.Join(layout.VendorPolicyDir, "guardrail", "default"); got != want {
		t.Fatalf("device default pack %q, want the vendor pack %q", got, want)
	}
	_, file, _, _ := runtime.Caller(0)
	installedVendor := t.TempDir()
	if err := os.CopyFS(installedVendor, os.DirFS(filepath.Join(filepath.Dir(file), "..", "..", "policies"))); err != nil {
		t.Fatal(err)
	}
	packCfg := cloneConfig(cfg)
	packCfg.UseOfflineVendorPolicies(layout.VendorPolicyDir, installedVendor)
	rulePacks, err := generationRulePacks(packCfg)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := newGuardrailProfileSet(packCfg, rulePacks.cache, false)
	if err != nil {
		profiles = nil
	}
	g, err := buildGeneration(context.Background(), generationInputs{cfg: cfg, raw: installed,
		rulePacks: rulePacks, profiles: profiles, goos: goos,
		bundleRoot: path.Join(bundles, enterprisebundle.VersionDirName(version, bundleID)),
		vendorRoot: installedVendor, vendorTarget: layout.VendorPolicyDir})
	if err != nil {
		t.Fatal(err)
	}
	return g.Digest
}
