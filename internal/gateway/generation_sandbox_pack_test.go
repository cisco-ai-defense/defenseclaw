// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
)

// GAP-0229: on a managed computer a required sandbox pack that does not
// load fails the generation, so the gateway refuses to start on it, a
// reload keeps the last good generation, and `policy digest` (which builds
// the same generation) refuses it before ensure would restart the gateway.
// The same pack on an unmanaged computer is left to the sandbox routes.
func TestBuildGenerationRefusesARequiredSandboxPackThatDoesNotLoad(t *testing.T) {
	dir := t.TempDir()
	pack := filepath.Join(dir, "corp", "pack.yaml")
	if err := os.MkdirAll(filepath.Dir(pack), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pack, []byte("version: 1\nname: corp\nnetwork:\n  mode: unbuildable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
	cfg.OpenShell.PackDir = dir
	cfg.OpenShell.Admin.RequiredPack = pack
	if _, err := buildGeneration(context.Background(), generationInputs{cfg: cfg}); err == nil ||
		!strings.Contains(err.Error(), "sandbox pack "+pack+" does not load") {
		t.Fatalf("buildGeneration error = %v, want the sandbox pack refused", err)
	}
	if _, err := ComputeEffectivePolicy(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "does not load") {
		t.Fatalf("ComputeEffectivePolicy error = %v, want the sandbox pack refused", err)
	}

	// A profile's own required pack is checked too.
	cfg.OpenShell.Admin.RequiredPack = ""
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"strict": {Sandbox: &config.OpenShellAdminConfig{RequiredPack: pack}}}
	if _, err := buildGeneration(context.Background(), generationInputs{cfg: cfg}); err == nil || !strings.Contains(err.Error(), "does not load") {
		t.Fatalf("buildGeneration error = %v, want the profile's sandbox pack refused", err)
	}

	cfg.DeploymentMode = ""
	if _, err := buildGeneration(context.Background(), generationInputs{cfg: cfg}); err != nil {
		t.Fatalf("an unmanaged generation: %v", err)
	}
}

// rel-1-0-3 GAP-0050: an unpinned required pack is still policy content.
// Both the organization floor and a profile-only pack must affect the root
// attestation, including edits inherited from the pack's parent.
func TestEffectiveDigestTracksUnpinnedSandboxPackContent(t *testing.T) {
	// Trust checks have their own tests. This unit test loads its private
	// fixtures as the current user without requiring administrator rights.
	previous := loadSandboxGenerationPack
	t.Cleanup(func() { loadSandboxGenerationPack = previous })
	loadSandboxGenerationPack = func(_ packs.Subject, ref, dir string) (*packs.Pack, error) { return packs.Load(ref, dir) }
	for _, profileOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "organization", true: "profile"}[profileOnly], func(t *testing.T) {
			dir := t.TempDir()
			pack := filepath.Join(dir, "corp", "pack.yaml")
			if err := os.MkdirAll(filepath.Dir(pack), 0o755); err != nil {
				t.Fatal(err)
			}
			write := func(host string) {
				t.Helper()
				if err := os.WriteFile(pack, []byte("version: 1\nname: corp\nextends: strict\negress:\n  allow: ["+host+"]\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cfg := &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
			cfg.OpenShell.Enabled, cfg.OpenShell.PackDir = true, dir
			if profileOnly {
				cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"engineering": {Sandbox: &config.OpenShellAdminConfig{RequiredPack: pack}}}
			} else {
				cfg.OpenShell.Admin.RequiredPack = pack
			}
			write("alpha.example")
			before, err := ComputeEffectivePolicy(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			write("beta.example")
			after, err := ComputeEffectivePolicy(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if before.Digest == after.Digest {
				t.Fatal("editing the unpinned sandbox pack did not change the root effective digest")
			}
			if before.Components["config"] != after.Components["config"] {
				t.Fatal("the test changed configuration rather than only the pack")
			}
			parent := filepath.Join(dir, "parent", "pack.yaml")
			if err := os.MkdirAll(filepath.Dir(parent), 0o755); err != nil {
				t.Fatal(err)
			}
			writeParent := func(host string) {
				t.Helper()
				if err := os.WriteFile(parent, []byte("version: 1\nname: parent\nextends: strict\negress:\n  allow: ["+host+"]\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(pack, []byte("version: 1\nname: corp\nextends: parent\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			writeParent("alpha.example")
			inheritedBefore, err := ComputeEffectivePolicy(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			writeParent("beta.example")
			inheritedAfter, err := ComputeEffectivePolicy(t.Context(), cfg)
			if err != nil || inheritedBefore.Digest == inheritedAfter.Digest {
				t.Fatalf("parent edit did not move the attestation: %v", err)
			}
		})
	}
}

func TestSandboxPackDigestMatchesTheBundleScope(t *testing.T) {
	previous := loadSandboxGenerationPack
	t.Cleanup(func() { loadSandboxGenerationPack = previous })
	loadSandboxGenerationPack = func(_ packs.Subject, ref, dir string) (*packs.Pack, error) { return packs.Load(ref, dir) }
	build := func(root string, offline bool) *Generation {
		t.Helper()
		dir := filepath.Join(root, "sandboxes")
		if err := os.MkdirAll(filepath.Join(dir, "corp"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "corp", "pack.yaml"), []byte("version: 1\nname: corp\nextends: strict\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
		cfg.OpenShell.Enabled, cfg.OpenShell.PackDir, cfg.OpenShell.Admin.RequiredPack = true, dir, "corp"
		g, err := buildGeneration(t.Context(), generationInputs{cfg: cfg, bundleRoot: root, offline: offline})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	signed, installed := build(t.TempDir(), true), build(t.TempDir(), false)
	if signed.Components["sandbox_pack:corp"] == "" || signed.Digest != installed.Digest {
		t.Fatalf("bundle pack digest differs after installation: signed %+v installed %+v", signed.Components, installed.Components)
	}
}

// Signing reads authenticated bundle contents as data before the managed
// installer promotes them to administrator ownership. Runtime must retain
// its stricter ownership check for exactly the same files.
func TestOfflineSandboxPackDigestReadsSignerOwnedFiles(t *testing.T) {
	if os.Geteuid() <= 0 {
		t.Skip("requires an unprivileged POSIX signer")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "sandboxes")
	if err := os.MkdirAll(filepath.Join(dir, "corp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "corp", "pack.yaml"), []byte("version: 1\nname: corp\nextends: strict\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DeploymentMode: "managed_enterprise", Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
	cfg.OpenShell.Enabled, cfg.OpenShell.PackDir, cfg.OpenShell.Admin.RequiredPack = true, dir, "corp"
	signed, err := buildGeneration(t.Context(), generationInputs{cfg: cfg, bundleRoot: root, offline: true})
	if err != nil || signed.Components["sandbox_pack:corp"] == "" {
		t.Fatalf("signer-owned bundle pack could not be digested: %v", err)
	}
	if _, err := buildGeneration(t.Context(), generationInputs{cfg: cfg, bundleRoot: root}); err == nil ||
		!strings.Contains(err.Error(), "administrator-owned") {
		t.Fatalf("runtime accepted a signer-owned pack before promotion: %v", err)
	}
}
