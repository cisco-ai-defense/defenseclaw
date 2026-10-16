// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// On a managed standalone host an undeclared openshell.pack_dir is
// <policy_dir>/sandbox, the administrator's folder that ensure and verify
// check and the docs stage packs in, not the service-writable
// <data_dir>/policies/sandbox (rel-1-0-2:GAP-0099, #1206). A custom required
// pack named there passes the managed pack check.
func TestStandaloneLayoutSandboxPacksDefaultToThePolicyDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Linux and macOS layout paths are not paths on Windows")
	}
	t.Setenv(managed.ConfigPathEnv, "")
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "")
	const minimal = `config_version: 8
deployment_mode: managed_enterprise
enterprise:
  profile: standalone
guardrail:
  enabled: true
  mode: observe
  connectors:
    codex: {}
`
	for _, goos := range []string{"linux", "darwin"} {
		layout, err := managed.StandaloneLayoutFor(goos)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(layout.DataDir, "policies", DefaultOpenShellPackDirName)); err == nil {
			t.Skipf("%s has a pre-1.0.2 sandbox packs folder on this host", layout.DataDir)
		}
		want := filepath.Join(layout.VendorPolicyDir, DefaultOpenShellPackDirName)
		t.Run(goos, func(t *testing.T) {
			cfg, err := LoadRuntimeV8InspectionCandidateFromBytes(layout.ConfigPath, []byte(minimal))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.OpenShell.PackDir != want {
				t.Fatalf("openshell.pack_dir = %q, want <policy_dir>/sandbox %q", cfg.OpenShell.PackDir, want)
			}
			if advisory := cfg.OpenShellPackDirAdvisory(); advisory != "" {
				t.Fatalf("advisory without a legacy folder: %q", advisory)
			}

			// The documented setup: policy_dir declared, a custom required
			// pack by name. It was refused because pack_dir stayed in data_dir.
			documented := minimal + "policy_dir: " + layout.PolicyDir + "\nopenshell:\n  admin:\n    required_pack: corp-dev\n"
			cfg, err = LoadRuntimeV8InspectionCandidateFromBytes(layout.ConfigPath, []byte(documented))
			if err != nil {
				t.Fatalf("a required pack staged as documented is refused: %v", err)
			}
			if staged := filepath.Join(layout.PolicyDir, DefaultOpenShellPackDirName); cfg.OpenShell.PackDir != staged {
				t.Fatalf("openshell.pack_dir with the documented policy_dir = %q, want %q", cfg.OpenShell.PackDir, staged)
			}

			explicit := minimal + "openshell:\n  pack_dir: /opt/corp/sandbox-packs\n"
			cfg, err = LoadRuntimeV8InspectionCandidateFromBytes(layout.ConfigPath, []byte(explicit))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.OpenShell.PackDir != "/opt/corp/sandbox-packs" {
				t.Fatalf("an explicit openshell.pack_dir must be kept: got %q", cfg.OpenShell.PackDir)
			}
		})
	}
}

// A host upgraded from a release that read its sandbox packs from
// <data_dir>/policies/sandbox keeps reading them there while
// <policy_dir>/sandbox does not exist, and is told to move them; the new
// folder wins once it exists. Per-user installs and explicit values are
// unchanged.
func TestStandaloneSandboxPackDirKeepsAPackStagedAtTheOldDefault(t *testing.T) {
	dataDir := t.TempDir()
	policyDir := t.TempDir()
	legacy := filepath.Join(dataDir, "policies", DefaultOpenShellPackDirName)
	current := filepath.Join(policyDir, DefaultOpenShellPackDirName)
	resolve := func(t *testing.T, mode, policy, packDir string, declared bool) *Config {
		t.Helper()
		cfg := &Config{DeploymentMode: mode, DataDir: dataDir, PolicyDir: policy}
		if mode != "" {
			cfg.Enterprise.Profile = managed.ProfileStandalone
		}
		cfg.OpenShell.PackDir = packDir
		cfg.openShellPackDirDeclared = declared
		if err := resolveEnterpriseConfig(cfg, "linux", ""); err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	cfg := resolve(t, "managed_enterprise", policyDir, legacy, false)
	if cfg.OpenShell.PackDir != current || cfg.OpenShellPackDirAdvisory() != "" {
		t.Fatalf("no packs anywhere: pack_dir %q (advisory %q), want %q", cfg.OpenShell.PackDir, cfg.OpenShellPackDirAdvisory(), current)
	}

	if err := os.MkdirAll(legacy, 0o755); err != nil {
		t.Fatal(err)
	}
	if cfg := resolve(t, "managed_enterprise", policyDir, legacy, false); cfg.OpenShell.PackDir != current {
		t.Fatalf("an empty old folder: pack_dir %q, want %q", cfg.OpenShell.PackDir, current)
	}

	if err := os.MkdirAll(filepath.Join(legacy, "corp-dev"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg = resolve(t, "managed_enterprise", policyDir, legacy, false)
	if cfg.OpenShell.PackDir != legacy {
		t.Fatalf("a pack staged at the old default: pack_dir %q, want the old folder %q", cfg.OpenShell.PackDir, legacy)
	}
	advisory := cfg.OpenShellPackDirAdvisory()
	if !strings.Contains(advisory, legacy) || !strings.Contains(advisory, "move them to "+current) {
		t.Fatalf("advisory = %q, want it to name %s and %s", advisory, legacy, current)
	}

	if err := os.MkdirAll(current, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg = resolve(t, "managed_enterprise", policyDir, legacy, false)
	if cfg.OpenShell.PackDir != current || cfg.OpenShellPackDirAdvisory() != "" {
		t.Fatalf("with <policy_dir>/sandbox present: pack_dir %q (advisory %q), want %q", cfg.OpenShell.PackDir, cfg.OpenShellPackDirAdvisory(), current)
	}

	if cfg := resolve(t, "managed_enterprise", policyDir, legacy, true); cfg.OpenShell.PackDir != legacy {
		t.Fatalf("an explicit pack_dir equal to the old default must be kept: got %q", cfg.OpenShell.PackDir)
	}
	if cfg := resolve(t, "managed_enterprise", filepath.Join(dataDir, "policies"), legacy, false); cfg.OpenShell.PackDir != legacy {
		t.Fatalf("policy_dir inside data_dir: pack_dir %q, want it unchanged", cfg.OpenShell.PackDir)
	}
	if cfg := resolve(t, "", policyDir, legacy, false); cfg.OpenShell.PackDir != legacy {
		t.Fatalf("a per-user install must keep its pack_dir: got %q", cfg.OpenShell.PackDir)
	}
}
