// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-2:GAP-0099: ensure, status and verify warn when a managed
// standalone host still reads its sandbox packs from the pre-1.0.2 default
// folder in data_dir, and name the folder to move them to.
func TestAddSandboxPolicyWarningsNamesTheOldSandboxPacksFolder(t *testing.T) {
	t.Setenv(managed.ConfigPathEnv, "")
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "")
	dataDir, policyDir := t.TempDir(), t.TempDir()
	legacy := filepath.Join(dataDir, "policies", "sandbox")
	if err := os.MkdirAll(filepath.Join(legacy, "corp-dev"), 0o755); err != nil {
		t.Fatal(err)
	}
	raw := "config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n" +
		"data_dir: " + dataDir + "\npolicy_dir: " + policyDir + "\n" +
		"guardrail:\n  enabled: true\n  mode: observe\n  connectors:\n    codex: {}\n"
	cfg, err := config.LoadRuntimeV8InspectionCandidateFromBytes(filepath.Join(t.TempDir(), "config.yaml"), []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	warned := func() bool {
		r := &Result{}
		r.AddSandboxPolicyWarnings(cfg, "linux")
		for _, w := range r.Warnings {
			if w.Code == CodeSandboxAdvisory && strings.Contains(w.Message, legacy) &&
				strings.Contains(w.Message, filepath.Join(policyDir, "sandbox")) {
				return true
			}
		}
		return false
	}
	if cfg.OpenShell.PackDir != legacy || !warned() {
		t.Fatalf("pack_dir %q with packs only in %s: want that folder and a warning", cfg.OpenShell.PackDir, legacy)
	}
	if err := os.Mkdir(filepath.Join(policyDir, "sandbox"), 0o750); err != nil {
		t.Fatal(err)
	}
	if cfg, err = config.LoadRuntimeV8InspectionCandidateFromBytes(filepath.Join(t.TempDir(), "config.yaml"), []byte(raw)); err != nil {
		t.Fatal(err)
	}
	if cfg.OpenShell.PackDir != filepath.Join(policyDir, "sandbox") || warned() {
		t.Fatalf("pack_dir %q once <policy_dir>/sandbox exists: want it and no warning", cfg.OpenShell.PackDir)
	}
}
