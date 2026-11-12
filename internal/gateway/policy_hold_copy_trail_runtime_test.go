// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// policyHoldProfilesForTest runs fn once per profile with a gateway that has
// a policy hold on copies of "shared-name".
func policyHoldProfilesForTest(t *testing.T, fn func(t *testing.T, api *APIServer, blocked func(path string) bool, held, admitted, root string)) {
	t.Helper()
	for _, profile := range []string{"balanced", "strict", "managed-standalone"} {
		t.Run(profile, func(t *testing.T) {
			api, store := policyHoldAPIForTest(t)
			switch profile {
			case "strict":
				api.scannerCfg.Guardrail.RulePackDir = filepath.Join(t.TempDir(), "strict")
			case "managed-standalone":
				api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
				api.scannerCfg.Enterprise.Profile = managed.ProfileStandalone
			}
			root := t.TempDir()
			held := policyHoldCopyForTest(t, root, "held")
			admitted := policyHoldCopyForTest(t, root, "admitted")
			if err := store.SetActionFieldForConnector("skill", "shared-name", "codex", "runtime", "disable", policyHoldReasonForTest("runtime", held)); err != nil {
				t.Fatal(err)
			}
			blocked := func(path string) bool {
				probe := skillProbeFromFields("Skill", map[string]interface{}{"skill_name": "shared-name", "skill_path": path}, nil)
				if probe.SourcePath != path || !probe.Matched {
					t.Fatalf("the hook field parser did not keep the named path %s: %+v", path, probe)
				}
				_, matched := api.runtimeSkillAssetPolicyDecision(context.Background(), "codex", probe)
				return matched
			}
			fn(t, api, blocked, held, admitted, root)
		})
	}
}

// A hard link to a link in the held copy is refused in every profile, and an
// admitted file named through a link that steps out of the held folder runs.
func TestPolicyHoldRefusesAHardLinkToALinkAndRunsAParentElementAliasInEveryProfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("links need privileges on Windows")
	}
	policyHoldProfilesForTest(t, func(t *testing.T, _ *APIServer, blocked func(string) bool, held, admitted, root string) {
		ordinary := filepath.Join(admitted, "SKILL.md")
		protected := filepath.Join(held, "protected-link")
		if err := os.Symlink(ordinary, protected); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		hard := filepath.Join(root, "hard-to-link")
		if err := os.Link(protected, hard); err != nil {
			t.Skipf("hard links to links unavailable: %v", err)
		}
		if info, err := os.Lstat(hard); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Skip("the hard link followed the link on this platform")
		}
		alias := filepath.Join(root, "alias")
		if err := os.Symlink(held+"/../admitted/SKILL.md", alias); err != nil {
			t.Fatal(err)
		}
		for label, path := range map[string]string{"the held file": filepath.Join(held, "SKILL.md"), "the link in the held copy": protected, "a hard link to it": hard} {
			if !blocked(path) {
				t.Errorf("%s: the protected path was allowed", label)
			}
		}
		for label, path := range map[string]string{"the admitted file": ordinary, "a link that steps out of the held folder": alias} {
			if blocked(path) {
				t.Errorf("%s: the ordinary path was refused", label)
			}
		}
	})
}

// A held folder with no read permission is present but unknown: balanced runs
// an admitted file with a warning, strict and managed keep the hold.
func TestPolicyHoldRunsAnAdmittedFileInBalancedWhenTheHeldFolderIsNotReadable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions as a non-root user")
	}
	policyHoldProfilesForTest(t, func(t *testing.T, api *APIServer, blocked func(string) bool, held, admitted, _ string) {
		if err := os.Chmod(held, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(held, 0o700) })
		if _, err := os.ReadDir(held); err == nil {
			t.Skip("the folder is still readable")
		}
		balanced := api.scannerCfg.DeploymentMode == "" && api.scannerCfg.Guardrail.RulePackDir == ""
		if got := blocked(filepath.Join(admitted, "SKILL.md")); got == balanced {
			t.Errorf("admitted file refused = %v, want %v", got, !balanced)
		}
		if !blocked(filepath.Join(held, "SKILL.md")) {
			t.Error("the held file was allowed")
		}
	})
}
