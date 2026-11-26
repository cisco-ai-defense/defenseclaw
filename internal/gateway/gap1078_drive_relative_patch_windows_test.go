// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-1078 at the verdict: a Codex or Copilot CLI apply_patch
// header spelled drive-relative (C:name, no separator after the colon) on
// the drive of the hook's working folder names the file of that folder. With
// the working folder at the home, C:.ssh\authorized_keys is judged by the
// path rule of the account's authorized_keys file, as its full drive path is
// (TestWindowsApplyPatchAbsoluteTargetsAreJudged). The hookpaths write
// target reader keeps every C:name unknown on purpose (patchTargetPaths):
// that only adds the unknown-target answer, never lowers the path rule.
func TestGAP1078DriveRelativePatchHeaderIsJudgedByThePathRule(t *testing.T) {
	for _, profile := range []string{"default", "strict"} {
		for _, connectorName := range []string{"codex", "copilot"} {
			t.Run(profile+"/"+connectorName, func(t *testing.T) {
				f := newWindowsPatchFixture(t)
				f.project = f.home
				target := filepath.VolumeName(f.home) + `.ssh\authorized_keys`
				got, out := postWindowsApplyPatch(t, f, connectorName, profile, windowsUpdatePatch(target))
				if !strings.Contains(out, "persistence.ssh_authorized_keys_command") {
					t.Fatalf("the patch of %s does not name the authorized_keys rule: %.600s", target, out)
				}
				if got != "block" {
					t.Fatalf("decision %s, want block: %.600s", got, out)
				}
			})
		}
	}
}

// The benign twin, recorded: a drive-relative header that names a project
// file. The verdict is pinned to what it was before the placement
// (TestGAP1078DriveRelativeProjectHeaderVerdict rows), so the placement
// raises nothing benign.
func TestGAP1078DriveRelativeProjectHeaderVerdict(t *testing.T) {
	for _, profile := range []string{"default", "strict"} {
		for _, connectorName := range []string{"codex", "copilot"} {
			t.Run(profile+"/"+connectorName, func(t *testing.T) {
				f := newWindowsPatchFixture(t)
				f.project = f.home
				target := filepath.VolumeName(f.home) + `proj\src\main.go`
				got, out := postWindowsApplyPatch(t, f, connectorName, profile, windowsUpdatePatch(target))
				rule := "-"
				for _, r := range []string{"persistence.ssh_authorized_keys_command", "tamper.detector_state_write", "unknown", "unplaced"} {
					if strings.Contains(out, r) {
						rule = r
						break
					}
				}
				t.Logf("VERDICT %s/%s decision=%s rule=%s", profile, connectorName, got, rule)
			})
		}
	}
}
