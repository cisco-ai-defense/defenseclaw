// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// GAP-2071: an upgrade whose hook image folder already exists (left by an
// earlier attempt of the same release) still starts the images in it before
// any hook config names them. An application-control deny on the new hook
// fails the stage with hook_image_start_failed whether the folder is new or
// kept, so the start probe is never skipped for an existing folder.
func TestGAP2071StartCheckRunsWhenTheReleaseFolderAlreadyExists(t *testing.T) {
	for _, name := range []string{winpath.EnterpriseHookImageName, winpath.EnterpriseHookGuardImageName} {
		t.Run(name, func(t *testing.T) {
			f := newFakeHookImageFS()
			oldHook, oldGuard := installRelease(f, "1.0.10-prior")
			if prior := stageRelease(t, f, oldHook, oldGuard); !prior.OK {
				t.Fatalf("prior stage = %+v", prior)
			}
			hookSHA, guardSHA := installRelease(f, "1.0.10")
			// An earlier attempt of this release staged its folder, then
			// rolled back: the folder stays, complete.
			if earlier := stageRelease(t, f, hookSHA, guardSHA); !earlier.OK || !earlier.CreatedFolder {
				t.Fatalf("earlier attempt = %+v, want a created folder", earlier)
			}
			starter := &fakeHookImageStarter{build: hookImageTestBuild,
				fail: map[string]error{name: errors.New("This program is blocked by group policy")}}
			report := stageWindowsHookImage(f, starter, windowsHookImageStageRequest{
				Bin: hookImageTestBin, HookSHA256: hookSHA, GuardSHA256: guardSHA, Build: hookImageTestBuild,
			})
			if report.CreatedFolder {
				t.Fatalf("the rerun created the folder again: %+v", report)
			}
			if report.OK || report.Reason != windowsHookImageStartFailed {
				t.Fatalf("stage over the kept folder with %s blocked = %+v; want hook_image_start_failed", name, report)
			}
			if sum, _ := f.SHA256(launchDir(oldHook) + `\defenseclaw-hook.exe`); sum != oldHook {
				t.Fatal("a failed stage changed the prior release's launch image")
			}
		})
	}
}
