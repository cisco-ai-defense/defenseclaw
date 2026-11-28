// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"strings"
	"testing"
)

// GAP-1898: the Copilot row's prior-render check is told the image the
// target's records are checked against, so a Local hook file the earlier
// release rendered for its own launch image can pass the guardian's read-only
// verify that accepts an earlier release render. Its error still fails the row,
// and a row of another connector runs no check.
func TestGAP1898CopilotPriorRenderCheckReceivesTheRecordedHookImage(t *testing.T) {
	const recorded = `C:\Program Files\Cisco\DefenseClaw\bin\hooks\6081ba06f39a5eb8\defenseclaw-hook.exe`
	windowsCopilotVSCodeUserPriorRender.Lock()
	previous := windowsCopilotVSCodeUserPriorRender.check
	windowsCopilotVSCodeUserPriorRender.Unlock()
	t.Cleanup(func() { SetWindowsCopilotVSCodeUserPriorRender(previous) })

	var gotHome, gotRecorded string
	calls := 0
	var fail error
	SetWindowsCopilotVSCodeUserPriorRender(func(home, image string) error {
		calls++
		gotHome, gotRecorded = home, image
		return fail
	})
	if err := applyWindowsCopilotVSCodeUserPriorRender("copilot", `C:\Users\u1`, recorded); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || gotHome != `C:\Users\u1` || gotRecorded != recorded {
		t.Fatalf("check got home=%q recorded=%q calls=%d, want the target home and its recorded image once", gotHome, gotRecorded, calls)
	}
	fail = errors.New("stale")
	if err := applyWindowsCopilotVSCodeUserPriorRender("copilot", `C:\Users\u1`, recorded); err == nil ||
		!strings.Contains(err.Error(), "copilot VS Code Local hooks: stale") {
		t.Fatalf("failing check: %v, want the row to fail with it", err)
	}
	if err := applyWindowsCopilotVSCodeUserPriorRender("opencode", `C:\Users\u1`, recorded); err != nil || calls != 2 {
		t.Fatalf("opencode row: err=%v calls=%d, want no check", err, calls)
	}
}

// GAP-1898: the administrator's verify of a runtime-only row checks the Copilot
// Local hook file and plugin against the image the target's records name, not
// the current image, when it accepts an earlier release's render. Passing the
// current image instead brings back the failed Copilot row after a launch-image
// upgrade. A verify that takes no earlier render stays strict and never asks
// the prior-render check.
func TestGAP1898RuntimeOnlyVerifyChecksTheCopilotFilesAgainstTheRecordedImage(t *testing.T) {
	const (
		current  = `C:\Program Files\Cisco\DefenseClaw\bin\hooks\65b4297c1bc70cbd\defenseclaw-hook.exe`
		recorded = `C:\Program Files\Cisco\DefenseClaw\bin\hooks\6081ba06f39a5eb8\defenseclaw-hook.exe`
		home     = `C:\Users\u1`
	)
	windowsCopilotVSCodeUserPriorRender.Lock()
	previousPrior := windowsCopilotVSCodeUserPriorRender.check
	windowsCopilotVSCodeUserPriorRender.Unlock()
	windowsCopilotVSCodeUser.Lock()
	previousStrict := windowsCopilotVSCodeUser.apply
	windowsCopilotVSCodeUser.Unlock()
	t.Cleanup(func() {
		SetWindowsCopilotVSCodeUserPriorRender(previousPrior)
		SetWindowsCopilotVSCodeUser(previousStrict)
	})
	var priorImages []string
	strictCalls := 0
	SetWindowsCopilotVSCodeUserPriorRender(func(gotHome, image string) error {
		if gotHome != home {
			t.Fatalf("prior-render check home %q, want %q", gotHome, home)
		}
		priorImages = append(priorImages, image)
		return nil
	})
	SetWindowsCopilotVSCodeUser(func(gotHome string, verify, remove bool) error {
		if gotHome != home || !verify || remove {
			t.Fatalf("strict check home=%q verify=%t remove=%t, want a read-only check of %q", gotHome, verify, remove, home)
		}
		strictCalls++
		return nil
	})

	target := windowsGenericManagedTarget{home: home, hookExecutable: current, runtimeHookExecutable: recorded}
	if err := verifyWindowsRuntimeOnlyUserFiles(InstallOptions{AcceptPriorReleaseRender: true}, "copilot", target); err != nil {
		t.Fatal(err)
	}
	if len(priorImages) != 1 || priorImages[0] != recorded || strictCalls != 0 {
		t.Fatalf("prior-render verify: check images %q, strict calls %d, want the recorded image %q once", priorImages, strictCalls, recorded)
	}
	// A target built without a recorded image is checked against its own.
	target.runtimeHookExecutable = ""
	if err := verifyWindowsRuntimeOnlyUserFiles(InstallOptions{AcceptPriorReleaseRender: true}, "copilot", target); err != nil {
		t.Fatal(err)
	}
	if len(priorImages) != 2 || priorImages[1] != current {
		t.Fatalf("target without a recorded image: check images %q, want the current image second", priorImages)
	}
	// A verify that accepts no earlier render stays strict.
	target.runtimeHookExecutable = recorded
	if err := verifyWindowsRuntimeOnlyUserFiles(InstallOptions{}, "copilot", target); err != nil {
		t.Fatal(err)
	}
	if len(priorImages) != 2 || strictCalls != 1 {
		t.Fatalf("strict verify: check images %q, strict calls %d, want one strict check and no prior-render check", priorImages, strictCalls)
	}
}
