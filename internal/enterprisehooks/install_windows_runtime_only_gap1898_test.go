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
