// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP1028GuestReadingIsAnalyzedOncePerHook: a hook dispatches one sandbox
// call many times, and each dispatch read the call placed in the guest's
// folder (sandboxGuestPlacedInput) afresh, its placed children included, up
// to about fifty analyses of the same input a hook. The reading is kept for
// the hook (guestReadingMemo): a repeat costs a lookup, not another analysis,
// gives the same facts, and a caller's append never reaches another caller's
// facts (substrate-1 GAP-1028).
func TestGAP1028GuestReadingIsAnalyzedOncePerHook(t *testing.T) {
	var b strings.Builder
	b.WriteString("cd .cache; ")
	for b.Len() < 1<<10 {
		b.WriteString("touch out.txt; ")
	}
	b.WriteString("rm .defenseclaw/audit.db")
	command := b.String()
	request := trustedActionRequest{Input: actionfacts.Input{Tool: "shell", Command: command, CWD: "/work", ActiveHome: "/home/alice"},
		SandboxGuestCWD: "/home/alice/project", guestMemo: &guestReadingMemo{}}
	facts := actionfacts.Analyze(request.Input)
	guest, ok := sandboxGuestPlacedInput(request, facts)
	if !ok {
		t.Fatal("the call has no guest reading")
	}
	want := actionfacts.Analyze(guest)
	wantChildren, wantCandidates, wantCut := sandboxGuestPlacedChildren(nil, guest, want)
	for range 2 {
		withSandboxGuestFolderTier(nil, request, facts)
		children, candidates, cut := sandboxGuestPlacedChildren(request.guestMemo, guest, want)
		if !reflect.DeepEqual(children, wantChildren) || !reflect.DeepEqual(candidates, wantCandidates) || cut != wantCut {
			t.Fatal("a repeated guest reading gives other placed children")
		}
	}
	if got := request.guestMemo.analyze(guest); !reflect.DeepEqual(got, want) {
		t.Fatal("a repeated guest reading gives other facts")
	}
	first := request.guestMemo.analyze(guest)
	if len(first.Paths) == 0 {
		t.Fatal("the guest reading names no path")
	}
	first.Paths = append(first.Paths, actionfacts.PathFact{Value: "changed"})
	first.Paths[0].Value = first.Paths[0].Value + "-changed"
	if again := request.guestMemo.analyze(guest); !reflect.DeepEqual(again, want) {
		t.Fatal("a caller's change reached another caller's guest reading")
	}
	analysis := testing.AllocsPerRun(5, func() { actionfacts.Analyze(guest) })
	repeat := testing.AllocsPerRun(5, func() {
		withSandboxGuestFolderTier(nil, request, facts)
		sandboxGuestPlacedChildren(request.guestMemo, guest, want)
	})
	if repeat > analysis/4 {
		t.Fatalf("a repeated guest reading allocates %.0f times, an analysis %.0f: the call is analyzed again", repeat, analysis)
	}
}
