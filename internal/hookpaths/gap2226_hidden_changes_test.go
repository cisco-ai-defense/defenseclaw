// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// TestGAP2226HiddenChangesMatchEveryOffset pins that placedCalls reads the
// hidden directory changes of a tree once with the answer
// hiddenDirectoryChangeBefore gives each call (rel-1-0-10:GAP-2226): for every
// call and every offset of each script, in order and out of order.
func TestGAP2226HiddenChangesMatchEveryOffset(t *testing.T) {
	home := "/home/alice"
	scripts := []string{
		"cd .cache && touch a; source x.sh; cat b; cd .ssh && cat id_ed25519",
		"f() { cd .ssh; }; touch a; f; cat id_ed25519",
		"touch a; eval 'cd .ssh'; cat id_ed25519; eval \"$X\"; cat b",
		"touch a; sh -c 'cd .ssh && cat id_ed25519'; bash -c 'source y'; cat c",
		"echo $(cd .ssh; source z); cat id_ed25519; trap 'cd /' EXIT; cat d",
		"cd a || exit; exec 3>x; builtin cd b; command cd c; alias l=ls; shopt -s cdable_vars; cat e",
		"for i in 1 2; do cd s$i; . ./env; done; cat f; ( cd .ssh; cat id_ed25519 ); cat g",
		"cat a; cat b; cat c",
		strings.Repeat("touch f; ", 40) + "source v; " + strings.Repeat("cat g; ", 40),
	}
	for _, script := range scripts {
		file, ok := parseShell(script)
		if !ok {
			t.Fatalf("parse %q", script)
		}
		var offsets []uint
		syntax.Walk(file, func(node syntax.Node) bool {
			if call, isCall := node.(*syntax.CallExpr); isCall {
				offsets = append(offsets, call.Pos().Offset(), call.End().Offset())
			}
			return true
		})
		for at := uint(0); at <= uint(len(script)); at += 3 {
			offsets = append(offsets, at)
		}
		for _, order := range []string{"forward", "backward"} {
			hidden := newHiddenChanges(file, home)
			for i := range offsets {
				offset := offsets[i]
				if order == "backward" {
					offset = offsets[len(offsets)-1-i]
				}
				want := hiddenDirectoryChangeBefore(file, home, offset)
				if got := hidden.before(offset); got != want {
					t.Errorf("%s %q offset %d: hiddenChanges %v, hiddenDirectoryChangeBefore %v", order, script, offset, got, want)
				}
			}
		}
	}
}

// TestGAP2226PlacedCallsReadHiddenChangesOnce pins the work: a placed call of
// a long script no longer walks the whole tree for each call.
func TestGAP2226PlacedCallsReadHiddenChangesOnce(t *testing.T) {
	var b strings.Builder
	b.WriteString("cd .cache\n")
	for i := range 1500 {
		fmt.Fprintf(&b, "touch f%d\n", i)
	}
	command := b.String()
	file, ok := parseShell(command)
	if !ok {
		t.Fatal("parse")
	}
	placed := newPlacedCalls(file, command, "/home/alice", "/home/alice")
	var calls []*syntax.CallExpr
	syntax.Walk(file, func(node syntax.Node) bool {
		if call, isCall := node.(*syntax.CallExpr); isCall {
			calls = append(calls, call)
		}
		return true
	})
	for _, call := range calls {
		placed.of(call)
	}
	// Each call asks for the changes that end before it starts, so the
	// walk reads every call but the last, once.
	if placed.hidden == nil || placed.hidden.next != len(calls)-1 {
		t.Fatalf("hidden changes not read once over the %d calls: %v", len(calls), placed.hidden != nil)
	}
	renamed := newPlacedCalls(file, command, "/home/alice", "/home/alice")
	renamed.renamed = true
	for _, call := range calls[:3] {
		renamed.of(call)
	}
	if renamed.hidden != nil {
		t.Fatal("a renamed tree must read its hidden changes afresh")
	}
}
