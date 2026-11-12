// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The memo hands back the split it holds only for the input and facts it was
// made for; any other input is split afresh, and the caller owns what it gets.
func TestTrustedSimpleMemoAnswersOnlyItsOwnInput(t *testing.T) {
	first := actionfacts.Input{Tool: "Bash", Command: "for u in a b; do cp x ../$u/y; done", CWD: "/r/home/proj", ActiveHome: "/r/home"}
	other := first
	other.Command = "u=a; cp x ../$u/y"
	var memo *trustedSimpleMemo
	if got, want := memo.commands(first, actionfacts.Analyze(first)), actionfacts.SimpleCommands(first, actionfacts.Analyze(first)); !slices.Equal(got, want) {
		t.Fatalf("nil memo = %v, want %v", got, want)
	}
	memo = &trustedSimpleMemo{}
	for _, row := range []struct {
		name  string
		input actionfacts.Input
	}{{"first", first}, {"again", first}, {"other", other}, {"first after other", first}} {
		got := memo.commands(row.input, actionfacts.Analyze(row.input))
		if want := actionfacts.SimpleCommands(row.input, actionfacts.Analyze(row.input)); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", row.name, got, want)
		}
		if len(got) != 0 {
			got[0].Text = "changed by the caller"
		}
	}
}
