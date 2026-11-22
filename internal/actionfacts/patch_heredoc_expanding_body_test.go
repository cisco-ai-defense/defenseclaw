// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// An apply_patch envelope fed by a here-document the shell expands is marked
// (CommandPatchNamesUnplacedTarget) whatever its headers name: an expansion
// in any line, a content line too, may hold newlines and add a header no
// reader sees, so the header set of the envelope is not known
// (rel-1-0-10:GAP-1093). The placed headers stay complete facts, so a block
// they prove stays a block; the same envelope with a quoted delimiter and
// only placed headers is not marked. Before, an expansion in a content line
// of an envelope whose headers were all placed left the command unmarked: a
// clean allow in every tier for benign placed headers.
func TestPatchHeredocExpandingBodyIsMarked(t *testing.T) {
	const placed = "src/placed.txt"
	type envelope struct {
		text      string
		access    PathAccess
		onlyPlace bool
	}
	envelopes := map[string]envelope{}
	for name, e := range patchHeaderEnvelopes(placed) {
		envelopes["placed "+name] = envelope{e.text, e.access, true}
	}
	for name, e := range patchDecoyEnvelopes(placed) {
		envelopes["decoy "+name] = envelope{e.text, e.access, false}
	}
	for name, e := range envelopes {
		for delimiter, document := range patchDecoyHeredocs(e.text) {
			t.Run(name+" "+delimiter, func(t *testing.T) {
				facts := patchDecoyShellFacts(t, document)
				if facts.Parse.Status != StatusComplete || !facts.Authoritative() {
					t.Fatalf("parse = %#v", facts.Parse)
				}
				if !slices.ContainsFunc(facts.Paths, func(path PathFact) bool {
					return path.Value == placed && path.Access == e.access
				}) {
					t.Fatalf("no %s fact for the placed header: %#v", e.access, facts.Paths)
				}
				want := delimiter == "expanding" || !e.onlyPlace
				if got := CommandPatchNamesUnplacedTarget(facts); got != want {
					t.Fatalf("marked %t, want %t", got, want)
				}
			})
		}
	}
}
