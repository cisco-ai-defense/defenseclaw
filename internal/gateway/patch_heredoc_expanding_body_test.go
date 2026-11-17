// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestPatchHeredocExpandingBodyIsNeverAllowed{Default,Strict,Permissive,Managed,ManagedStrict}:
// an apply_patch envelope the Codex shell tool feeds by a here-document the
// shell expands is judged at the unknown tier of the pack at least (alert in
// default, permissive and managed, block in strict and managed-strict), and
// at least as the same envelope fed byte for byte by a quoted delimiter (the
// placed block): never a clean allow. An expansion in any line, a content
// line too, may hold newlines and add a header no reader sees, so the header
// set of the envelope is not known (rel-1-0-10:GAP-1093).
//
// The envelopes are the decoy shapes of
// TestPatchDecoyHeaderNeverWeakerThanTheSinglePatch (patchDecoyShapes, each
// envelope and its single-header reference) on the codex/heredoc-expanding
// route, for the wincred Write and Edit fixture targets, rotated as there,
// and for a benign target in every shape. Before GAP-1093, an envelope whose
// headers were all placed (the single-header reference, every benign
// reference) with an expansion in a content line was a complete read with no
// unknown finding: allow in every tier, strict too.
func TestPatchHeredocExpandingBodyIsNeverAllowedDefault(t *testing.T) {
	patchHeredocExpandingNeverAllowed(t, "default")
}

func TestPatchHeredocExpandingBodyIsNeverAllowedStrict(t *testing.T) {
	patchHeredocExpandingNeverAllowed(t, "strict")
}

func TestPatchHeredocExpandingBodyIsNeverAllowedPermissive(t *testing.T) {
	patchHeredocExpandingNeverAllowed(t, "permissive")
}

func TestPatchHeredocExpandingBodyIsNeverAllowedManaged(t *testing.T) {
	patchHeredocExpandingNeverAllowed(t, "managed")
}

func TestPatchHeredocExpandingBodyIsNeverAllowedManagedStrict(t *testing.T) {
	patchHeredocExpandingNeverAllowed(t, "managed-strict")
}

// patchHeredocExpandingTarget is one placed change the envelopes carry.
type patchHeredocExpandingTarget struct {
	id, target, body, hunk string
	rotate                 bool
}

func patchHeredocExpandingNeverAllowed(t *testing.T, tier string) {
	index := slices.IndexFunc(gap0437Packs, func(p gap0437Pack) bool { return p.name == tier })
	if index < 0 {
		t.Fatalf("no tier %q in gap0437Packs", tier)
	}
	p := gap0437Packs[index]
	// The unknown tier of the pack: alert where the pack alerts on an
	// unknown call, block in the strict packs (ONE BOUND RULE).
	unknown := shapeParityRank["alert"]
	if p.pack == "strict" {
		unknown = shapeParityRank["block"]
	}
	envelopeBody := func(single string) string {
		return strings.TrimSuffix(strings.TrimPrefix(single, "*** Begin Patch\n"), "\n*** End Patch")
	}
	var targets []patchHeredocExpandingTarget
	for _, c := range shapeParityCases(t) {
		if !strings.HasPrefix(c.id, "wincred/") || (c.tool != "Write" && c.tool != "Edit") {
			continue
		}
		str := func(key string) string { value, _ := c.args[key].(string); return value }
		target := str("file_path")
		if runtime.GOOS != "windows" {
			target = strings.ReplaceAll(target, `\`, "/")
		}
		single := shapeParityPatch(target, str("content"))
		hunk := "@@\n-a\n+" + strings.ReplaceAll(str("content"), "\n", "\n+")
		if c.tool == "Edit" {
			single = shapeParityUpdatePatch(target, str("old_string"), str("new_string"))
			hunk = "@@\n-" + strings.ReplaceAll(str("old_string"), "\n", "\n-") + "\n+" +
				strings.ReplaceAll(str("new_string"), "\n", "\n+")
		}
		targets = append(targets, patchHeredocExpandingTarget{c.id + " " + c.tool, target, envelopeBody(single), hunk, true})
	}
	if len(targets) == 0 {
		t.Fatal("no wincred Write or Edit fixture cases")
	}
	// A benign placed file, in every shape: its envelopes have nothing a path
	// or content rule blocks, so only the unknown finding keeps them from a
	// clean allow.
	targets = append(targets, patchHeredocExpandingTarget{"benign", "src/zzbenign.txt",
		envelopeBody(shapeParityPatch("src/zzbenign.txt", "x")), "@@\n-a\n+x", false})

	cwd := t.TempDir()
	handlers := shapeParityHandlers(t, p)
	var expanding, quoted patchDecoyRoute
	for _, route := range patchDecoyRoutes(cwd) {
		switch route.name {
		case "codex/heredoc-expanding":
			expanding = route
		case "codex/heredoc-quoted":
			quoted = route
		}
	}
	if expanding.call == nil || quoted.call == nil {
		t.Fatal("no codex here-document routes in patchDecoyRoutes")
	}
	verdict := func(route patchDecoyRoute, envelope string) string {
		call := route.call(envelope)
		return shapeParityHook(t, handlers[call.conn], call, p.managed)
	}
	placedBlocks, benignChecked := 0, 0
	for n, target := range targets {
		shapes := make([]int, 0, len(patchDecoyShapes))
		if target.rotate {
			for k := range patchDecoyShapesPerCase {
				shapes = append(shapes, (n+k*len(patchDecoyShapes)/patchDecoyShapesPerCase)%len(patchDecoyShapes))
			}
		} else {
			for s := range patchDecoyShapes {
				shapes = append(shapes, s)
			}
		}
		for _, s := range shapes {
			shape := patchDecoyShapes[s]
			u := expanding.unplaced[(n+s)%len(expanding.unplaced)]
			u2 := expanding.unplaced[(n+s+1)%len(expanding.unplaced)]
			for kind, envelope := range map[string]string{
				"envelope":  shape.envelope(target.target, target.body, target.hunk, u, u2),
				"reference": shape.reference(target.target, target.body, target.hunk, u, u2),
			} {
				placed := verdict(quoted, envelope)
				if placed == "block" {
					placedBlocks++
				}
				want := max(unknown, shapeParityRank[placed])
				got := verdict(expanding, envelope)
				if !target.rotate {
					benignChecked++
				}
				if shapeParityRank[got] < want {
					t.Errorf("%s %s %s (%s): %q, want the unknown tier or the placed %q", target.id, shape.name, kind,
						u, got, placed)
				}
			}
		}
	}
	if benignChecked != 2*len(patchDecoyShapes) {
		t.Errorf("benign envelopes checked %d, want %d", benignChecked, 2*len(patchDecoyShapes))
	}
	if placedBlocks == 0 {
		t.Fatal("no quoted envelope of the fixture targets blocks: the test no longer pins a placed block")
	}
}
