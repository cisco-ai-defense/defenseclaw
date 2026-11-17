// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// TestPatchHeredocExpandingBodyIsNeverAllowed{Default,Strict,Permissive,Managed,ManagedStrict}:
// an apply_patch envelope the Codex shell tool feeds by a here-document the
// shell expands is judged at the unknown tier of the pack at least (alert in
// default, permissive and managed, block in strict and managed-strict), and
// each decoy envelope at least as its single-header reference on the same
// route is (the placed block): never a clean allow. An expansion in any line,
// a content line too, may hold newlines and add a header no reader sees, so
// the header set of the envelope is not known (rel-1-0-10:GAP-1093). A
// target name the shell expands is itself a header no reader places
// (GAP-1077), so its reference is judged at the unknown tier, not by the
// path rule its quoted spelling meets.
//
// The envelopes are the decoy shapes of
// TestPatchDecoyHeaderNeverWeakerThanTheSinglePatch (patchDecoyShapes, each
// envelope and its single-header reference) on the codex/heredoc-expanding
// route, for the wincred Write and Edit fixture targets in
// patchHeredocExpandingShapesPerCase of the shapes, rotated by case, and for a
// benign target in every shape. Before GAP-1093, an envelope whose
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

// patchHeredocExpandingShapesPerCase is how many of the patchDecoyShapes each
// fixture target is checked in (the benign target is checked in all of them).
const patchHeredocExpandingShapesPerCase = 2

// patchHeredocExpandingWorkers is how many parallel subtests share the targets.
const patchHeredocExpandingWorkers = 8

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
	var expanding patchDecoyRoute
	for _, route := range patchDecoyRoutes(cwd) {
		if route.name == "codex/heredoc-expanding" {
			expanding = route
		}
	}
	if expanding.call == nil {
		t.Fatal("no codex/heredoc-expanding route in patchDecoyRoutes")
	}
	verdict := func(t *testing.T, envelope string) string {
		call := expanding.call(envelope)
		return shapeParityHook(t, handlers[call.conn], call, p.managed)
	}
	var placedBlocks, benignChecked atomic.Int64
	// The targets are independent; patchHeredocExpandingWorkers subtests take
	// them in turn, in parallel, so the -race shards finish in time.
	t.Run("targets", func(t *testing.T) {
		for w := range patchHeredocExpandingWorkers {
			t.Run(strconv.Itoa(w), func(t *testing.T) {
				t.Parallel()
				for n := w; n < len(targets); n += patchHeredocExpandingWorkers {
					target := targets[n]
					shapes := make([]int, 0, len(patchDecoyShapes))
					if target.rotate {
						for k := range patchHeredocExpandingShapesPerCase {
							shapes = append(shapes, (n+k*len(patchDecoyShapes)/patchHeredocExpandingShapesPerCase)%len(patchDecoyShapes))
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
						reference := verdict(t, shape.reference(target.target, target.body, target.hunk, u, u2))
						if reference == "block" {
							placedBlocks.Add(1)
						}
						got := verdict(t, shape.envelope(target.target, target.body, target.hunk, u, u2))
						if !target.rotate {
							benignChecked.Add(1)
						}
						if shapeParityRank[reference] < unknown {
							t.Errorf("%s %s reference: %q, want the unknown tier at least", target.id, shape.name, reference)
						}
						if shapeParityRank[got] < max(unknown, shapeParityRank[reference]) {
							t.Errorf("%s %s envelope (%s): %q, want the unknown tier or the placed %q", target.id, shape.name,
								u, got, reference)
						}
					}
				}
			})
		}
	})
	if n := benignChecked.Load(); n != int64(len(patchDecoyShapes)) {
		t.Errorf("benign shapes checked %d, want %d", n, len(patchDecoyShapes))
	}
	if placedBlocks.Load() == 0 {
		t.Fatal("no single-header reference of the fixture targets blocks: the test no longer pins a placed block")
	}
}
