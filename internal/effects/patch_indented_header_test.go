// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects_test

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// TestPatchIndentedHeader: apply_patch trims a hunk header's leading blanks, so
// an indented header outside an Update File chunk is read; inside a chunk body
// the same line is a context line and is not (S3-PRE security review relayed
// 2026-11-22, DET111 R1; review SF-5).
func TestPatchIndentedHeader(t *testing.T) {
	o := effects.Options{Flavor: effects.FlavorPOSIX, CWD: "/home/u/proj", Home: "/home/u"}
	paths := func(env string) map[string]effects.Kind {
		r := effects.Extract(effects.Call{Surface: effects.SurfacePatch, Tool: "apply_patch", Command: env}, o)
		out := map[string]effects.Kind{}
		for _, e := range r.Effects {
			out[e.Target.Path] = e.Kind
		}
		return out
	}
	got := paths("*** Begin Patch\n  *** Delete File: /home/u/proj/old.txt\n*** End Patch\n")
	if got["/home/u/proj/old.txt"] != effects.KindDelete {
		t.Errorf("indented header: delete not read: %v", got)
	}
	got = paths("*** Begin Patch\n*** Update File: /home/u/proj/a.md\n@@\n *** Delete File: /home/u/proj/old.txt\n+x\n*** End Patch\n")
	if _, ok := got["/home/u/proj/old.txt"]; ok {
		t.Errorf("context line in an update chunk read as a header: %v", got)
	}
}
