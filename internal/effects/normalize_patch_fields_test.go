// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// TestNormalizePatchEnvelopeFields: a patch tool's envelope is read from
// OpenCode's patchText / patch_text too, and every field holding an envelope
// is read (S3-PRE security review relayed 2026-11-22, DET111 R1).
func TestNormalizePatchEnvelopeFields(t *testing.T) {
	env := func(path string) string {
		return "*** Begin Patch\n*** Add File: " + path + "\n+x\n*** End Patch\n"
	}
	for _, k := range []string{"patchText", "patch_text"} {
		args, _ := json.Marshal(map[string]string{k: env("/home/u/proj/a.txt")})
		c := effects.Normalize("opencode", "apply_patch", args)
		if c.Surface != effects.SurfacePatch || !strings.Contains(c.Command, "/home/u/proj/a.txt") {
			t.Errorf("%s: surface %q command %q", k, c.Surface, c.Command)
		}
	}
	args, _ := json.Marshal(map[string]string{"patch": env("/home/u/proj/a.txt"), "input": env("/home/u/proj/b.txt")})
	c := effects.Normalize("codex", "apply_patch", args)
	if !strings.Contains(c.Command, "/home/u/proj/a.txt") || !strings.Contains(c.Command, "/home/u/proj/b.txt") {
		t.Errorf("two envelopes: only one read: %q", c.Command)
	}
	r := effects.Extract(c, effects.Options{Flavor: effects.FlavorPOSIX, CWD: "/home/u/proj", Home: "/home/u"})
	got := map[string]bool{}
	for _, e := range r.Effects {
		got[e.Target.Path] = true
	}
	if !got["/home/u/proj/a.txt"] || !got["/home/u/proj/b.txt"] {
		t.Errorf("two envelopes: effects do not name both files: %+v", r.Effects)
	}
}
