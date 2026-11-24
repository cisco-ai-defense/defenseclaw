// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"
	"testing"
)

// TestUnionPOSIXReadingKeepsTheCopySource (GAP-2084, T23 review P3-14): a
// POSIX-only write of a guessed Windows call that copies a credential read
// keeps that read as its data source. Red at 08e285b2a6: the POSIX read was
// not added (only mutations are) and remapSources dropped the producer, so
// the write had no source and the read no content flow (Flow=Copied). Green
// when an unadded producer maps to the guessed reading read of the same file.
func TestUnionPOSIXReadingKeepsTheCopySource(t *testing.T) {
	const out = `C:\Temp\o.txt`
	for _, tc := range []struct{ cmd, member string }{
		{`cat ~/.git-credentials > "` + out + `"; find . -name x -exec true \;`, ".git-credentials"},
		{`cat ~/.git-credentials > "` + out + `" # <<`, ".git-credentials"},
		{`cat ~/.ssh/id_rsa > "` + out + `"; find . -name x -exec true \;`, `.ssh\id_rsa`},
	} {
		r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: tc.cmd}, gap1915Options())
		writes := 0
		for _, e := range r.Effects {
			if e.Kind != KindWrite || !strings.EqualFold(e.Target.Path, out) || e.TargetState != TargetStateKnown {
				continue
			}
			writes++
			if !gap2084HasSourceRead(r, e, tc.member) {
				t.Errorf("%q: write %+v has no source read of %s (effects %+v)", tc.cmd, e, tc.member, r.Effects)
			}
		}
		if writes == 0 {
			t.Errorf("%q: no known write of %s in %+v", tc.cmd, out, r.Effects)
		}
	}
}

func gap2084HasSourceRead(r Result, e Effect, member string) bool {
	if e.Data == nil {
		return false
	}
	for _, s := range e.Data.Sources {
		if s.Kind != SourceEffect || s.Effect < 1 || s.Effect > len(r.Effects) {
			continue
		}
		if src := r.Effects[s.Effect-1]; src.Kind == KindRead && strings.HasSuffix(strings.ToLower(src.Target.Path), strings.ToLower(member)) {
			return true
		}
	}
	return false
}
