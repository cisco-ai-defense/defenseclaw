// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
)

// A UNC path on a share that does not answer (RFC 5737 TEST-NET-1, which
// nothing answers) comes back as spelled within the share wait of the hook
// call, never after the system connect timeout (about 21 s), in every UNC
// spelling. Each spelling names a fresh address, so no earlier probe answers
// for it. The extended-length spelling (the UNC form after the question-mark
// prefix) comes back in the usual UNC spelling, the one the deny rules and
// the skill roots share (assetfacts.ResolveLinks trims the prefix).
func TestLinkWalkOfAUNCPathOnASilentShareIsBoundedByTheShareWait(t *testing.T) {
	host := 10 + rand.IntN(200)
	defer HookCall()()
	for i, row := range []struct{ path, want string }{
		{fmt.Sprintf(`//192.0.2.%d/share/skills/a/../b/SKILL.md`, host),
			fmt.Sprintf(`\\192.0.2.%d\share\skills\b\SKILL.md`, host)},
		{fmt.Sprintf(`\\?\UNC\192.0.2.%d\share\skills\b\SKILL.md`, host+1),
			fmt.Sprintf(`\\192.0.2.%d\share\skills\b\SKILL.md`, host+1)},
		{fmt.Sprintf(`\\192.0.2.%d\share\skills\b\SKILL.md`, host+2),
			fmt.Sprintf(`\\192.0.2.%d\share\skills\b\SKILL.md`, host+2)},
	} {
		start := time.Now()
		got := assetfacts.ResolveLinks(row.path)
		if took := time.Since(start); took > 1500*time.Millisecond {
			t.Errorf("spelling %d: ResolveLinks took %v, want the share wait and no more", i, took)
		}
		if got != row.want {
			t.Errorf("spelling %d: ResolveLinks = %q, want %q", i, got, row.want)
		}
	}
}
