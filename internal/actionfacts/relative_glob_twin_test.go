// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestRelativeGlobTwinsNamed is the reading of a pathname pattern in a folder
// the call does not give (rel-1-0-10:GAP-0960): each name it may match, as
// the shell matches a component, a pattern of more components keeping its
// leading ones, one reading per match; a pattern with no literal name, a quoted pattern, a home or
// absolute pattern and a leading wildcard before a dot name are no twin.
func TestRelativeGlobTwinsNamed(t *testing.T) {
	names := []string{"credentials", ".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials"}
	for _, tc := range []struct {
		command string
		want    []string
	}{
		{"cp .ssh/id_* /tmp/s", []string{"cp '.ssh/id_ed25519' /tmp/s", "cp '.ssh/id_rsa' /tmp/s"}},
		{"cat .ssh/id_r*a", []string{"cat '.ssh/id_rsa'"}},
		{"cat .ss?/id_rsa", []string{"cat '.ssh/id_rsa'"}},
		{"cat alice/.ssh/id_r*", []string{"cat 'alice/.ssh/id_rsa'"}},
		{"cat .aws/*", []string{"cat '.aws/credentials'"}},
		{"cat cred* .ssh/id_*", []string{"cat 'credentials' '.ssh/id_ed25519'", "cat 'credentials' '.ssh/id_rsa'"}},
		{"cat *", nil},
		{"cat ./*", nil},
		{"cat */*", nil},
		{"cat '.ssh/id_*'", nil},
		{"cat *ssh/id_rsa", nil},
		{"cat ~/.ssh/id_*", nil},
		{"cat /root/.ssh/id_*", nil},
		{"cat *.go", nil},
	} {
		got := RelativeGlobTwinsNamed(tc.command, "/home/alice", names)
		if !slices.Equal(got.Twins, tc.want) || got.Truncated.Any() {
			t.Errorf("RelativeGlobTwinsNamed(%q) = %q truncated %v; want %q", tc.command, got.Twins, got.Truncated.Reason(), tc.want)
		}
	}
}

// TestRelativeGlobTwinsNamedCap: a pattern that may match more names than
// maxStateGlobMatches is read as its first maxStateGlobMatches matches and
// reports bounded.Items, never no twin (rel-1-0-10:GAP-1003); at the cap it
// is read whole and not truncated. The names are synthetic.
func TestRelativeGlobTwinsNamedCap(t *testing.T) {
	names := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("n%03d", i)
		}
		return out
	}
	at := RelativeGlobTwinsNamed("cat n*", "/home/alice", names(maxStateGlobMatches))
	if len(at.Twins) != maxStateGlobMatches || at.Truncated.Any() || len(at.Capped) != 0 {
		t.Fatalf("at the cap: %d twins, truncated %q, %d capped; want %d, none, 0",
			len(at.Twins), at.Truncated.Reason(), len(at.Capped), maxStateGlobMatches)
	}
	for _, size := range []int{maxStateGlobMatches + 1, 2 * maxStateGlobMatches} {
		past := RelativeGlobTwinsNamed("cat n* other.txt", "/home/alice", names(size))
		if len(past.Twins) != maxStateGlobMatches || !past.Truncated.Has(bounded.Items) {
			t.Fatalf("past the cap (%d names): %d twins, truncated %q; want %d and items",
				size, len(past.Twins), past.Truncated.Reason(), maxStateGlobMatches)
		}
		if len(past.Capped) != maxStateGlobMatches || !slices.Contains(past.Capped, "n000") || slices.Contains(past.Capped, "other.txt") {
			t.Fatalf("past the cap (%d names): capped words %q", size, past.Capped)
		}
		if past.Twins[0] != "cat 'n000' other.txt" {
			t.Fatalf("past the cap (%d names): first twin %q", size, past.Twins[0])
		}
	}
}
