// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
	"testing"
)

// GAP-1774: every link name ln creates or replaces is a write path fact;
// the link target is not a path the call reads or writes.
func TestLinkNamesAreWrites(t *testing.T) {
	for _, tc := range []struct {
		command string
		writes  []string
		partial bool
	}{
		{"ln -sf /tmp/x /h/.defenseclaw/config.yaml", []string{"/h/.defenseclaw/config.yaml"}, false},
		{"ln -sfn /tmp/x /h/.defenseclaw/hooks", []string{"/h/.defenseclaw/hooks"}, false},
		{"ln -sf /tmp/x /h/.defenseclaw/hooks/", []string{"/h/.defenseclaw/hooks/x"}, false},
		{"ln -sfT /tmp/x /h/.defenseclaw/hooks", []string{"/h/.defenseclaw/hooks"}, false},
		{"ln -sfh /tmp/x /h/.defenseclaw/hooks", []string{"/h/.defenseclaw/hooks"}, false},
		{"ln -s -t /h/d /tmp/a /tmp/b/", []string{"/h/d/a", "/h/d/b"}, false},
		{"ln --target-directory=/h/d /tmp/a", []string{"/h/d/a"}, false},
		{"ln /tmp/a /tmp/b /h/d/", []string{"/h/d/a", "/h/d/b"}, false},
		{"ln -s /h/.defenseclaw/config.yaml", []string{"/w/config.yaml"}, false},
		{"ln -s /h/.defenseclaw/config.yaml ./link", []string{"/w/link"}, false},
		{"ln -s -S .bak /tmp/x /h/f", []string{"/h/f"}, false},
		{"ln -Q /tmp/x /h/f", []string{"/h/f"}, true},
		{"ln -T -t /h/d /tmp/x", nil, true},
		{"ln", nil, true},
	} {
		facts := Analyze(Input{Tool: "Bash", Command: tc.command, CWD: "/w", ActiveHome: "/h"})
		var writes []string
		for _, p := range facts.Paths {
			if p.Access == PathAccessWrite {
				writes = append(writes, p.Resolved)
			} else {
				t.Errorf("%q: unexpected %s fact %q", tc.command, p.Access, p.Resolved)
			}
		}
		if !slices.Equal(writes, tc.writes) {
			t.Errorf("%q: writes %q, want %q", tc.command, writes, tc.writes)
		}
		if partial := facts.Parse.Status != StatusComplete; partial != tc.partial {
			t.Errorf("%q: parse %+v, want partial=%t", tc.command, facts.Parse, tc.partial)
		}
	}
	for argv, want := range map[string][]string{
		"ln -sf /tmp/x /h/.defenseclaw": {"/tmp/x"},
		"ln -s -t /h/d /tmp/a /tmp/b/":  {"/tmp/a", "/tmp/b/"},
		"ln /tmp/a /tmp/b /h/d":         {"/tmp/a", "/tmp/b"},
		"ln -T -t /h/d /tmp/x":          nil,
	} {
		if got := LinkTargets(strings.Fields(argv)); !slices.Equal(got, want) {
			t.Errorf("LinkTargets(%q) = %q, want %q", argv, got, want)
		}
	}
	if facts := Analyze(Input{Tool: "Bash", Command: "ln --version", CWD: "/w"}); len(facts.Paths) != 0 || facts.Commands[0].Effect != EffectPreview {
		t.Errorf("ln --version: %+v %+v", facts.Paths, facts.Commands)
	}
}

// GAP-2077: chmod takes the BSD/macOS symlink options before the mode, so
// the target keeps its path fact and the parse stays complete.
func TestChmodSymlinkOptionsKeepTheTarget(t *testing.T) {
	for _, command := range []string{
		"chmod -h 777 ~/.defenseclaw/hooks",
		"chmod -RH 777 ~/.defenseclaw/hooks",
		"chmod -R -L o+w ~/.defenseclaw/hooks",
		"chmod -R -P g+w ~/.defenseclaw/hooks",
	} {
		facts := Analyze(Input{Tool: "Bash", Command: command, CWD: "/h/p", ActiveHome: "/h"})
		if facts.Parse.Status != StatusComplete || !hasPathFact(facts, PathAccessMetadata, "/h/.defenseclaw/hooks") {
			t.Errorf("%q: parse %+v paths %+v", command, facts.Parse, facts.Paths)
		}
	}
}
