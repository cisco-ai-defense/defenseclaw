// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// The spellings a hook call keeps for its registration names
// (RegistrationSpellings, TST-18078) are the spellings ResolveWriteTarget
// gives, through a linked home, a linked folder, a linked file, a link that
// points nowhere and a missing folder, asked in any order and twice.
func TestRegistrationSpellingsMatchResolveWriteTarget(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	for _, dir := range []string{"home/.claude", "home/proj/sub", "elsewhere/conf"} {
		if err := os.MkdirAll(filepath.Join(real, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"home/.claude/settings.json", "elsewhere/conf/hooks.json"} {
		if err := os.WriteFile(filepath.Join(real, file), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		filepath.Join(root, "home"):                    filepath.Join(real, "home"),
		filepath.Join(real, "home/.codex"):             filepath.Join(real, "elsewhere/conf"),
		filepath.Join(real, "home/proj/settings.json"): filepath.Join(real, "home/.claude/settings.json"),
		filepath.Join(real, "home/proj/dangling.json"): filepath.Join(real, "nowhere/x.json"),
		filepath.Join(real, "home/proj/sub/up"):        "..",
	}
	for link, target := range links {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	home := filepath.Join(root, "home")
	names := []string{
		filepath.Join(home, ".claude/settings.json"),
		filepath.Join(home, ".claude"),
		filepath.Join(home, ".codex/hooks.json"),
		filepath.Join(home, ".codex"),
		filepath.Join(home, "proj/settings.json"),
		filepath.Join(home, "proj/dangling.json"),
		filepath.Join(home, "proj/sub/up/settings.json"),
		filepath.Join(home, "missing/deeper/hooks.json"),
		filepath.Join(real, "home/.claude/settings.json"),
		home,
		"/",
	}
	spellings := NewRegistrationSpellings()
	for pass := 0; pass < 2; pass++ {
		for index := range names {
			name := names[(index*7+pass)%len(names)]
			want, ok := ResolveWriteTarget(name)
			if !ok {
				want = ""
			}
			if got := spellings.physical(name); got != want {
				t.Errorf("pass %d %s: spelling %q, ResolveWriteTarget %q", pass, name, got, want)
			}
		}
	}
}
