// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// TestGAP0546LinkResolvedCommandSpellsEachWordAtItsPlace: the path words of
// a command (arguments, a --name=VALUE value, redirect targets, the words of
// a static eval or -c body) are spelled at their places, followed where the
// command opens the file and as the entry where it acts on the name (rm, ls,
// a cp that keeps links); a place a quoted body cannot carry as it is, a word
// with an expansion and an option are left as written (substrate-1 GAP-0546).
func TestGAP0546LinkResolvedCommandSpellsEachWordAtItsPlace(t *testing.T) {
	places := map[string]CommandWordPlace{
		"key-link":      {Followed: "/sandbox/.ssh/id_ed25519"},
		"a/b/ssh":       {Followed: "/sandbox/.ssh"},
		"dc-link":       {Followed: "/sandbox/.defenseclaw/config.yaml"},
		"claude-dir/x":  {Followed: "/sandbox/.claude/x", Entry: "/sandbox/.claude/x"},
		"sp-link":       {Followed: "/sandbox/a b/k"},
		"$K":            {Followed: "/sandbox/.ssh/id_ed25519"},
		"-r":            {Followed: "/sandbox/.ssh"},
		"dir-link/name": {Followed: "/sandbox/.ssh/id_ed25519", Entry: "/sandbox/.ssh/name"},
	}
	for _, row := range []struct{ command, want string }{
		{"cat key-link", "cat /sandbox/.ssh/id_ed25519"},
		{"cd -P a/b/ssh && cat id_ed25519", "cd -P /sandbox/.ssh && cat id_ed25519"},
		{"eval cat key-link", "eval cat /sandbox/.ssh/id_ed25519"},
		{`eval "cat key-link"`, `eval "cat /sandbox/.ssh/id_ed25519"`},
		{`bash -c 'cat key-link; true'`, `bash -c 'cat /sandbox/.ssh/id_ed25519; true'`},
		{"echo x >> dc-link", "echo x >> /sandbox/.defenseclaw/config.yaml"},
		{"cp /tmp/x claude-dir/x", "cp /tmp/x /sandbox/.claude/x"},
		{"cat sp-link", "cat '/sandbox/a b/k'"},
		{`eval "cat sp-link"`, `eval "cat sp-link"`},
		{"tool --in=key-link", "tool --in=/sandbox/.ssh/id_ed25519"},
		{"rm dir-link/name", "rm /sandbox/.ssh/name"},
		{"ls -l dir-link/name", "ls -l /sandbox/.ssh/name"},
		{"cp -a dir-link/name /tmp/y", "cp -a /sandbox/.ssh/name /tmp/y"},
		{"cp dir-link/name /tmp/y", "cp /sandbox/.ssh/id_ed25519 /tmp/y"},
		{"rm key-link", "rm key-link"},
		{"cat $K -r", "cat $K -r"},
		{"cat 'key-link'", "cat 'key-link'"},
	} {
		got, changed := LinkResolvedCommand(row.command, "/sandbox", places)
		if got != row.want || changed != (row.want != row.command) {
			t.Errorf("%q: %q changed=%v, want %q", row.command, got, changed, row.want)
		}
	}
	if got, changed := LinkResolvedCommand("cat key-link", "/sandbox", nil); changed || got != "cat key-link" {
		t.Errorf("no places: %q %v", got, changed)
	}
	if got, changed := LinkResolvedCommand("cat key-link", "/sandbox", map[string]CommandWordPlace{"key-link": {Followed: "relative"}}); changed {
		t.Errorf("relative place: %q", got)
	}
}
