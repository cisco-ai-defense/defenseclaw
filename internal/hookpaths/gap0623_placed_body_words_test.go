// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"slices"
	"testing"
)

// TestGAP0623PlacedWordsReadEvalBodyCdAndDdOutput: the actor's reading
// (PlacedCommandPathWords) placed a word after the cd of an eval or -c body
// nowhere, so eval "cd sub && echo x >> dc-link" kept the word as written
// and the actor missed the write through sub/dc-link, and it did not read
// dd's of= value, so dd of=dc-link was no path word (substrate-1 GAP-0623).
// The body's statements are read from the folder the eval runs in now, and
// of='s value is a word. The cd of a body still moves every word after the
// body, and the laptop's CommandPathWords keeps rel's words.
func TestGAP0623PlacedWordsReadEvalBodyCdAndDdOutput(t *testing.T) {
	const cwd, home = "/w/app", "/w"
	placed := func(command, text string) CommandPathWord {
		t.Helper()
		for _, word := range PlacedCommandPathWords(command, cwd, home) {
			if word.Text == text {
				return word
			}
		}
		t.Fatalf("%s: no word %s", command, text)
		return CommandPathWord{}
	}
	for _, row := range []struct {
		command, text string
		dirs          []string
	}{
		{`eval "cd sub && echo x >> dc-link"`, "dc-link", []string{"/w/app/sub"}},
		{`bash -c 'cd sub && echo x >> dc-link'`, "dc-link", []string{"/w/app/sub"}},
		{`cd a && eval "cd ../b && cat lk"`, "lk", []string{"/w/app/b"}},
		{`eval "cd a || cd b; cat lk"`, "lk", []string{"/w/app/a", "/w/app/b", "/w/app"}},
		{`eval "cat lk && cd sub"`, "lk", []string{"/w/app"}},
		{"dd if=/dev/zero of=dc-link count=1", "dc-link", []string{"/w/app"}},
		{"cd sub && sudo dd of=dc-link", "dc-link", []string{"/w/app/sub"}},
		{`dd of="dc-link"`, `"dc-link"`, []string{"/w/app"}},
	} {
		word := placed(row.command, row.text)
		if word.Unplaced || !slices.Equal(word.Dirs, row.dirs) {
			t.Errorf("%s: %s unplaced=%v dirs %v, want %v", row.command, row.text, word.Unplaced, word.Dirs, row.dirs)
		}
	}
	for _, command := range []string{
		`eval "cd sub"; cat lk`,
		`bash -c "cd sub"; cat lk`,
		`eval 'cd $D && cat lk'`,
		`eval "f() { cd sub; }; f; cat lk"`,
	} {
		if word := placed(command, "lk"); !word.Unplaced || len(word.Dirs) != 0 {
			t.Errorf("%s: lk unplaced=%v dirs %v, want unplaced", command, word.Unplaced, word.Dirs)
		}
	}
	for _, word := range CommandPathWords("dd if=/dev/zero of=dc-link", home) {
		if word.Text == "dc-link" {
			t.Errorf("CommandPathWords reads dd's of= value %q; the laptop keeps rel's words", word.Text)
		}
	}
}
