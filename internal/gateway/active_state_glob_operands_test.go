// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"slices"
	"testing"
)

// GAP-2047: an operand the shell expands (a pattern or a brace list), an
// rsync into the state and a git clean of it reach protected state as
// surely as the plain spelling, so they block in every mode; cleanup and
// copies out that no protected name can match stay allowed with no state
// finding.
func TestGlobbedOperandsOfActiveState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	_, cwd := r105StateFixture(t)
	rows := []r105StateRow{
		{"rm root star", "rm -rf ~/.defenseclaw/*", true, ""},
		{"rm hooks star", "rm -rf ~/.defenseclaw/hooks/*", true, ""},
		{"rm brace trees", "rm -rf ~/.defenseclaw/{installer,hooks}", true, ""},
		{"rm brace log and hooks", "rm -rf ~/.defenseclaw/{logs,hooks}", true, ""},
		{"rm prefix glob", "rm -rf ~/.defenseclaw/instal*", true, ""},
		{"rm config glob", "rm -f ~/.defenseclaw/config.*", true, ""},
		{"rm bracket glob", "rm -rf ~/.defenseclaw/[hp]ooks", true, ""},
		{"rm dot glob home", "rm -rf ~/.d*", true, ""},
		{"rm question glob", "rm -rf ~/.defenseclaw/p?licies", true, ""},
		{"mv hooks star away", "mv ~/.defenseclaw/hooks/* /tmp/", true, ""},
		{"rsync delete into hooks", "rsync -a --delete /tmp/empty/ ~/.defenseclaw/hooks/", true, ""},
		{"rsync delete into root", "rsync -a --delete /tmp/empty/ ~/.defenseclaw/", true, ""},
		{"rsync into policies", "rsync -a /tmp/x/ ~/.defenseclaw/policies/", true, ""},
		{"git clean root", "git clean -fdx ~/.defenseclaw", true, ""},
		{"git clean hooks", "git clean -f -d ~/.defenseclaw/hooks", true, ""},
		{"cp star into root", "cp /tmp/fcdir/* ~/.defenseclaw/", true, ""},
		{"cp yaml into policies", "cp /tmp/x/*.yaml ~/.defenseclaw/policies/", true, ""},
		// Allowed: no protected name can match, or the state is only read.
		{"rm root logs glob", "rm -f ~/.defenseclaw/*.log", false, ""},
		{"rm logs tree star", "rm -rf ~/.defenseclaw/logs/*", false, ""},
		{"rm brace logs tmp", "rm -rf ~/.defenseclaw/{logs,tmp}", false, ""},
		{"rm project tmp glob", "rm -f *.tmp build/*.o", false, ""},
		{"rm home star no dots", "rm -rf ~/proj-old/*", false, ""},
		{"cp state out", "cp -r ~/.defenseclaw/* /tmp/backup/", false, ""},
		{"rsync state out", "rsync -a ~/.defenseclaw/ /tmp/backup/", false, ""},
		{"rsync remote dest", "rsync -a --delete /tmp/x/ host:~/.defenseclaw/", false, ""},
		{"git clean dry run", "git clean -n -d ~/.defenseclaw", false, ""},
		{"git clean project", "git clean -fdx", false, ""},
		{"ls state glob", "ls -la ~/.defenseclaw/*", false, ""},
		{"cp txt into root", "cp /tmp/x/*.txt ~/.defenseclaw/", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, cwd, rows, true)
	}
}

func TestExpandStateBraces(t *testing.T) {
	for word, want := range map[string][]string{
		"a/{b,c}":      {"a/b", "a/c"},
		"{x,y}/{1,2}":  {"x/1", "x/2", "y/1", "y/2"},
		"a/{b,{c,d}}e": {"a/be", "a/ce", "a/de"},
		"a/{b}":        {"a/{b}"},
		"plain":        {"plain"},
		"a/{1..3}":     {"a/{1..3}"},
		"x/{a,b":       {"x/{a,b"},
	} {
		if got := expandStateBraces(word); !slices.Equal(got, want) {
			t.Errorf("expandStateBraces(%q) = %q, want %q", word, got, want)
		}
	}
}
