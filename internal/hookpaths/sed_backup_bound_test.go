// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// sedBoundRows are the rows of the second review of s7/sedbak-bound
// (s7-sbrev, rel-1-0-10:GAP-0667, GAP-0668, GAP-0669, GAP-0670). The ids are
// the case ids of that review. Placeholders: {keys} the protected folder,
// {home} the home. A command that spells no "sed" or "perl" in full is the
// point of the GAP-0667 rows (they name the protected folder with a relative
// path): the reading never starts from a text test of the raw command.
var sedBoundRows = []struct{ id, command, want string }{
	// GAP-0667: the program word is what the parser makes of it.
	{"SFXREV-split-prog", "s''ed -i../.ssh/* s/x/y/ authorized_keys", sedBlock},
	{"SBREV2-split-sed", "s''ed -i{keys}/* s/x/y/ authorized_keys", sedBlock},
	{"SBREV2-bs-sed", `s\ed -i../.ssh/* s/x/y/ authorized_keys`, sedBlock},
	{"SBREV2-dq-sed", `"s"ed -i../.ssh/* s/x/y/ authorized_keys`, sedBlock},
	{"SBREV2-split-gsed", "gs''ed -i../.ssh/* s/x/y/ authorized_keys", sedBlock},
	{"SBREV2-split-perl", "p''erl -pi../.ssh/* -e 1 authorized_keys", sedBlock},
	{"SBREV2-split-sed-unres", `s''ed -i"$X" s/x/y/ authorized_keys`, sedUnresolved},
	{"SBREV2-split-sed-envC", "env -C {home} s''ed -i.ssh/* s/x/y/ authorized_keys", sedBlock},
	{"SBREV2-bs-env-sed", `e\nv -C {home} s''ed -i.ssh/* s/x/y/ authorized_keys`, sedBlock},
	{"SBREV2-split-sed-xargs", "echo authorized_keys | xargs s''ed -i../.ssh/* s/x/y/", sedUnresolved},
	{"SBREV2-split-sed-find", `find . -name f -exec s''ed -i../.ssh/* s/x/y/ {} \;`, sedUnresolved},
	{"SBREV2-split-bash-c", `b''ash -c "s''ed -i../.ssh/* s/x/y/ authorized_keys"`, sedBlock},
	{"SBREV2-path-split-sed", "/usr/bin/s''ed -i../.ssh/* s/x/y/ authorized_keys", sedBlock},
	{"SBREV2-C-split-sed-bak", "s''ed -i.bak s/x/y/ f", sedNone},
	{"SBREV2-C-split-perl-bak", "p''erl -pi.bak -e 1 f", sedNone},
	{"SBREV2-C-split-no-inplace", "s''ed s/x/y/ f", sedNone},
	{"SBREV2-C-no-sed-text", "grep -n x f | wc -l", sedNone},

	// GAP-0668: xargs options of the GNU and BSD grammars.
	{"SBREV-xargs-maxargs-sep", "echo authorized_keys | xargs --max-args 1 sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-xargs-maxargs-eq", "echo authorized_keys | xargs --max-args=1 sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-xargs-maxargs-abbrev", "echo authorized_keys | xargs --max-a 1 sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-xargs-delim-sep", "echo authorized_keys | xargs --delimiter , sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-xargs-arg-file", "xargs --arg-file list sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-xargs-max-procs", "echo authorized_keys | xargs --max-procs 4 --max-args 1 sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-xargs-slot-var", "echo authorized_keys | xargs --process-slot-var SLOT sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-xargs-bsd-J", "echo authorized_keys | xargs -J % sed -i{keys}/* s/x/y/ %", sedUnresolved},
	{"SBREV-xargs-bsd-R-S", "echo authorized_keys | xargs -R 5 -S 255 -I {} sed -i{keys}/* s/x/y/ {}", sedUnresolved},
	{"SBREV-xargs-cluster", "echo authorized_keys | xargs -rn 1 sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-xargs-cluster-0", "echo authorized_keys | xargs -0rn1 sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-xargs-eof-sep", "echo authorized_keys | xargs -E END sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-xargs-eof-attached-opt", "echo authorized_keys | xargs -eEND sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-xargs-replace-eq", "echo authorized_keys | xargs --replace=@ sed -i{keys}/* s/x/y/ @", sedUnresolved},
	{"SBREV-xargs-i-default", "echo authorized_keys | xargs -i sed -i{keys}/* s/x/y/ {}", sedUnresolved},
	{"SBREV-xargs-double-dash", "echo authorized_keys | xargs -n 1 -- sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-xargs-unknown-option", "echo authorized_keys | xargs --no-such-option 3 sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-xargs-unknown-option-past-cap", "echo f | xargs --no-such-option 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 grep x", sedUnresolved},
	{"SBREV-gxargs", "echo authorized_keys | gxargs -n 1 sed -i{keys}/* s/x/y/", sedUnresolved},
	{"SBREV-gfind", `gfind . -name f -exec sed -i{keys}/* s/x/y/ {} \;`, sedUnresolved},
	{"SBREV-xargs-replace-static", "echo authorized_keys | xargs --max-args 1 -I @ sed -i{keys}/* s/x/y/ authorized_keys", sedBlock},
	{"SBREV-C-xargs-maxargs", "echo f | xargs --max-args 1 sed -i.bak s/x/y/", sedNone},
	{"SBREV-C-xargs-delim", "echo f | xargs --delimiter , sed -i s/x/y/", sedNone},
	{"SBREV-C-xargs-bsd-J", "echo f | xargs -J % sed -i.bak s/x/y/ %", sedNone},
	{"SBREV-C-xargs-cluster", "git ls-files -z | xargs -0rn 1 sed -i.bak s/a/b/", sedNone},
	{"SBREV-C-xargs-no-sed", "echo f | xargs --max-args 1 grep -i x", sedNone},

	// GAP-0669: brace lists are expanded as bash does.
	{"SBREV-brace-suffix", "sed -i{.bak,{keys}/*} s/x/y/ authorized_keys", sedBlock},
	{"SBREV-brace-suffix-first", "sed -i{{keys}/*,.bak} s/x/y/ authorized_keys", sedNone},
	{"SBREV-brace-long", "sed --in-place={.bak,{keys}/*} s/x/y/ authorized_keys", sedBlock},
	{"SBREV-brace-operand", "sed -i{keys}/* s/x/y/ {f,authorized_keys}", sedBlock},
	{"SBREV-brace-option-word", "sed {-n,-i{keys}/*} s/x/y/ authorized_keys", sedBlock},
	{"SBREV-brace-perl", "perl -pi{.bak,{keys}/*} -e 1 authorized_keys", sedBlock},
	{"SBREV-C-brace-seq", "sed -i{1..3}.bak s/x/y/ f{1..2}", sedNone},
	{"SBREV-brace-overflow-suffix", "sed -i{.bak,x}{1..999} s/x/y/ f", sedUnresolved},
	{"SBREV-brace-overflow-option", "sed {-i,-n}{1..999} s/x/y/ f", sedUnresolved},
	{"SBREV-brace-var-in-list", `sed -i{.bak,"$X"} s/x/y/ f`, sedUnresolved},
	{"SBREV-C-brace-plain", "sed -i.bak s/x/y/ {f,g}", sedNone},
	{"SBREV-C-brace-suffix-plain", "sed -i{.bak,.orig} s/x/y/ f", sedNone},
	{"SBREV-C-brace-quoted", `sed -i"{.bak,x}" s/x/y/ f`, sedNone},
	{"SBREV-C-brace-operand-overflow", "sed -i.bak s/x/y/ file{1..999}", sedNone},
	{"SBREV-C-brace-braces-expr", "sed -i.bak 's/a/{b,c}/' f", sedNone},
	{"SBREV-C-find-braces", `find . -name f -exec sed -i.bak s/x/y/ {} \;`, sedNone},

	// GAP-0670: the residual shapes.
	{"SBREV-heredoc-dev-stdin", "bash /dev/stdin <<'EOF'\nsed -i{keys}/* s/x/y/ authorized_keys\nEOF", sedBlock},
	{"SBREV-heredoc-proc-fd", "bash /proc/self/fd/0 <<'EOF'\nsed -i{keys}/* s/x/y/ authorized_keys\nEOF", sedBlock},
	{"SBREV-source-stdin", "source /dev/stdin <<'EOF'\nsed -i{keys}/* s/x/y/ authorized_keys\nEOF", sedBlock},
	{"SBREV-dot-stdin", ". /dev/stdin <<'EOF'\nsed -i{keys}/* s/x/y/ authorized_keys\nEOF", sedBlock},
	{"SBREV-pipe-chain", "echo 'sed -i{keys}/* s/x/y/ authorized_keys' | cat | bash", sedBlock},
	{"SBREV-pipe-chain-filter", "echo 'sed -i{keys}/* s/x/y/ authorized_keys' | tr a-z A-Z | cat | bash", sedBlock},
	{"SBREV-pipe-block", "{ echo 'sed -i{keys}/* s/x/y/ authorized_keys'; } | bash", sedBlock},
	{"SBREV-pipe-loop", "for i in 1 2; do echo 'sed -i{keys}/* s/x/y/ authorized_keys'; done | sh", sedBlock},
	{"SBREV-pipe-subshell", "(printf '%s\\n' 'sed -i{keys}/* s/x/y/ authorized_keys') | bash -s", sedBlock},
	{"SBREV-pipe-cat-heredoc-chain", "cat <<'EOF' | cat | bash\nsed -i{keys}/* s/x/y/ authorized_keys\nEOF", sedBlock},
	{"SBREV-perl-versioned", "perl5.38.2 -pi{keys}/* -e 1 authorized_keys", sedBlock},
	{"SBREV-perl-major", "perl5 -pi../.ssh/* -e 1 authorized_keys", sedBlock},
	{"SBREV-sudo-D", "sudo -D {home} sed -i.ssh/* s/x/y/ authorized_keys", sedBlock},
	{"SBREV-sudo-D-attached", "sudo -D{home} sed -i.ssh/* s/x/y/ authorized_keys", sedBlock},
	{"SBREV-sudo-chdir", "sudo --chdir={home} sed -i.ssh/* s/x/y/ authorized_keys", sedBlock},
	{"SBREV-sudo-chdir-sep", "sudo -n --chdir {home} sed -i.ssh/* s/x/y/ authorized_keys", sedBlock},
	{"SBREV-sudo-D-dyn", `sudo -D "$D" sed -i.ssh/* s/x/y/ authorized_keys`, sedUnresolved},
	{"SBREV-cd-tilde-minus", "cd ~- && sed -i.ssh/* s/x/y/ authorized_keys", sedUnresolved},
	{"SBREV-cd-tilde-plus", "cd ~+ && sed -i.ssh/* s/x/y/ authorized_keys", sedUnresolved},
	{"SBREV-func-args", `f(){ sed "$@"; }; f -i{keys}/* s/x/y/ authorized_keys`, sedUnresolved},
	{"SBREV-func-args-perl", `f(){ perl "$@"; }; f -pi{keys}/* -e 1 authorized_keys`, sedUnresolved},
	{"SBREV-C-func-args-inplace", `f(){ sed -i.bak "$@"; }; f s/x/y/ file`, sedNone},
	{"SBREV-C-func-args-read", `f(){ sed -n "$@"; }; f 1p file`, sedNone},
	{"SBREV-C-func-args-var", `sed -n "$A" "$F"`, sedNone},
	{"SBREV-C-sudo-D-plain", "sudo -D /tmp sed -i.bak s/x/y/ f", sedNone},
	{"SBREV-C-cd-tilde-home", "cd ~ && sed -i.bak s/x/y/ f", sedNone},
	{"SBREV-C-heredoc-dev-stdin-ord", "bash /dev/stdin <<'EOF'\nsed -i.bak s/x/y/ f\nEOF", sedNone},
	{"SBREV-C-pipe-chain-ord", "echo 'sed -i.bak s/x/y/ f' | cat | bash", sedNone},
	{"SBREV-C-pipe-no-shell", "echo 'x' | cat | wc -l", sedNone},
	{"SBREV-C-perl-version-ord", "perl5.38.2 -pi.bak -e 1 f", sedNone},
}

// TestSedInPlaceBackupBoundRows runs the rows above through the reader.
func TestSedInPlaceBackupBoundRows(t *testing.T) {
	home, proj := sedBackupFixture(t)
	keys := filepath.Join(home, ".ssh")
	for _, tc := range sedBoundRows {
		command := strings.NewReplacer("{keys}", keys, "{home}", home).Replace(tc.command)
		blocked, unresolved := actionSedInPlaceReading(command, proj, home, nil, false)
		got := sedNone
		switch {
		case blocked:
			got = sedBlock
		case unresolved:
			got = sedUnresolved
		}
		if got != tc.want {
			t.Errorf("%s: reading = %s, want %s", tc.id, got, tc.want)
		}
		if exported := SedInPlaceBackupUnresolved(command, proj, home); exported != (tc.want == sedUnresolved) {
			t.Errorf("%s: SedInPlaceBackupUnresolved = %v, want %v", tc.id, exported, tc.want == sedUnresolved)
		}
	}
}

// TestSedXargsGrammar: the options of xargs, GNU and BSD, are read from the
// grammar: the command starts at the first word that is not an option or an
// option value (GAP-0668).
func TestSedXargsGrammar(t *testing.T) {
	for _, tc := range []struct {
		id      string
		words   []string
		child   int // index of the first word of the command
		replace string
		unknown bool
	}{
		{"plain", []string{"xargs", "sed", "-i"}, 1, "", false},
		{"none", []string{"xargs"}, 1, "", false},
		{"short-sep", []string{"xargs", "-n", "1", "sed"}, 3, "", false},
		{"short-attached", []string{"xargs", "-n1", "sed"}, 2, "", false},
		{"cluster", []string{"xargs", "-0rn", "1", "sed"}, 3, "", false},
		{"cluster-attached", []string{"xargs", "-0rn1", "sed"}, 2, "", false},
		{"long-sep", []string{"xargs", "--max-args", "1", "sed"}, 3, "", false},
		{"long-eq", []string{"xargs", "--max-args=1", "sed"}, 2, "", false},
		{"long-abbrev", []string{"xargs", "--max-a", "1", "sed"}, 3, "", false},
		{"long-ambiguous", []string{"xargs", "--ma", "1", "sed"}, 1, "", true},
		{"long-flag", []string{"xargs", "--null", "--verbose", "sed"}, 3, "", false},
		{"long-optional", []string{"xargs", "--eof", "sed"}, 2, "", false},
		{"delimiter", []string{"xargs", "--delimiter", ",", "sed"}, 3, "", false},
		{"short-d", []string{"xargs", "-d", ",", "sed"}, 3, "", false},
		{"arg-file", []string{"xargs", "-a", "list", "sed"}, 3, "", false},
		{"bsd-J", []string{"xargs", "-J", "%", "sed", "%"}, 3, "%", false},
		{"bsd-I", []string{"xargs", "-I", "{}", "sed", "{}"}, 3, "{}", false},
		{"bsd-I-attached", []string{"xargs", "-I@", "sed", "@"}, 2, "@", false},
		{"bsd-R-S", []string{"xargs", "-R", "5", "-S", "255", "sed"}, 5, "", false},
		{"bsd-P-L-s", []string{"xargs", "-P", "4", "-L", "2", "-s", "99", "sed"}, 7, "", false},
		{"i-default", []string{"xargs", "-i", "sed"}, 2, "{}", false},
		{"i-attached", []string{"xargs", "-i@", "sed"}, 2, "@", false},
		{"replace-long", []string{"xargs", "--replace", "sed"}, 2, "{}", false},
		{"replace-long-eq", []string{"xargs", "--replace=@", "sed"}, 2, "@", false},
		{"e-optional", []string{"xargs", "-eEND", "sed"}, 2, "", false},
		{"l-optional", []string{"xargs", "-l", "sed"}, 2, "", false},
		{"double-dash", []string{"xargs", "-n", "1", "--", "-n"}, 4, "", false},
		{"dash-word", []string{"xargs", "-", "x"}, 1, "", false},
		{"unknown-short", []string{"xargs", "-Z", "3", "sed"}, 1, "", true},
		{"unknown-long", []string{"xargs", "--nope", "sed"}, 1, "", true},
		{"missing-value", []string{"xargs", "-n"}, 2, "", false},
	} {
		got := sedXargsRead(tc.words)
		if got.child != tc.child || got.replace != tc.replace || got.unknown != tc.unknown {
			t.Errorf("%s: sedXargsRead(%q) = %+v, want child %d replace %q unknown %v", tc.id, tc.words, got, tc.child, tc.replace, tc.unknown)
		}
	}
}

// sedCallWordsOf makes the words of the first simple command of command.
func sedCallWordsOf(t *testing.T, command string) (words []string, overflow bool) {
	t.Helper()
	file, ok := parseShell(command)
	if !ok || len(file.Stmts) == 0 {
		t.Fatalf("cannot parse %q", command)
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok {
		t.Fatalf("%q is not a simple command", command)
	}
	r := &sedBackupReader{cwd: "/work", home: "/home/u"}
	return r.callWords(call.Args, actionValues{"HOME": r.home, "PWD": r.cwd})
}

// TestSedBraceWordLimits: a brace list is counted before it is expanded,
// and a list past the limit stays one word with a hole (GAP-0669).
func TestSedBraceWordLimits(t *testing.T) {
	got, overflow := sedCallWordsOf(t, "echo a{b,c}d {1..4} {a..c}{1,2} {a,b}{c,d}{e,f}")
	want := []string{"echo", "abd", "acd", "1", "2", "3", "4", "a1", "a2", "b1", "b2", "c1", "c2",
		"ace", "acf", "ade", "adf", "bce", "bcf", "bde", "bdf"}
	if !slices.Equal(got, want) || overflow {
		t.Errorf("words = %q overflow %v, want %q", got, overflow, want)
	}
	got, overflow = sedCallWordsOf(t, "echo x{1..999} y{a,b}{1..999} {1..99999999999999999999} -{i,n}{1..999}")
	if len(got) != 5 || got[1][0] != 'x' || !strings.Contains(got[1], sedHole) || !strings.Contains(got[2], sedHole) || got[3] != "{1..99999999999999999999}" || !overflow {
		t.Errorf("past-the-limit words = %q overflow %v", got, overflow)
	}
	got, overflow = sedCallWordsOf(t, "echo x{1..999} y{1..999}")
	if len(got) != 3 || overflow {
		t.Errorf("a list inside a name is no option: words = %q overflow %v", got, overflow)
	}
	// A quoted brace and a brace in a single word are no list.
	got, _ = sedCallWordsOf(t, `echo "{a,b}" '{a,b}' {a} a{b`)
	if !slices.Equal(got, []string{"echo", "{a,b}", "{a,b}", "{a}", "a{b"}) {
		t.Errorf("literal braces: words = %q", got)
	}
}
