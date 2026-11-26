// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Spec §2.1 pinned Perl acceptance corpus.
package gateway

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type rv92bRow struct{ id, kind, cmd string }

func rv92bRows() []rv92bRow {
	rows := []rv92bRow{
		{"N01 hashkey y", "w", "perl -e 'my %p; $p{y}=1; unlink \"HP\"; $p{x}=1;'"},
		{"N02 hashkey s", "w", "perl -e 'my %o; $o{s}=1; unlink \"HP\"; $o{t}=2;'"},
		{"N03 arrow key m", "w", "perl -e 'my $h={}; $h->{m}=1; unlink \"HP\"; $h->{n}=1;'"},
		{"N04 filetest -s", "w", "perl -e 'print -s \"notes.txt\"; unlink \"HP\"; print \"x\"'"},
		{"N05 split \\s+ regex", "w", "perl -e 'my @w = split /\\s+/, \"a b\"; unlink \"HP\"; print 1+1'"},
		{"N06 method named s", "w", "perl -e 'package O; sub s {1} package main; O->s(1); unlink \"HP\"; print 1;'"},
		{"N07 q #comment delim", "w", "perl -e 'print q #c\n{a}; unlink \"HP\"; # z\n'"},
		{"N08 s{}NL{}e", "w", "perl -e '$_=\"a\"; s{a}\n{unlink \"HP\"}e;\nprint 1;\n'"},
		{"N09 heredoc __END__", "w", "perl -e 'print <<X;\n__END__\nX\nunlink \"HP\";\n'"},
		{"N10 heredoc dquote", "w", "perl -e 'print <<X;\na \" b\nX\nunlink \"HP\"; print \"c\";\n'"},
		{"N11 pod __END__", "w", "perl -e '=pod\n\n__END__\n\n=cut\n\nunlink \"HP\";\n'"},
		{"N12 format dquote", "w", "perl -e 'format STDOUT =\na \" b\n.\nunlink \"HP\"; print \"c\";\n'"},
		{"N13 utf8 sub eq", "w", "perl -Mutf8 -e 'sub éq{ unlink \"HP\" } éq();'"},
		{"N14 hash elem *unlink", "w", "perl -e 'my %h=(a=>1); print $h{a}*unlink \"HP\"'"},
		{"N15 hash elem &unlink(", "w", "perl -e 'my %h=(a=>1); print $h{a}&unlink(\"HP\")'"},
		{"N16 q => key ctl", "w", "perl -e 'my %h = (q => 1); unlink \"HP\";'"},
		{"N17 hashkey q", "w", "perl -e 'my %h; $h{q}=1; unlink \"HP\"; $h{r}=2'"},
		{"N18 q{} escaped ctl", "w", "perl -e 'print q{a\\}b}; unlink \"HP\"'"},
		{"N19 q{} nested ctl", "w", "perl -e 'print q{a{b}c}; unlink \"HP\"'"},
		{"N20 s{}{}e ctl", "w", "perl -e '$_=\"a\"; s{a}{unlink \"HP\"}e'"},
		{"N21 CORE::GLOBAL ctl", "w", "perl -e 'BEGIN{*CORE::GLOBAL::unlink = sub { CORE::unlink(@_) }} unlink \"HP\"'"},
		{"N22 ref CORE::rename", "w", "perl -e 'my $r = \\&CORE::rename; $r->(\"notes.txt\", \"HP\")'"},
		{"N23 __END__ in string ctl", "w", "perl -e 'print \"x\n__END__\n\"; unlink \"HP\";'"},
		{"N24 CORE::rename ctl", "w", "perl -e 'CORE::rename(\"notes.txt\", \"HP\")'"},
		{"N25 &CORE::rename ctl", "w", "perl -e '&CORE::rename(\"notes.txt\", \"HP\")'"},
		{"N26 hashkey y then open3", "w", "perl -e 'my %p; $p{y}=1; open(my $f, \">\", \"HP\"); print $f 1; $p{x}=1;'"},
		{"N27 -s then open3", "w", "perl -e 'print -s \"notes.txt\"; open(my $f, \">\", \"HP\"); print $f 1; print \"x\"'"},
		{"N28 s{}#c NL{}e", "w", "perl -e '$_=\"a\"; s{a} # c\n {unlink \"HP\"}e;\nprint 1;\n'"},
		{"N29 rename q{a,b} arg", "w", "perl -e 'rename(q{notes.txt}, \"HP\")'"},
		{"N30 y/// tr then unlink ctl", "w", "perl -e '$_=\"a\"; y/a/b/; unlink \"HP\"'"},
		{"B01 sysopen RDONLY|NOFOLLOW", "b", "perl -MFcntl -e 'sysopen(my $f, \"HP\", O_RDONLY|O_NOFOLLOW) or die; print <$f>'"},
		{"B02 sysopen 00", "b", "perl -e 'sysopen(my $f, \"HP\", 00) or die; print <$f>'"},
		{"B03 heredoc text", "b", "perl -e 'print <<X;\nrun: unlink \"HP\" to reset\nX\n'"},
		{"B04 pod text", "b", "perl -e '=pod\n\nunlink \"HP\"\n\n=cut\n\nprint 1;\n'"},
		{"B05 format text", "b", "perl -e 'format STDOUT =\nunlink \"HP\"\n.\nwrite;\n'"},
		{"B06 bare regex rename text", "b", "perl -ne 'print if /rename \"a\", \"HP\"/' notes.txt"},
		{"B07 => key ctl", "b", "perl -e 'my %h = (unlink => \"HP\"); print 1'"},
		{"B08 method unlink ctl", "b", "perl -e 'my $x = bless {}, \"O\"; sub O::unlink {1} $x->unlink(\"HP\")'"},
		{"B09 qq text ctl", "b", "perl -e 'print qq{unlink \"HP\"}'"},
		{"B10 mid-line __END__", "b", "perl -e 'print 1; __END__ unlink \"HP\"'"},
		{"B11 sysopen RDONLY ctl", "b", "perl -MFcntl -e 'sysopen(my $f, \"HP\", O_RDONLY) or die; print <$f>'"},
		{"B12 s{}{} no e ctl", "b", "perl -e '$_=\"a\"; s{a}{unlink \"HP\"}; print'"},
		{"B13 sysopen RDONLY()", "b", "perl -MFcntl -e 'sysopen(my $f, \"HP\", O_RDONLY()) or die; print <$f>'"},
		{"B14 and &unlink user sub", "b", "perl -e 'sub unlink { print 1 } 1 and &unlink(\"HP\")'"},
		{"B15 open read 2arg ctl", "b", "perl -e 'open(F, \"HP\"); print <F>'"},
		{"B16 -n print rename text", "b", "perl -ne 'print \"rename x HP\" if /x/' notes.txt"},
	}
	for i := range rows {
		rows[i].cmd = strings.ReplaceAll(rows[i].cmd, "HP", ".claude/settings.json")
	}
	return rows
}

func TestRV0592bProbe(t *testing.T) {
	h := newGAP0048Home(t)
	rows := rv92bRows()
	for _, profile := range []string{"default", "strict"} {
		judge := newHookConfigJudge(t, "claudecode", profile)
		for _, r := range rows {
			got := hookConfigAction(judge(h.project, false, "Bash", map[string]any{"command": r.cmd}))
			perlSpecCorpusAssert(t, "b", r.id, r.kind, profile, got)
			t.Logf("ROW|%s|%s|%s|%s", profile, r.kind, r.id, got)
		}
	}
}

// Runs each row as real Perl in a temp dir with dummy files: did the hook file change?
func TestRV0592bPerlTruth(t *testing.T) {
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("no perl")
	}
	out, _ := exec.Command("perl", "-v").Output()
	t.Logf("PERLV|%s", strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0])
	for _, r := range rv92bRows() {
		dir := t.TempDir()
		_ = os.MkdirAll(filepath.Join(dir, ".claude"), 0o755)
		hook := filepath.Join(dir, ".claude", "settings.json")
		_ = os.WriteFile(hook, []byte("{}\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("a b\n"), 0o644)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c := exec.CommandContext(ctx, "bash", "-c", r.cmd)
		c.Dir = dir
		o, err := c.CombinedOutput()
		cancel()
		st, serr := os.Lstat(hook)
		changed := "same"
		if serr != nil {
			changed = "GONE"
		} else if st.Mode()&os.ModeSymlink != 0 {
			changed = "SYMLINK"
		} else if b, _ := os.ReadFile(hook); string(b) != "{}\n" {
			changed = "MODIFIED"
		}
		msg := strings.ReplaceAll(strings.TrimSpace(string(o)), "\n", " ")
		if len(msg) > 80 {
			msg = msg[:80]
		}
		t.Logf("PERL|%s|%s|%s|err=%v|%s", r.kind, r.id, changed, err != nil, msg)
	}
}
