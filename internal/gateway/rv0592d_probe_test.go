// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRV0592dProbe(t *testing.T) {
	h := newGAP0048Home(t)
	rows := []struct{ id, kind, cmd string }{
		{"C01 custom sub", "w", `perl -e 'sub O_CUSTOM () { 1 }; sysopen(my $f, ".claude/settings.json", O_CUSTOM) or die $!; print $f "x"'`},
		{"C02 use constant", "w", `perl -e 'use constant O_CUSTOM => 1; sysopen(my $f, ".claude/settings.json", O_CUSTOM) or die $!; print $f "x"'`},
		{"C03 amp sub", "w", `perl -e 'sub O_X { 1 }; sysopen(my $f, ".claude/settings.json", &O_X) or die $!; print $f "x"'`},
		{"C04 spoof O_NOFOLLOW", "w", `perl -e 'sub O_NOFOLLOW () { 1 }; sysopen(my $f, ".claude/settings.json", O_NOFOLLOW) or die $!; print $f "x"'`},
	}
	for _, profile := range []string{"default", "strict"} {
		judge := newHookConfigJudge(t, "claudecode", profile)
		for _, r := range rows {
			got := hookConfigAction(judge(h.project, false, "Bash", map[string]any{"command": r.cmd}))
			perlSpecCorpusAssert(t, "d", r.id, r.kind, profile, got)
			t.Logf("ROW|%s|%s|%s|%s", profile, r.kind, r.id, got)
		}
	}
}

func TestRV0592dEdge(t *testing.T) {
	h := newGAP0048Home(t)
	rows := []struct{ id, kind, cmd string }{
		{"E01 mode var", "w", `perl -e 'my $m=">"; open(F,$m,".claude/settings.json"); print F "x"'`},
		{"E02 mode concat", "w", `perl -e 'open(F, ">" . "", ".claude/settings.json"); print F "x"'`},
		{"E03 read then write same line", "w", `perl -e 'open(F,"<notes.txt"); open(G,">.claude/settings.json"); print G "x"'`},
		{"E04 two arg plus less", "w", `perl -e 'open(F,"+<.claude/settings.json"); print F "x"'`},
		{"E05 layer raw write", "w", `perl -e 'open(F,"<:raw","notes.txt"); open(G,">:raw",".claude/settings.json"); print G "x"'`},
		{"E06 heredoc after reads", "w", `perl -e 'open(F,"<notes.txt"); my $s=<<X;
hello
X
open(G,">.claude/settings.json"); print G "x"'`},
		{"E07 end marker after reads", "b", `perl -e 'open(F,"<notes.txt");
__END__
open(G,">.claude/settings.json"); print G "x"'`},
		{"E08 trailing write after 600 reads", "w", "perl -e '" + strings.Repeat(`open(F,"<notes.txt");`, 600) + `open(G,">.claude/settings.json"); print G "x"'`},
		{"E09 middle write in 600 reads", "w", "perl -e '" + strings.Repeat(`open(F,"<notes.txt");`, 300) + `open(G,">.claude/settings.json"); print G "x";` + strings.Repeat(`open(F,"<notes.txt");`, 300) + "'"},
		{"E10 newline boundary", "w", `perl -e 'open(F,"<notes.txt");
 open(G,">.claude/settings.json"); print G "x"'`},
		{"E11 comment boundary", "w", `perl -e 'open(F,"<notes.txt"); # comment
 open(G,">.claude/settings.json"); print G "x"'`},
		{"E12 package flag", "w", `perl -MFcntl -e 'sysopen(my $f,".claude/settings.json",Fcntl::O_WRONLY) or die $!; print $f "x"'`},
		{"E13 posix flag", "w", `perl -MPOSIX -e 'sysopen(my $f,".claude/settings.json",POSIX::O_WRONLY) or die $!; print $f "x"'`},
		{"E14 hash flag", "w", `perl -e 'my %f=(w=>1); sysopen(my $f,".claude/settings.json",$f{w}) or die $!; print $f "x"'`},
		{"E15 hex flag", "w", `perl -e 'sysopen(my $f,".claude/settings.json",0x241) or die $!; print $f "x"'`},
		{"E16 numeric expr", "w", `perl -e 'sysopen(my $f,".claude/settings.json",1|64) or die $!; print $f "x"'`},
		{"E17 variable flag", "w", `perl -e 'my $w=1; sysopen(my $f,".claude/settings.json",$w) or die $!; print $f "x"'`},
		{"E18 default arithmetic", "w", `perl -e 'use Fcntl qw(:DEFAULT); sysopen(my $f,".claude/settings.json",O_WRONLY+O_CREAT) or die $!; print $f "x"'`},
		{"E19 sysopen four args", "w", `perl -e 'sysopen(my $f,".claude/settings.json",0x241,0600) or die $!; print $f "x"'`},
		{"E20 read nofollow", "b", `perl -MFcntl -e 'sysopen(my $f,".claude/settings.json",O_RDONLY|O_NOFOLLOW) or die $!; print <$f>'`},
	}
	for _, profile := range []string{"default", "strict"} {
		judge := newHookConfigJudge(t, "claudecode", profile)
		for _, r := range rows {
			got := hookConfigAction(judge(h.project, false, "Bash", map[string]any{"command": r.cmd}))
			perlSpecCorpusAssert(t, "d", r.id, r.kind, profile, got)
			t.Logf("EDGE|%s|%s|%s|%s", profile, r.kind, r.id, got)
		}
	}
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl absent")
	}
	for _, r := range rows {
		dir := t.TempDir()
		_ = os.Mkdir(filepath.Join(dir, ".claude"), 0700)
		p := filepath.Join(dir, ".claude", "settings.json")
		_ = os.WriteFile(p, []byte("{}"), 0600)
		_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("a"), 0600)
		cmd := exec.Command("bash", "-c", r.cmd)
		cmd.Dir = dir
		o, err := cmd.CombinedOutput()
		b, _ := os.ReadFile(p)
		changed := string(b) != "{}"
		t.Logf("TRUTH|%s|%s|%t|err=%v|%s", r.kind, r.id, changed, err, strings.ReplaceAll(string(o), "\n", " "))
	}
}
