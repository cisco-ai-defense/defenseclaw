// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"sort"
	"strings"
	"testing"
)

// Round 8 (GAP-0133..0136): the walker's cwd and environment are certainty
// states, not facts. These tests state the model directly -- which directories
// a command may run in, which environment a child process starts with -- so a
// fix to one shape can not quietly rely on a golden verdict.

func mutKeys(r Result) []string {
	var out []string
	for _, e := range r.Effects {
		if isMutation(e.Kind) && e.TargetState == TargetStateKnown && e.Target.Type == TargetPath && e.Target.Key() != "" {
			out = append(out, e.Target.Key())
		}
	}
	sort.Strings(out)
	return out
}

func extractSh(cmd string, o Options) Result {
	return Extract(Call{Surface: SurfaceShell, Command: cmd}, o)
}

func TestCwdCandidateSet(t *testing.T) {
	const proj = "/home/u/proj/f"
	const cd = "/t/a/f"
	for _, c := range []struct {
		name string
		cmd  string
		want []string
	}{
		// a cd's tail is narrowed to the side of the cd's status it depends on
		{"&& tail runs only in the new directory", `cd /t/a && touch f`, []string{cd}},
		{"|| tail runs only in the old directory", `cd /t/a || touch f`, []string{proj}},
		{"&& chain keeps the narrowing", `cd /t/a && true && touch f`, []string{cd}},
		{"|| after && joins", `cd /t/a && true || touch f`, []string{cd, proj}},
		{"; after a cd may run in either", `cd /t/a; touch f`, []string{cd, proj}},
		{"a block under || is the failure side", `cd /t/a || { touch f; touch g; }`, []string{"/home/u/proj/f", "/home/u/proj/g"}},
		{"a block under && is the success side", `cd /t/a && { touch f; touch g; }`, []string{"/t/a/f", "/t/a/g"}},
		{"if-condition cd may have failed in the else", "if cd /t/a; then :; else touch f; fi", []string{cd, proj}},
		{"absolute targets do not multiply", `cd /t/a; touch /t/b/f`, []string{"/t/b/f"}},
		{"a subshell cd does not move the parent", `(cd /t/a); touch f`, []string{proj}},
		{"pipeline stage cd does not move the parent", `cd /t/a | cat; touch f`, []string{proj}},
		{"two unguarded cds are still a small set", `cd /t/a; cd /t/b; touch f`, []string{"/home/u/proj/f", "/t/a/f", "/t/b/f"}},
		{"cd - is unknown", `cd /t/a; cd -; touch f`, nil},
		{"a dynamic cd is unknown", `cd "$X"; touch f`, nil},
		{"a conditional cd is unknown afterwards", `true && cd /t/a; touch f`, nil},
	} {
		r := extractSh(c.cmd, raLin)
		got := mutKeys(r)
		// dedupe
		var uniq []string
		for i, k := range got {
			if i == 0 || k != got[i-1] {
				uniq = append(uniq, k)
			}
		}
		want := append([]string(nil), c.want...)
		sort.Strings(want)
		if strings.Join(uniq, ",") != strings.Join(want, ",") {
			t.Errorf("%s: known mutations %v, want %v\n%s", c.name, uniq, want, fmtRes(r))
		}
	}
}

func TestCwdOverflowIsDynamic(t *testing.T) {
	r := extractSh(`cd /t/a; cd /t/b; cd /t/c; cd /t/d; cd /t/e; touch f`, raLin)
	for _, k := range mutKeys(r) {
		if strings.HasSuffix(k, "/f") {
			t.Errorf("a cwd set past the candidate bound still placed f: %s\n%s", k, fmtRes(r))
		}
	}
}

func TestChildEnvironment(t *testing.T) {
	for _, c := range []struct {
		name string
		cmd  string
		want []string // known mutation keys
	}{
		{"prefix HOME reaches a child shell", `HOME=/t/h sh -c 'touch ~/f'`, []string{"/t/h/f"}},
		{"env HOME reaches a child shell", `env HOME=/t/h sh -c 'touch ~/f'`, []string{"/t/h/f"}},
		{"prefix HOME through exec", `HOME=/t/h exec sh -c 'touch ~/f'`, []string{"/t/h/f"}},
		{"prefix HOME through nohup", `HOME=/t/h nohup sh -c 'touch ~/f'`, []string{"/t/h/f"}},
		{"prefix HOME through timeout", `HOME=/t/h timeout 5 sh -c 'touch ~/f'`, []string{"/t/h/f"}},
		{"env -i leaves the child no HOME", `env -i sh -c 'touch ~/f'`, nil},
		{"env -u HOME", `env -u HOME sh -c 'touch ~/f'`, nil},
		{"sudo resets the environment", `sudo sh -c 'touch ~/f'`, nil},
		{"sudo -H", `sudo -H sh -c 'touch ~/f'`, nil},
		{"su -c", `su -c 'touch ~/f'`, nil},
		{"the shell's own HOME reaches an unchanged child", `sh -c 'touch ~/f'`, []string{"/home/u/f"}},
		{"an unexported variable is not in the child", `D=/t/a; sh -c 'touch "$D/f"'`, nil},
		{"an exported variable is", `export D=/t/a; sh -c 'touch "$D/f"'`, []string{"/t/a/f"}},
		{"a variable assigned to an inherited name stays inherited", `HOME=/t/h; sh -c 'touch ~/f'`, []string{"/t/h/f"}},
		{"declare -x exports", `declare -x D=/t/a; sh -c 'touch "$D/f"'`, []string{"/t/a/f"}},
		{"declare without -x does not", `declare D=/t/a; sh -c 'touch "$D/f"'`, nil},
		{"prefix assignment reaches the child's variable", `D=/t/a sh -c 'touch "$D/f"'`, []string{"/t/a/f"}},
		{"prefix assignment does not outlive the command", `D=/t/a true; touch "$D/f"`, nil},
		{"printf -v makes the variable unknown", `D=/t/a; printf -v D %s /t/b; touch "$D/f"`, nil},
		{"read makes HOME unknown", `read HOME <<< /t/h; touch ~/f`, nil},
	} {
		r := extractSh(c.cmd, raLin)
		got := mutKeys(r)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: known mutations %v, want %v\n%s", c.name, got, c.want, fmtRes(r))
		}
	}
}

func TestWrappersThatMoveTheCwd(t *testing.T) {
	for _, c := range []struct {
		name string
		cmd  string
		want []string
	}{
		{"env -C", `env -C /t/a touch f`, []string{"/t/a/f"}},
		{"env -C fused", `env -C/t/a touch f`, []string{"/t/a/f"}},
		{"env --chdir=", `env --chdir=/t/a touch f`, []string{"/t/a/f"}},
		{"env --chdir space", `env --chdir /t/a touch f`, []string{"/t/a/f"}},
		{"nice env --chdir=", `nice env --chdir=/t/a touch f`, []string{"/t/a/f"}},
		{"sudo -D", `sudo -D /t/a touch f`, []string{"/t/a/f"}},
		{"sudo --chdir=", `sudo --chdir=/t/a touch f`, []string{"/t/a/f"}},
		{"sudo -i starts in the target's home", `sudo -i touch f`, nil},
		{"sudo -u x -i", `sudo -u x -i touch f`, nil},
		{"su - starts in the target's home", `su - -c 'touch f'`, nil},
		{"runuser -l", `runuser -l x -c 'touch f'`, nil},
		{"find -execdir runs in the match's directory", `find /t/a -name x -execdir touch f \;`, nil},
		{"find -exec runs in the cwd", `find /t/a -name x -exec touch f \;`, []string{"/home/u/proj/f"}},
		{"an unlisted wrapper option is not transparent", `sudo --bogus touch /t/a/f`, nil},
	} {
		r := extractSh(c.cmd, raLin)
		got := mutKeys(r)
		if c.name == "an unlisted wrapper option is not transparent" {
			if r.FullyKnown() {
				t.Errorf("%s: fully known\n%s", c.name, fmtRes(r))
			}
			continue
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: known mutations %v, want %v\n%s", c.name, got, c.want, fmtRes(r))
		}
	}
}

func TestShadowedCdAndCmdlet(t *testing.T) {
	// a PowerShell function of the same name wins over the cmdlet, in any case
	r := Extract(Call{Surface: SurfaceShell, Command: `function Set-Location {}; set-location C:\t; Set-Content authorized_keys k`}, raPS)
	for _, k := range mutKeys(r) {
		if strings.HasSuffix(k, `\t\authorized_keys`) {
			t.Errorf("the shadowed Set-Location still moved the cwd: %s\n%s", k, fmtRes(r))
		}
	}
	// a POSIX function that shadows cd leaves the cwd unknown
	r = extractSh(`cd() { :; }; cd /t/a; touch f`, raLin)
	if len(mutKeys(r)) != 0 {
		t.Errorf("a shadowed cd still placed a relative target: %v\n%s", mutKeys(r), fmtRes(r))
	}
	// the cd builtin disabled or turned into a variable lookup
	for _, cmd := range []string{`enable -n cd; cd /t/a; touch f`, `shopt -s cdable_vars; cd a; touch f`, `alias cd=true; cd /t/a; touch f`} {
		r = extractSh(cmd, raLin)
		if len(mutKeys(r)) != 0 {
			t.Errorf("%q: a relative target after an unreliable cd was placed: %v", cmd, mutKeys(r))
		}
	}
}

func TestDriveAliasesAreNotTheirLetter(t *testing.T) {
	for _, cmd := range []string{
		`subst X: C:\Users\u\.ssh & echo k >> X:\authorized_keys`,
		`net use X: \\host\share & echo k >> X:\authorized_keys`,
	} {
		r := Extract(Call{Surface: SurfaceShell, Command: cmd}, raCmd)
		for _, k := range mutKeys(r) {
			if strings.HasPrefix(k, `x:`) {
				t.Errorf("%q: a rebound drive letter was trusted: %s", cmd, k)
			}
		}
	}
	// an unrelated drive stays known
	r := Extract(Call{Surface: SurfaceShell, Command: `subst X: C:\t & echo k >> D:\f`}, raCmd)
	if len(mutKeys(r)) == 0 {
		t.Errorf("an unrelated drive was demoted\n%s", fmtRes(r))
	}
}
