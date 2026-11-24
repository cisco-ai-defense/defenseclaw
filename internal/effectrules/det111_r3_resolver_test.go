// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

// DET111 step 4, class R3 (DESIGN D3): one path resolver and one protected-set
// classifier. Each row is a gap's own spelling, read by effects.Extract and
// graded by Project with a fake link resolver (no disk). Red at a64bfdb931,
// green with the resolver families. Rows marked fp are false-positive guards:
// they must stay out of every protected set.

type r3Row struct {
	gap   string
	o     effects.Options
	c     effects.Call
	links map[string]string // lexical path -> physical path the resolver returns
	// want maps a protected set (or "*" for every set) to the weakest grade the
	// strongest effect of the call must reach: known, unknown, or no (exactly
	// no match: the false-positive guard).
	want map[string]string
	// path, when set, is a target Path some effect must carry exactly.
	path string
	// kind, when set, grades only the effects of this kind (the call's other
	// effects, such as the ln that made a link, are not the proof).
	kind effects.Kind
}

func r3Opts() (px, ph, wps, wpsh, wgb, wgbh effects.Options) {
	px = effects.Options{Flavor: effects.FlavorPOSIX, Home: "/home/dcku", CWD: "/home/dcku/proj", Login: "dcku",
		Env: map[string]string{"HOME": "/home/dcku"}}
	ph = px
	ph.CWD = "/home/dcku"
	wps = effects.Options{Flavor: effects.FlavorWindows, Dialect: effects.DialectPowerShell, Home: `C:\Users\u`, CWD: `C:\work`,
		Drive: "C", CaseInsensitive: true, Env: map[string]string{"USERPROFILE": `C:\Users\u`}}
	wpsh = wps
	wpsh.CWD = `C:\Users\u`
	wgb = effects.Options{Flavor: effects.FlavorWindows, Dialect: effects.DialectPOSIX, Home: `C:\Users\u`, CWD: `C:\Users\u\proj`,
		Drive: "C", CaseInsensitive: true, Env: map[string]string{"HOME": `C:\Users\u`}}
	wgbh = wgb
	wgbh.CWD = `C:\Users\u`
	return
}

func r3Rows() []r3Row {
	px, ph, wps, wpsh, wgb, wgbh := r3Opts()
	acct := px
	acct.Accounts = map[string]string{"other": "/home/other"}
	sh := func(c string) effects.Call { return effects.Call{Surface: effects.SurfaceShell, Command: c} }
	patch := func(header string) effects.Call {
		return effects.Call{Surface: effects.SurfacePatch, Tool: "apply_patch",
			Args: []byte(`{"input":"*** Begin Patch\n*** Add File: ` + strings.ReplaceAll(header, `\`, `\\`) + `\n+k\n*** End Patch"}`)}
	}
	K, U, N := "known", "unknown", "no"
	return []r3Row{
		// home spellings
		{gap: "GAP-1678 ~login hook config", o: px, c: sh(`echo k >> ~dcku/.claude/settings.json`), want: map[string]string{SetAgentHookConfig: K}},
		// cp cannot decide whether the destination names a file or directory;
		// keep this active-login operand at Maybe until its target is resolved.
		{gap: "GAP-1678 ~login keys", o: px, c: sh(`cp x ~dcku/.ssh/authorized_keys`), want: map[string]string{SetSSHAuthorizedKeys: U}},
		{gap: "GAP-1677 ~other/../login keys", o: acct, c: sh(`echo k >> ~other/../dcku/.ssh/authorized_keys`),
			links: map[string]string{"/home/other/../dcku/.ssh/authorized_keys": "/home/dcku/.ssh/authorized_keys"},
			want:  map[string]string{SetSSHAuthorizedKeys: K}},
		{gap: "GAP-1677 ~other/../login state, unresolved", o: acct, c: sh(`echo k >> ~other/../dcku/.defenseclaw/config.yaml`),
			want: map[string]string{SetSelfProtection: U}},
		{gap: "GAP-0898 ~account the walker cannot place, credential", o: px, c: sh(`cat ~x/.aws/credentials`), want: map[string]string{SetCredentials: U}},
		{gap: "GAP-0898 ~account the walker cannot place, key", o: px, c: sh(`cat ~root/.ssh/id_rsa`), want: map[string]string{SetCredentials: U}},
		{gap: "GAP-0898 fp: ~account, ordinary file", o: px, c: sh(`cat ~x/notes.txt`), want: map[string]string{"*": N}},
		{gap: "GAP-0948 ~.. is a literal folder", o: px, c: sh(`echo k >> ~../x`), path: "/home/dcku/proj/~../x",
			want: map[string]string{"*": N}},
		{gap: "GAP-0948 quoted tilde is a literal folder", o: px, c: sh(`echo k >> '~/notes'`), path: "/home/dcku/proj/~/notes",
			want: map[string]string{"*": N}},
		// dot-dot and links
		{gap: "GAP-1648 find $HOME/.. -delete", o: px, c: sh(`find $HOME/.. -type f -delete`),
			links: map[string]string{"/home/dcku/..": "/home"}, want: map[string]string{"*": K}},
		{gap: "GAP-1648 find /.. -delete unresolved", o: px, c: sh(`find /.. -type f -delete`), want: map[string]string{"*": U}},
		{gap: "GAP-1648 find ~ -delete", o: px, c: sh(`find ~ -type f -delete`), want: map[string]string{"*": K}},
		{gap: "GAP-1020 x/../ glob", o: ph, c: sh(`cat proj/../.ss*/id_*`), want: map[string]string{SetCredentials: U}},
		{gap: "GAP-0443 .. after a wildcard", o: px, c: sh(`echo k > u*/../keydir/authorized_keys`), want: map[string]string{SetSSHAuthorizedKeys: U}},
		// working folder
		{gap: "GAP-1608 $PWD/../ glob", o: px, c: sh(`cat $PWD/../.ssh/id_*`), want: map[string]string{SetCredentials: U}},
		{gap: "GAP-1608 $PWD after cd", o: px, c: sh(`cd ~/.ssh && echo k >> "$PWD/authorized_keys"`), want: map[string]string{SetSSHAuthorizedKeys: K}},
		{gap: "GAP-1608 $(pwd)/../ glob", o: px, c: sh(`cat $(pwd)/../.ssh/id_*`), want: map[string]string{SetCredentials: U}},
		{gap: "GAP-1535 $(pwd) on a Windows working folder", o: wgbh, c: sh(`cat $(pwd)/.ssh/id_rsa`), want: map[string]string{SetCredentials: K}},
		{gap: "GAP-1043 pwd function", o: ph, c: sh(`pwd() { echo /tmp; }; cat $(pwd)/.ssh/id_rsa`), want: map[string]string{SetCredentials: U}},
		{gap: "GAP-1043 pwd function, backquotes", o: px, c: sh("pwd() { echo /tmp; }; echo k >> `pwd`/.ssh/authorized_keys"),
			want: map[string]string{SetSSHAuthorizedKeys: U}},
		{gap: "GAP-1043 pwd function printing another home", o: px, c: sh(`pwd() { echo /home/other; }; cat $(pwd)/.ssh/id_rsa`),
			path: "/home/other/.ssh/id_rsa", want: map[string]string{SetCredentials: K}},
		{gap: "GAP-1043 fp: pwd function printing the project", o: px, c: sh(`pwd() { echo /home/dcku/proj; }; cat $(pwd)/notes.txt`),
			path: "/home/dcku/proj/notes.txt", want: map[string]string{"*": N}},
		{gap: "GAP-1043 fp: read of ssh config behind an unread prefix", o: px, c: sh(`sed -n 1,40p "$X/.ssh/config"`), want: map[string]string{"*": N}},
		{gap: "GAP-1043 fp: AGENTS.md read in a loop", o: px, c: sh(`for d in / /home; do cat "$d/AGENTS.md"; done`), want: map[string]string{"*": N}},
		{gap: "GAP-2123 PWD suffix shell rc", o: px, c: sh(`echo y >> ${PWD%/proj}/.bashrc`),
			path: "/home/dcku/.bashrc", kind: effects.KindAppend, want: map[string]string{SetShellRC: K}},
		{gap: "GAP-2123 project lookalike", o: px, c: sh(`echo y >> ${PWD%/proj}/proj/.bashrc.fixture`),
			path: "/home/dcku/proj/.bashrc.fixture", kind: effects.KindAppend, want: map[string]string{"*": N}},
		{gap: "GAP-1244 ${PWD%suffix}", o: px, c: sh(`cat ${PWD%/proj}/.ssh/id_rsa`), want: map[string]string{SetCredentials: K}},
		{gap: "GAP-1244 ${PWD%/*}", o: px, c: sh(`cat "${PWD%/*}/.aws/credentials"`), want: map[string]string{SetCredentials: K}},
		{gap: "GAP-1244 ${PWD/proj/}", o: px, c: sh(`cat ${PWD/proj/}.ssh/id_rsa`), want: map[string]string{SetCredentials: K}},
		{gap: "GAP-1244 ${PWD:0:10}", o: px, c: sh(`cat ${PWD:0:10}/.aws/credentials`), want: map[string]string{SetCredentials: K}},
		// The substring with a negative length or offset, the anchored
		// replacement and an escaped literal in the pattern (bash 4.2+).
		{gap: "GAP-1244 ${PWD:0:-5}", o: px, c: sh(`cat ${PWD:0:-5}/.ssh/id_rsa`), path: "/home/dcku/.ssh/id_rsa", want: map[string]string{SetCredentials: K}},
		{gap: "GAP-1244 ${PWD::-5}", o: px, c: sh(`cat ${PWD::-5}/.ssh/id_rsa`), path: "/home/dcku/.ssh/id_rsa", want: map[string]string{SetCredentials: K}},
		{gap: "GAP-1244 ${PWD:(-15):10}", o: px, c: sh(`cat ${PWD:(-15):10}/.aws/credentials`), path: "/home/dcku/.aws/credentials", want: map[string]string{SetCredentials: K}},
		{gap: "GAP-1244 ${PWD/%suffix/} escaped", o: px, c: sh(`cat "${PWD/%\/proj/}/.ssh/id_rsa"`), path: "/home/dcku/.ssh/id_rsa", want: map[string]string{SetCredentials: K}},
		{gap: "GAP-1244 ${PWD/#prefix/home} escaped", o: px, c: sh(`cat ${PWD/#\/home\/dcku\/proj//home/dcku}/.ssh/id_rsa`), path: "/home/dcku/.ssh/id_rsa", want: map[string]string{SetCredentials: K}},
		{gap: "GAP-1244 fp: ${PWD:0:-5} project file", o: px, c: sh(`cat ${PWD:0:-5}/proj/notes.txt`), path: "/home/dcku/proj/notes.txt", want: map[string]string{"*": N}},
		{gap: "GAP-1244 fp: anchored suffix that does not match", o: px, c: sh(`cat ${PWD/%\/x/}/notes.txt`), path: "/home/dcku/proj/notes.txt", want: map[string]string{"*": N}},
		{gap: "GAP-1244 substring past the start is an expansion error", o: px, c: sh(`cat ${PWD:5:-40}/.ssh/id_rsa`), want: map[string]string{SetCredentials: U}},
		{gap: "GAP-1037 lastpipe cd", o: px, c: sh(`shopt -s lastpipe; echo x | cd ~/.ssh; cat id_rsa`), want: map[string]string{SetCredentials: K}},
		{gap: "GAP-1037 pipe cd may run here (zsh)", o: px, c: sh(`echo x | cd ~/.ssh; cat id_rsa`), want: map[string]string{SetCredentials: K}},
		{gap: "GAP-1037 fp: cd in a middle stage", o: px, c: sh(`shopt -s lastpipe; cd ~/.ssh | cat; cat notes.txt`), want: map[string]string{"*": N}},
		{gap: "GAP-1483 fp: chroot / sh heredoc writes under /", o: ph, c: sh("chroot / sh <<'E'\n: >> .defenseclaw/config.yaml\nE"),
			path: "/.defenseclaw/config.yaml", want: map[string]string{"*": N}},
		{gap: "GAP-1483 fp: chroot / sh -c", o: ph, c: sh(`chroot / sh -c ': >> .defenseclaw/config.yaml'`), want: map[string]string{"*": N}},
		{gap: "GAP-1483 chroot elsewhere is unknown", o: ph, c: sh(`chroot /srv/r sh -c ': >> .defenseclaw/config.yaml'`),
			want: map[string]string{SetSelfProtection: U}},
		{gap: "GAP-1535 ~+ on a Windows working folder", o: wgb, c: sh(`cd 'C:\Users\u' && cat ~+/.ssh/id_rsa`), want: map[string]string{SetCredentials: K}},
		{gap: "GAP-1556 $env:X folder, keys", o: wps, c: sh(`Set-Location $env:X; Set-Content -Path authorized_keys -Value x`),
			want: map[string]string{SetSSHAuthorizedKeys: U}},
		{gap: "GAP-1556 $env:X folder, state", o: wps, c: sh(`Set-Location $env:X; Set-Content -Path config.yaml -Value x`),
			want: map[string]string{SetSelfProtection: U}},
		{gap: "GAP-1156 cd in a function body", o: wpsh, c: sh(`function g { cd .defenseclaw }; g; Set-Content -Path config.yaml -Value x`),
			want: map[string]string{SetSelfProtection: U}},
		{gap: "GAP-1157 fp: may-fail cd, project append", o: wps, c: sh(`cd X; type nul >> notes.txt`), want: map[string]string{"*": N}},
		{gap: "GAP-1556 fp: unknown folder, ordinary name", o: wps, c: sh(`Set-Location $env:X; Set-Content -Path notes.txt -Value x`),
			want: map[string]string{"*": N}},
		// Windows names
		{gap: "GAP-1553 SSH~1 PowerShell", o: wpsh, c: sh(`Add-Content SSH~1\authorized_keys x`), want: map[string]string{SetSSHAuthorizedKeys: U}},
		{gap: "GAP-1553 SSH~1 Git Bash", o: wgbh, c: sh(`echo k >> SSH~1/authorized_keys`), want: map[string]string{SetSSHAuthorizedKeys: U}},
		{gap: "GAP-1553 AUTHOR~1", o: wgbh, c: sh(`cd .ssh && echo k >> AUTHOR~1`), want: map[string]string{SetSSHAuthorizedKeys: U}},
		{gap: "GAP-1553 fp: short name of another file", o: wgbh, c: sh(`echo k >> PROGRA~1/notes.txt`), want: map[string]string{"*": N}},
		{gap: "GAP-1078 drive-relative patch header", o: wpsh, c: patch(`C:.ssh\authorized_keys`), want: map[string]string{SetSSHAuthorizedKeys: K}},
		{gap: "GAP-0945 find C:/ -delete", o: wgbh, c: sh(`find C:/ -type f -delete`), want: map[string]string{"*": K}},
		// find shapes
		{gap: "GAP-1573 find -name [s]ettings.json", o: px, c: sh(`find ~/.claude -name '[s]ettings.json' -delete`),
			want: map[string]string{SetAgentHookConfig: U}},
		{gap: "GAP-1590 find -regex at the dot root", o: ph, c: sh(`find . -regex '.*/\.s[s]h/.*' -delete`),
			want: map[string]string{SetSSHAuthorizedKeys: U}},
		{gap: "GAP-1573c in-call link as a find root", o: px, c: sh(`ln -s ~/.claude d && find d/ -name '*.json' -delete`),
			kind: effects.KindDelete, want: map[string]string{SetAgentHookConfig: U}},
		{gap: "GAP-1573c in-call link, find -L", o: px, c: sh(`ln -s ~/.claude d; find -L d -name settings.json -delete`),
			kind: effects.KindDelete, want: map[string]string{SetAgentHookConfig: U}},
		{gap: "GAP-1573c in-call link, bare tree delete", o: px, c: sh(`ln -sfn ~/.ssh k && find k/ -delete`),
			kind: effects.KindDelete, want: map[string]string{SetSSHAuthorizedKeys: U}},
		{gap: "GAP-1573c write below an in-call link", o: px, c: sh(`ln -s ~/.ssh k && echo x >> k/authorized_keys`),
			kind: effects.KindAppend, want: map[string]string{SetSSHAuthorizedKeys: U}},
		{gap: "GAP-1573c guard: link placed inside an existing folder", o: px, c: sh(`mkdir -p d; ln -s ~/.ssh d; echo x >> d/.ssh/authorized_keys`),
			kind: effects.KindAppend, want: map[string]string{SetSSHAuthorizedKeys: U}},
		{gap: "GAP-1573c Git Bash in-call link as a find root", o: wgb, c: sh(`ln -s ~/.claude d && find d/ -name '*.json' -delete`),
			kind: effects.KindDelete, want: map[string]string{SetAgentHookConfig: U}},
		{gap: "GAP-1573c fp: in-call link to a project folder", o: px, c: sh(`ln -s ~/proj/src d && find d/ -name '*.pyc' -delete`),
			kind: effects.KindDelete, want: map[string]string{"*": N}},
		{gap: "GAP-1573c fp: pattern the hook folder does not hold", o: px, c: sh(`ln -s ~/.claude d && find d/ -name '*.pyc' -delete`),
			kind: effects.KindDelete, want: map[string]string{SetAgentHookConfig: N}},
		{gap: "GAP-1573 fp: find -name *.pyc -delete in the home", o: ph, c: sh(`find ~ -name '*.pyc' -delete`), want: map[string]string{"*": N}},
		{gap: "GAP-1590 fp: find -regex in a project", o: px, c: sh(`find . -regex '.*\.log' -delete`), want: map[string]string{"*": N}},
	}
}

var gradeRank = map[string]int{"no": 0, "unknown": 1, "known": 2}

func TestDET111R3Resolver(t *testing.T) {
	for _, r := range r3Rows() {
		r := r
		t.Run(r.gap, func(t *testing.T) {
			res := effects.Extract(r.c, r.o)
			rs := func(p string) (string, bool) {
				if q, ok := r.links[p]; ok {
					return q, true
				}
				return p, true
			}
			facts := Project(res, Env{Home: r.o.Home, Flavor: r.o.Flavor, Resolve: rs})
			best := map[string]string{}
			for i, f := range facts {
				if r.kind != "" && res.Effects[i].Kind != r.kind {
					continue
				}
				for _, m := range f.Target.Protected {
					if gradeRank[m.State] > gradeRank[best[m.Set]] {
						best[m.Set] = m.State
					}
				}
			}
			for set, want := range r.want {
				sets := []string{set}
				if set == "*" {
					sets = AllSets
				}
				for _, s := range sets {
					got := best[s]
					if got == "" {
						got = "no"
					}
					if (want == "no" && got != "no") || gradeRank[got] < gradeRank[want] {
						t.Errorf("%s: set %s grade %s, want %s\n%s", r.gap, s, got, want, r3Dump(res, facts))
					}
				}
			}
			if r.path != "" {
				hit := false
				for _, e := range res.Effects {
					hit = hit || e.Target.Path == r.path
				}
				if !hit {
					t.Errorf("%s: no effect on %s\n%s", r.gap, r.path, r3Dump(res, facts))
				}
			}
		})
	}
}

func r3Dump(res effects.Result, facts []*semanticpb.EffectFact) string {
	var b strings.Builder
	for i, e := range res.Effects {
		var pr []string
		for _, m := range facts[i].Target.Protected {
			pr = append(pr, m.Set+":"+m.State+":"+m.Reason)
		}
		b.WriteString("  " + string(e.Kind) + " " + string(e.TargetState) + " sp=" + e.Target.Spelling + " path=" + e.Target.Path +
			" glob=" + e.Target.Glob + " lex=" + e.Target.Lexical + " prot=" + strings.Join(pr, ",") + "\n")
	}
	return b.String()
}

// TestDET111R3Protected checks the classifier answer in decision terms.
func TestDET111R3Protected(t *testing.T) {
	px, _, _, _, _, _ := r3Opts()
	cases := []struct {
		cmd, class, certainty, reach string
	}{
		{`echo k >> ~/.ssh/authorized_keys`, "authorized_keys", "known", ""},
		{`cat ~/.ss*/id_rsa`, "credential", "maybe", "R-GLOB"},
		{`cat /srv/homes/bob/.aws/credentials`, "other_home_credential", "maybe", "R-NAME"},
		{`cd $X; echo x > authorized_keys`, "authorized_keys", "maybe", "R-CWD"},
		{`echo k > u*/../keydir/authorized_keys`, "authorized_keys", "maybe", "R-FS"}, // GAP-0443
	}
	for _, c := range cases {
		res := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: c.cmd}, px)
		facts := Project(res, Env{Home: px.Home, Flavor: px.Flavor, Resolve: func(p string) (string, bool) { return p, true }})
		hit := false
		var got []Protection
		for _, f := range facts {
			for _, p := range Protected(f.Target) {
				got = append(got, p)
				hit = hit || (p.Class == c.class && p.Certainty == c.certainty && p.Reach == c.reach)
			}
		}
		if !hit {
			t.Errorf("%s: want %s/%s/%s, got %+v", c.cmd, c.class, c.certainty, c.reach, got)
		}
	}
}
