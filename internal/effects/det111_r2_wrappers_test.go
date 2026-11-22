// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"
	"testing"
)

// DET111 step 4, class R2 (DESIGN D2, programs as data): the wrapper rows of
// the program table. Each case names the gap whose spelling it reads; the
// check is what the row must produce. Every case is red at a64bfdb931 (1.0.10)
// unless it is marked pin (already right there, kept so the row cannot lose it).

type r2case struct {
	id    string
	o     Options
	cmd   string
	check func(Result) string // "" when the result is right
	pin   bool
}

// r2Verdict wants the raVerdict string exactly.
func r2Verdict(want string) func(Result) string {
	return func(r Result) string {
		if got := raVerdict(r); got != want {
			return "verdict " + got + ", want " + want
		}
		return ""
	}
}

// r2Has wants an effect of kind at path (any certainty), with the program and
// target state when given.
func r2Has(kind Kind, path string, known bool) func(Result) string {
	return func(r Result) string {
		for _, e := range r.Effects {
			if e.Kind != kind || !strings.EqualFold(e.Target.Path, path) {
				continue
			}
			if known && e.TargetState != TargetStateKnown {
				continue
			}
			return ""
		}
		return "no " + string(kind) + " effect at " + path
	}
}

// r2HasUnknownTarget wants an effect of kind whose target is not known, with
// the given reason.
func r2HasUnknownTarget(kind Kind, reason ReasonCode) func(Result) string {
	return func(r Result) string {
		for _, e := range r.Effects {
			if e.Kind != kind || e.TargetState == TargetStateKnown {
				continue
			}
			for _, rs := range e.Reasons {
				if rs.Code == reason {
					return ""
				}
			}
		}
		return "no " + string(kind) + " effect with an unknown target (" + string(reason) + ")"
	}
}

// r2Program wants the inner program read (an effect whose origin is it).
func r2Program(program string) func(Result) string {
	return func(r Result) string {
		for _, e := range r.Effects {
			if e.Origin.Program == program {
				return ""
			}
		}
		return "the child program " + program + " is never read"
	}
}

func r2All(fs ...func(Result) string) func(Result) string {
	return func(r Result) string {
		var bad []string
		for _, f := range fs {
			if m := f(r); m != "" {
				bad = append(bad, m)
			}
		}
		return strings.Join(bad, "; ")
	}
}

var r2WrapperCases = []r2case{
	// GAP-1461: taskset and /usr/bin/time -p in front of sudo env NAME=v / sudo nohup.
	{"GAP-1461 taskset sudo env", raLin, `taskset 1 sudo env LD_PRELOAD=/tmp/x.so rm -rf ~/.defenseclaw`, r2Has(KindDelete, "/home/u/.defenseclaw", true), false},
	{"GAP-1461 taskset -c list", raLin, `taskset -c 0 rm -rf ~/.defenseclaw`, r2Verdict("K|delete:/home/u/.defenseclaw"), false},
	{"GAP-1461 taskset -p is no wrapper", raLin, `taskset -p 1 rm`, r2Verdict("U|"), true},
	{"GAP-1461 time -p sudo nohup", raLin, `/usr/bin/time -p sudo nohup rm -rf ~/.defenseclaw`, r2Verdict("K|delete:/home/u/.defenseclaw"), true},
	{"GAP-1461 time -p env", raLin, `/usr/bin/time -p env LD_PRELOAD=/tmp/x.so rm -rf ~/.defenseclaw`, r2Has(KindDelete, "/home/u/.defenseclaw", true), true},
	// GNU time writes its report with -o (appends with -a).
	{"R2 time -o writes", raLin, `/usr/bin/time -o ~/.claude/settings.json true`, r2Verdict("K|write:/home/u/.claude/settings.json"), false},
	{"R2 time -a -o appends", raLin, `/usr/bin/time -a -o ~/.claude/settings.json true`, r2Verdict("K|append:/home/u/.claude/settings.json"), false},
	{"R2 time --output=", raLin, `/usr/bin/time --output=/home/u/.claude/settings.json true`, r2Verdict("K|write:/home/u/.claude/settings.json"), false},
	// GAP-1493: a hook config delete or truncate behind a prefix wrapper.
	{"GAP-1493 chrt rm", raLin, `chrt -i 0 rm -f ~/.claude/settings.json`, r2Verdict("K|delete:/home/u/.claude/settings.json"), false},
	{"GAP-1493 flock rm", raLin, `flock /tmp/l rm -f ~/.claude/settings.json`, r2Verdict("K|delete:/home/u/.claude/settings.json"), false},
	{"GAP-1493 flock -w rm", raLin, `flock -w 5 /tmp/l rm -f ~/.claude/settings.json`, r2Verdict("K|delete:/home/u/.claude/settings.json"), false},
	{"GAP-1493 stdbuf -oL rm", raLin, `stdbuf -oL rm -f ~/.claude/settings.json`, r2Verdict("K|delete:/home/u/.claude/settings.json"), false},
	{"GAP-1493 ionice -c3 truncate", raLin, `ionice -c3 truncate -s0 ~/.claude/settings.json`, r2Verdict("K|write:/home/u/.claude/settings.json"), false},
	{"GAP-1493 nice -n5 rm", raLin, `nice -n5 rm -f ~/.claude/settings.json`, r2Verdict("K|delete:/home/u/.claude/settings.json"), false},
	{"GAP-1493 doas truncate", raLin, `doas truncate -s0 ~/.claude/settings.json`, r2Verdict("K|write:/home/u/.claude/settings.json"), true},
	{"GAP-1493 setsid -f rm", raLin, `setsid -f rm -f ~/.claude/settings.json`, r2Verdict("K|delete:/home/u/.claude/settings.json"), true},
	{"GAP-1493 uv run rm", raLin, `uv run rm -f ~/.claude/settings.json`, r2Verdict("K|delete:/home/u/.claude/settings.json"), false},
	{"GAP-1493 runuser -u rm", raLin, `runuser -u u -- rm -f /home/u/.claude/settings.json`, r2Verdict("U|delete:/home/u/.claude/settings.json"), false},
	// GAP-1323 / 1326 / 0879: already read through the rows (pins).
	{"GAP-1323 nohup cat", raLin, `nohup cat ~/.aws/credentials`, r2Has(KindRead, "/home/u/.aws/credentials", true), true},
	{"GAP-1326 sudo nohup cat", raLin, `sudo nohup cat ~/.aws/credentials`, r2Has(KindRead, "/home/u/.aws/credentials", true), true},
	{"GAP-0879 nice rm glob", raLin, `nice rm -rf ~/*`, r2HasUnknownTarget(KindDelete, ReasonGlob), true},
	{"GAP-0879 setsid rm glob", raLin, `setsid rm -rf $HOME/*`, r2HasUnknownTarget(KindDelete, ReasonGlob), true},
	// GAP-0972: a wrapper word that expands at run time keeps the child read.
	{"GAP-0972 env FOO=$V awk", raLin, `env FOO=$V awk 'BEGIN{print 1}'`, r2Program("awk"), false},
	// The child word is read and its target kept (GAP-0972); FOO is a name the
	// GAP-0217 allow list does not account for rm, so the call is not fully known.
	{"GAP-0972 env FOO=$V rm", raLin, `env FOO=$V rm -f /home/u/.claude/settings.json`, r2Verdict("U|delete:/home/u/.claude/settings.json"), false},
	{"GAP-0972 sudo -u $U rm", raLin, `sudo -u $U rm -f /home/u/.claude/settings.json`, r2Has(KindDelete, "/home/u/.claude/settings.json", true), true},
	// GAP-1274: a login shell through exec -a -NAME / exec -l starts after its
	// profile files: its folder is not the caller's.
	{"GAP-1274 exec -a -bash", raLin, `exec -a -bash bash -c 'echo k >> authorized_keys'`, r2Verdict("U|"), false},
	{"GAP-1274 exec -l bash", raLin, `exec -l bash -c 'echo k >> authorized_keys'`, r2Verdict("U|"), false},
	{"GAP-1274 exec -a name", raLin, `exec -a x tee -a /home/u/.ssh/authorized_keys`, r2Verdict("K|append:/home/u/.ssh/authorized_keys"), true},
	{"GAP-1274 sudo -D", raLin, `sudo -D /home/u/.ssh bash -c 'echo k >> authorized_keys'`, r2Verdict("K|append:/home/u/.ssh/authorized_keys"), true},
	{"GAP-1274 sudo -i", raLin, `sudo -i bash -c 'echo k >> authorized_keys'`, r2Verdict("U|"), true},
	{"GAP-1274 nsenter --wd", raLin, `nsenter -t 1 --wd=/home/u/.ssh tee -a authorized_keys`, r2Has(KindAppend, "/home/u/.ssh/authorized_keys", false), false},
	// Shell text a wrapper runs (script -c, flock -c, watch).
	{"R2 script -c", raLin, `script -qc 'echo k >> /home/u/.ssh/authorized_keys' /dev/null`, r2Verdict("K|append:/home/u/.ssh/authorized_keys,write:/dev/null"), false},
	{"R2 script typescript", raLin, `script -q -c true`, r2Verdict("K|write:/home/u/proj/typescript"), false},
	{"R2 script -a log", raLin, `script -a -c true /home/u/.bashrc`, r2Verdict("K|append:/home/u/.bashrc"), false},
	{"R2 script no -c", raLin, `script /tmp/x`, r2Verdict("U|"), true},
	{"R2 flock -c", raLin, `flock /tmp/l -c 'rm -f ~/.claude/settings.json'`, r2Verdict("K|delete:/home/u/.claude/settings.json"), false},
	{"R2 watch", raLin, `watch -n1 rm -f /home/u/.claude/settings.json`, r2Verdict("K|delete:/home/u/.claude/settings.json"), false},
	{"R2 watch -x", raLin, `watch -x rm -f /home/u/.claude/settings.json`, r2Verdict("K|delete:/home/u/.claude/settings.json"), false},
	// F1: an option with which the launcher runs nothing is no wrapper.
	{"R2 command -v is no exec", raLin, `command -v rm -rf ~`, r2Verdict("K|"), false},
	{"R2 sudo -l is no exec", raLin, `sudo -l rm -rf ~`, r2Verdict("U|"), false},
	// xargs: -i takes an attached value only; a fed copier writes a fed name.
	{"R2 xargs -i", raLin, `xargs -i rm {}`, r2HasUnknownTarget(KindDelete, ReasonDynamicExpansion), false},
	{"GAP-1317 xargs cp", raLin, `echo keya | xargs cp ordinary/x`, r2HasUnknownTarget(KindWrite, ReasonOperandsFromInput), false},
	{"R2 xargs -a reads", raLin, `xargs -a /home/u/.ssh/id_rsa echo`, r2Has(KindRead, "/home/u/.ssh/id_rsa", true), false},
}

func TestDET111R2Wrappers(t *testing.T) {
	runR2(t, r2WrapperCases)
}

func runR2(t *testing.T, cases []r2case) {
	t.Helper()
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.id] {
			t.Errorf("%s: duplicate id", c.id)
		}
		seen[c.id] = true
		r := Extract(Call{Surface: SurfaceShell, Command: c.cmd}, c.o)
		if msg := c.check(r); msg != "" {
			t.Errorf("%s: %s: %s\n%s", c.id, c.cmd, msg, fmtRes(r))
		}
	}
}
