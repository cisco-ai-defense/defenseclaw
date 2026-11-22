// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/awkprog"
)

// rel-1-0-10:GAP-0652..GAP-0655 (s7-awkchk, review round 1 of GAP-0499): every
// spelling of an awk call that starts a command reaches the rule. The rows are
// the reviewer's spelling ids; a row's program is the same system() of the
// protected link the lane's channel table uses, so the direct form blocks in
// every cell of every pack. A command the reading cannot know (a computed
// program, a computed command, a program file it cannot read) is the unknown
// tier of the pack: an alert in the default and permissive packs, a block in
// strict, never an allow.

const awkTouchLink = `BEGIN{system("touch keylink")}`

type awkSpelling struct {
	id    string
	cmd   string
	files map[string]string
	want  string // "block": as the direct command; "unknown": the unknown tier; "allow"
}

func awkSpellings() []awkSpelling {
	file := map[string]string{"prog.awk": awkTouchLink}
	rows := []awkSpelling{
		// GAP-0652: program files.
		{id: "A13", cmd: `awk -f prog.awk`, files: file, want: "block"},
		{id: "A14", cmd: `awk -f ./prog.awk`, files: file, want: "block"},
		{id: "A15", cmd: `awk -f @PROJ@/prog.awk`, files: file, want: "block"},
		{id: "A16", cmd: `gawk --file=prog.awk`, files: file, want: "block"},
		{id: "A17", cmd: `awk -fprog.awk`, files: file, want: "block"},
		{id: "A32", cmd: `gawk -E prog.awk`, files: file, want: "block"},
		{id: "A33", cmd: `gawk --exec prog.awk`, files: file, want: "block"},
		{id: "A34", cmd: `mawk -W exec prog.awk`, files: file, want: "block"},
		{id: "B60", cmd: `busybox awk -f prog.awk`, files: file, want: "block"},
		{id: "E02", cmd: `awk -f prog.awk`, files: file, want: "block"},
		{id: "E07", cmd: `gawk -E prog.awk`, files: file, want: "block"},
		{id: "E08", cmd: `awk -fprog.awk`, files: file, want: "block"},
		{id: "E10", cmd: `sh -c 'awk -f prog.awk'`, files: file, want: "block"},
		{id: "E04", cmd: `awk -f dyn.awk ordinary/a.txt`, files: map[string]string{"dyn.awk": `{system("echo " $1)}`}, want: "unknown"},
		{id: "E05-missing", cmd: `awk -f missing.awk`, want: "unknown"},
		{id: "E06-stdin", cmd: `awk -f - ordinary/a.txt`, want: "unknown"},
		{id: "E03", cmd: `awk -f benign.awk ordinary/a.txt`, files: map[string]string{"benign.awk": `{print $1}`}, want: "allow"},
		// GAP-0653: a computed word.
		{id: "A20", cmd: `P='` + awkTouchLink + `'; awk "$P"`, want: "unknown"},
		{id: "A21", cmd: `export P='` + awkTouchLink + `'; awk "$P"`, want: "unknown"},
		{id: "C-var-A", cmd: `P='` + awkTouchLink + `'; awk "$P"`, want: "unknown"},
		{id: "C-var2-A", cmd: "P='" + awkTouchLink + "'\nawk \"$P\"", want: "unknown"},
		{id: "B19", cmd: `X=date; awk -v c="$X" 'BEGIN{system(c)}'`, want: "unknown"},
		{id: "B20", cmd: `C=date awk 'BEGIN{system(ENVIRON["C"])}'`, want: "unknown"},
		{id: "D27", cmd: `awk -v n=$(date +%s) 'BEGIN{system("echo " n)}'`, want: "unknown"},
		{id: "D28", cmd: `C=date; awk -v c="$C" 'BEGIN{c | getline x}'`, want: "unknown"},
		{id: "A-operand", cmd: `awk '` + awkTouchLink + `' "$F"`, want: "block"},
		{id: "A-operand-glob", cmd: `awk '` + awkTouchLink + `' ordinary/*.txt`, want: "block"},
		{id: "A-F-computed", cmd: `awk -F"$S" '` + awkTouchLink + `' ordinary/a.txt`, want: "block"},
		{id: "T-operand", cmd: `awk '{print $1}' "$F"`, want: "allow"},
		{id: "T-F-computed", cmd: `awk -F"$S" '{print $1}' ordinary/a.txt`, want: "allow"},
		{id: "T-v-computed", cmd: `awk -v n="$N" '{print n}' ordinary/a.txt`, want: "allow"},
		// GAP-0656 (by design): a command awk builds at run time is the unknown tier.
		{id: "D34", cmd: `awk '{print $1 | "sort -k" n}' ordinary/a.txt`, want: "unknown"},
		{id: "D35", cmd: `awk '{print $1 | cmd}' ordinary/a.txt`, want: "unknown"},
		{id: "A61", cmd: `awk '{ cmd="date -d @" $1; cmd | getline d; close(cmd); print d }' ordinary/a.txt`, want: "unknown"},
		{id: "A65", cmd: `awk '{print $0 | "sort -k" $2}' ordinary/a.txt`, want: "unknown"},
		// GAP-0654: a regular expression after an operator.
		{id: "A42", cmd: `awk 'BEGIN{ y = 1 + /"/; system("touch keylink"); y = 1 + /"/ }'`, want: "block"},
		{id: "A43", cmd: `awk 'BEGIN{ if (1) /"/; system("touch keylink"); if (1) /"/ }'`, want: "block"},
		{id: "A44", cmd: `awk 'BEGIN{ y = 1 < /"/; system("touch keylink"); y = 1 < /"/ }'`, want: "block"},
		{id: "A45", cmd: `awk 'BEGIN{ y = 2 * /"/; system("touch keylink"); y = 2 * /"/ }'`, want: "block"},
		{id: "B39", cmd: `awk 'BEGIN{ y = 1 - /"/; system("touch keylink"); y = 1 - /"/ }'`, want: "block"},
		{id: "B41", cmd: `awk 'BEGIN{ print > "/dev/null"; y = 3 % /"/; system("touch keylink"); y = 3 % /"/ }'`, want: "block"},
		{id: "B42", cmd: `awk 'BEGIN{ y = 3 ^ /"/; system("touch keylink"); y = 3 ^ /"/ }'`, want: "block"},
		{id: "B43", cmd: `awk 'BEGIN{ y = 3 > /"/; system("touch keylink"); y = 3 > /"/ }'`, want: "block"},
		{id: "T-division", cmd: `awk '{ x = $1 / 2; y = $2 / 3; system("wc -l ordinary/a.txt") }' ordinary/a.txt`, want: "allow"},
		// GAP-0655: find -exec, xargs and busybox.
		{id: "C-findexec-A", cmd: `find . -maxdepth 0 -exec awk '` + awkTouchLink + `' \;`, want: "block"},
		{id: "C-findexec-plus-A", cmd: `find . -maxdepth 0 -exec awk '` + awkTouchLink + `' {} +`, want: "block"},
		{id: "C-xargs-A", cmd: `echo | xargs -I{} awk '` + awkTouchLink + `'`, want: "block"},
		{id: "C-xargs-plain-A", cmd: `echo x | xargs awk '` + awkTouchLink + `'`, want: "block"},
		{id: "C-busybox-A", cmd: `busybox awk '` + awkTouchLink + `'`, want: "block"},
		{id: "A05", cmd: `busybox awk 'BEGIN{system("touch @KEYS@")}'`, want: "parity:busybox touch @KEYS@"},
		{id: "T-findexec", cmd: `find ordinary -name '*.txt' -exec awk '{print $1}' {} \;`, want: "allow"},
		{id: "T-xargs", cmd: `ls ordinary | xargs awk '{print $1}'`, want: "allow"},
		// GAP-0729 (s7-awk2chk round 2): a shell hole anywhere in the program
		// text is the unknown tier, whatever the text around it says.
		{id: "U01", cmd: `awk "BEGIN{$X}"`, want: "unknown"},
		{id: "U02", cmd: `awk "END{$X}" ordinary/a.txt`, want: "unknown"},
		{id: "U03", cmd: `awk "BEGIN{print \"$X\"}"`, want: "unknown"},
		{id: "U04", cmd: `awk "/$X/{print}" ordinary/a.txt`, want: "unknown"},
		{id: "U05", cmd: `awk "$X{print}" ordinary/a.txt`, want: "unknown"},
		{id: "U06", cmd: `awk "BEGIN{print $(date +%s)}"`, want: "unknown"},
		{id: "U07", cmd: `awk "{print $2}" ordinary/a.txt`, want: "unknown"},
		{id: "U08", cmd: `awk -e "{print $1}" ordinary/a.txt`, want: "unknown"},
		{id: "T-u-single", cmd: `awk '{print $2}' ordinary/a.txt`, want: "allow"},
		{id: "T-u-var", cmd: `awk -v n="$N" '{print n, $2}' ordinary/a.txt`, want: "allow"},
		// GAP-0730: gawk -i / --include source files are read like -f.
		{id: "J02", cmd: `gawk -i inc.awk 'BEGIN{}'`, files: map[string]string{"inc.awk": awkTouchLink}, want: "block"},
		{id: "J02b", cmd: `gawk -iinc.awk 'BEGIN{}'`, files: map[string]string{"inc.awk": awkTouchLink}, want: "block"},
		{id: "A-i-include", cmd: `gawk --include inc.awk 'BEGIN{}'`, files: map[string]string{"inc.awk": awkTouchLink}, want: "block"},
		{id: "A-include-eq", cmd: `gawk --include=inc.awk 'BEGIN{}'`, files: map[string]string{"inc.awk": awkTouchLink}, want: "block"},
		{id: "K03", cmd: `gawk -i inc 'BEGIN{}'`, files: map[string]string{"inc.awk": awkTouchLink}, want: "block"},
		{id: "K05", cmd: `gawk -i ./missing-inc.awk 'BEGIN{}'`, want: "unknown"},
		{id: "K06", cmd: `gawk -i inc2.awk 'BEGIN{}'`, files: map[string]string{"inc2.awk": `function f(x){return x}`}, want: "allow"},
		{id: "A-i-include-benign", cmd: `gawk -i inplace '{print}' ordinary/a.txt`, want: "allow"},
		// GAP-0732: gawk -l / --load.
		{id: "K01", cmd: `gawk -l ./ext 'BEGIN{}'`, want: "unknown"},
		{id: "K02", cmd: `gawk --load=./ext.so 'BEGIN{}'`, want: "unknown"},
		{id: "A-load-ext", cmd: `gawk -l ext 'BEGIN{}'`, want: "unknown"},
		// GAP-0731: an awk -f program file behind an assignment or a wrapper.
		{id: "P-envprefix-F", cmd: `LC_ALL=C awk -f prog.awk ordinary/a.txt`, files: file, want: "block"},
		{id: "P-twoprefix-F", cmd: `LC_ALL=C LANG=C awk -f prog.awk ordinary/a.txt`, files: file, want: "block"},
		{id: "P-env-F", cmd: `env LC_ALL=C awk -f prog.awk ordinary/a.txt`, files: file, want: "block"},
		{id: "P-nice-F", cmd: `nice awk -f prog.awk ordinary/a.txt`, files: file, want: "block"},
		{id: "P-nohup-F", cmd: `nohup awk -f prog.awk ordinary/a.txt`, files: file, want: "block"},
		{id: "P-timeout-F", cmd: `timeout 5 awk -f prog.awk ordinary/a.txt`, files: file, want: "block"},
		{id: "P-time-F", cmd: `time awk -f prog.awk ordinary/a.txt`, files: file, want: "block"},
		{id: "P-setsid-F", cmd: `setsid awk -f prog.awk ordinary/a.txt`, files: file, want: "block"},
		{id: "P-stdbuf-F", cmd: `stdbuf -oL awk -f prog.awk ordinary/a.txt`, files: file, want: "block"},
		{id: "P-flock-F", cmd: `flock ordinary/a.txt awk -f prog.awk ordinary/a.txt`, files: file, want: "block"},
		{id: "P-fn-F", cmd: `r() { awk -f prog.awk ordinary/a.txt; }; r`, files: file, want: "block"},
		{id: "P-gawkE-prefix", cmd: `LC_ALL=C gawk -E prog.awk ordinary/a.txt`, files: file, want: "block"},
		{id: "P-envprefix-I", cmd: `LC_ALL=C awk '` + awkTouchLink + `' ordinary/a.txt`, want: "block"},
		{id: "T-envprefix-F", cmd: `LC_ALL=C awk -f benign.awk ordinary/a.txt`, files: map[string]string{"benign.awk": `{print $1}`}, want: "allow"},
		{id: "T-nice-F", cmd: `nice awk -f benign.awk ordinary/a.txt`, files: map[string]string{"benign.awk": `{print $1}`}, want: "allow"},
		// GAP-0734: a program file between the 16 KiB script read and the
		// 64 KiB awk bound is read, and a command at the start of a file past
		// the awk bound is judged as the direct command (the rest is the unknown
		// tier, never a refusal of the whole file).
		// GAP-0733: a relative program file under a folder the reading does not
		// track (env -C, cd, pushd, a subshell cd) or a bare name with AWKPATH
		// set is not the file at the hook's folder: the unknown tier. The
		// absolute name and a call that changes no folder keep their verdicts.
		{id: "J06", cmd: `env -C ordinary awk -f prog.awk a.txt`, files: file, want: "unknown"},
		{id: "J05", cmd: `cd ordinary && awk -f prog.awk a.txt`, files: file, want: "unknown"},
		{id: "A-subshell-cd-awk-f", cmd: `(cd ordinary && awk -f prog.awk a.txt)`, files: file, want: "unknown"},
		{id: "A-pushd-awk-f", cmd: `pushd ordinary >/dev/null; awk -f prog.awk a.txt`, files: file, want: "unknown"},
		{id: "K09", cmd: `AWKPATH=ordinary gawk -f prog.awk a.txt`, files: file, want: "unknown"},
		// The folder is tracked, so the file the shell opens is the one read:
		// the benign file below the folder allows, a cd back out reads the
		// file of the project, and AWKPATH names the folders searched.
		{id: "J05D", cmd: `cd ordinary && awk -f prog2.awk a.txt`, files: map[string]string{"prog2.awk": awkTouchLink, "ordinary/prog2.awk": `{print $1}`}, want: "allow"},
		{id: "J06D", cmd: `env -C ordinary awk -f prog2.awk a.txt`, files: map[string]string{"prog2.awk": awkTouchLink, "ordinary/prog2.awk": `{print $1}`}, want: "allow"},
		{id: "A-cd-dotdot-awk-f", cmd: `cd ordinary && cd .. && awk -f prog2.awk`, files: map[string]string{"prog2.awk": awkTouchLink, "ordinary/prog2.awk": `{print $1}`}, want: "block"},
		// GAP-0852 (review tbrev r1, J05D-cd-relative-f-ctl x false-and-cd): a
		// cd that may not have run (behind false && or ||, after a ;, in an
		// untaken branch, in a subshell that ended) does not move the call: the
		// program file is read in every folder the call may run in, and the
		// strongest decides. A cd of an && chain the call is on the right of
		// certainly ran (J05D allows). A folder no words give stays the unknown
		// tier, with what the other folders prove still deciding.
		{id: "J05D-false-and-cd", cmd: "false && cd ordinary\nawk -f prog2.awk a.txt", files: map[string]string{"prog2.awk": awkTouchLink, "ordinary/prog2.awk": `{print $1}`}, want: "block"},
		{id: "J05D-false-and-cd-semi", cmd: `false && cd ordinary; awk -f prog2.awk a.txt`, files: map[string]string{"prog2.awk": awkTouchLink, "ordinary/prog2.awk": `{print $1}`}, want: "block"},
		{id: "J05D-true-or-cd", cmd: `true || cd ordinary; awk -f prog2.awk a.txt`, files: map[string]string{"prog2.awk": awkTouchLink, "ordinary/prog2.awk": `{print $1}`}, want: "block"},
		{id: "J05D-cd-or-true", cmd: `cd ordinary || true; awk -f prog2.awk a.txt`, files: map[string]string{"prog2.awk": awkTouchLink, "ordinary/prog2.awk": `{print $1}`}, want: "block"},
		{id: "J05D-if-false-cd", cmd: `if false; then cd ordinary; fi; awk -f prog2.awk a.txt`, files: map[string]string{"prog2.awk": awkTouchLink, "ordinary/prog2.awk": `{print $1}`}, want: "block"},
		{id: "J05D-subshell-cd-ended", cmd: `(cd ordinary); awk -f prog2.awk a.txt`, files: map[string]string{"prog2.awk": awkTouchLink, "ordinary/prog2.awk": `{print $1}`}, want: "block"},
		{id: "J05D-semi-cd", cmd: `cd ordinary; awk -f prog2.awk a.txt`, files: map[string]string{"prog2.awk": awkTouchLink, "ordinary/prog2.awk": `{print $1}`}, want: "block"},
		{id: "J05D-false-and-cd-var", cmd: `false && cd "$D"; awk -f prog2.awk a.txt`, files: map[string]string{"prog2.awk": awkTouchLink, "ordinary/prog2.awk": `{print $1}`}, want: "block"},
		{id: "J05D-false-and-cd-in-sh-c", cmd: `sh -c 'false && cd ordinary; awk -f prog2.awk a.txt'`, files: map[string]string{"prog2.awk": awkTouchLink, "ordinary/prog2.awk": `{print $1}`}, want: "block"},
		{id: "J05D-and-chain-in-sh-c", cmd: `cd ordinary && sh -c 'awk -f prog2.awk a.txt'`, files: map[string]string{"prog2.awk": awkTouchLink, "ordinary/prog2.awk": `{print $1}`}, want: "allow"},
		{id: "J05D-ctl-uncertain-benign-both", cmd: `false && cd ordinary; awk -f prog3.awk a.txt`, files: map[string]string{"prog3.awk": `{print $2}`, "ordinary/prog3.awk": `{print $1}`}, want: "allow"},
		{id: "J05D-ctl-uncertain-unknown-folder", cmd: `false && cd "$D"; awk -f prog3.awk a.txt`, files: map[string]string{"prog3.awk": `{print $2}`}, want: "unknown"},

		{id: "J05-dash", cmd: `cd - && awk -f prog.awk a.txt`, files: file, want: "unknown"},
		{id: "J05-var", cmd: `cd "$D" && awk -f prog.awk a.txt`, files: file, want: "unknown"},
		{id: "J05-abs", cmd: `cd ordinary && awk -f @PROJ@/prog.awk a.txt`, files: file, want: "block"},
		{id: "J05-benign", cmd: `cd ordinary && awk '{print $1}' a.txt`, want: "allow"},
		{id: "R30000", cmd: `awk -f big30.awk ordinary/a.txt`, files: map[string]string{"big30.awk": `{print $1}` + strings.Repeat(" ", 30000)}, want: "allow"},
		{id: "R63000", cmd: `awk -f big63.awk ordinary/a.txt`, files: map[string]string{"big63.awk": `{print $1}` + strings.Repeat(" ", 63000)}, want: "allow"},
		{id: "Q06", cmd: `awk -f big200.awk`, files: map[string]string{"big200.awk": awkTouchLink + strings.Repeat(" ", 200000)}, want: "block"},
		{id: "Q06-mid", cmd: `awk -f big40.awk`, files: map[string]string{"big40.awk": awkTouchLink + strings.Repeat(" ", 40000)}, want: "block"},
	}
	return rows
}

func awkSpellingFixture(t *testing.T, pack string, rows []awkSpelling) (b36ManagedHookFixture, map[string]string) {
	t.Helper()
	f := awkPackFixture(t, pack)
	fill := strings.NewReplacer("@KEYS@", f.keys, "@PROJ@", f.project)
	commands := map[string]string{}
	for _, row := range rows {
		for name, content := range row.files {
			if err := os.WriteFile(filepath.Join(f.project, name), []byte(fill.Replace(content)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		commands[row.id] = fill.Replace(row.cmd)
	}
	return f, commands
}

func TestAwkSpellingRowsReachTheRule(t *testing.T) {
	rows := awkSpellings()
	for pack, unknown := range map[string]string{"default": "alert", "permissive": "alert", "strict": "block"} {
		t.Run(pack, func(t *testing.T) {
			f, commands := awkSpellingFixture(t, pack, rows)
			var all []string
			for _, row := range rows {
				all = append(all, commands[row.id])
				if direct, ok := strings.CutPrefix(row.want, "parity:"); ok {
					all = append(all, strings.NewReplacer("@KEYS@", f.keys).Replace(direct))
				}
			}
			got := awkVerdictsNoWeakerCheck(t, f, all)
			for _, row := range rows {
				for _, call := range got[commands[row.id]] {
					switch {
					case row.want == "block" && call.verdict != "block":
						t.Errorf("%s %s: %s, want block as the direct command", row.id, call.name, call.verdict)
					case row.want == "allow" && (call.verdict != "allow" || strings.Contains(call.body, awkprog.DynamicReason)):
						t.Errorf("%s %s: %s, want allow with no awk finding", row.id, call.name, call.verdict)
					case row.want == "unknown" && (call.verdict == "allow" || pack == "strict" && call.verdict != "block"):
						t.Errorf("%s %s: %s, want the unknown tier of the %s pack (%s or stricter)", row.id, call.name, call.verdict, pack, unknown)
					}
				}
				if direct, ok := strings.CutPrefix(row.want, "parity:"); ok {
					direct = strings.NewReplacer("@KEYS@", f.keys).Replace(direct)
					want := got[direct]
					for i, call := range got[commands[row.id]] {
						if i < len(want) && call.verdict != want[i].verdict {
							t.Errorf("%s %s: %s, the direct form %q is %s", row.id, call.name, call.verdict, direct, want[i].verdict)
						}
					}
				}
			}
		})
	}
}

// awkVerdictsNoWeakerCheck is awkVerdicts for rows whose direct form is itself
// allowed in a managed cell and blocked per user on rel (the busybox applet):
// the rows compare an awk call with its direct form, so the managed-weaker
// check of the harness does not apply.
func awkVerdictsNoWeakerCheck(t *testing.T, f b36ManagedHookFixture, commands []string) map[string][]*hookCall {
	t.Helper()
	payloads := make([][]byte, len(commands))
	for i, command := range commands {
		payloads[i] = f.payload(t, command)
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, command := range commands {
		calls = append(calls, everyMode(command, payloads[i], headers[i])...)
	}
	for _, call := range calls {
		call.benignPerUserBlock = true
	}
	f.answerAll(t, calls)
	byCommand := map[string][]*hookCall{}
	for i, call := range calls {
		byCommand[commands[i/4]] = append(byCommand[commands[i/4]], call)
	}
	return byCommand
}
