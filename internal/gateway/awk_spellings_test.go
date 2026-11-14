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
		{id: "B60", cmd: `busybox awk -f prog.awk`, files: file, want: "parity:busybox touch keylink"},
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
		{id: "C-busybox-A", cmd: `busybox awk '` + awkTouchLink + `'`, want: "parity:busybox touch keylink"},
		{id: "A05", cmd: `busybox awk 'BEGIN{system("touch @KEYS@")}'`, want: "parity:busybox touch @KEYS@"},
		{id: "T-findexec", cmd: `find ordinary -name '*.txt' -exec awk '{print $1}' {} \;`, want: "allow"},
		{id: "T-xargs", cmd: `ls ordinary | xargs awk '{print $1}'`, want: "allow"},
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
