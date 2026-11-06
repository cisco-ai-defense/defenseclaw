// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build regressioncorpora

package gateway

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

var rvCdvarRows7 = []struct{ kind, cmd string }{
	{"P", `cd /tmp; g() { cp ~/proj/a.txt disklink; }; cd ~/proj; g`},
	{"P", `cd /tmp && g() { cp ~/proj/a.txt disklink; } && cd ~/proj && g`},
	{"P", `cd ~/proj/build && g() { cp ../a.txt disklink; }; cd ~/proj; g`},
	{"P", `g() { cp a.txt disklink; }; g`},
	{"P", `cd /tmp; function g { cp ~/proj/a.txt disklink; }; cd ~/proj; g`},
	{"P", `cd ~ && f=proj/disklink; echo $(cp proj/a.txt $f)`},
	{"P", `cd ~ && f=proj/disklink; echo "$(cp proj/a.txt $f)"`},
	{"P", `cd ~ && f=proj/disklink; x=$(cp proj/a.txt $f)`},
	{"P", "cd ~ && f=proj/disklink; echo `cp proj/a.txt $f`"},
	{"P", `cd ~ && f=proj/disklink; cat <(cp proj/a.txt $f)`},
	{"P", `cd ~ && echo $(cp proj/a.txt proj/disklink)`},
	{"P", `cd ~ && for x in 1; do cp proj/a.txt proj/disklink; done`},
	{"P", `cd ~ && f=proj/disklink; case x in x) cp proj/a.txt $f;; esac`},
	{"P", `cd ~ && f=proj/disklink; while true; do cp proj/a.txt $f; break; done`},
	{"P", `cd ~ && f=proj/disklink; until false; do cp proj/a.txt $f; break; done`},
	{"P", `cd ~ && f=proj/disklink; for x in 1; do for y in 1; do cp proj/a.txt $f; done; done`},
	{"P", `cd ~ && f=proj/disklink; { cp proj/a.txt $f; } &`},
	{"P", `cd ~ && f=proj/disklink; { cp proj/a.txt $f; } >/dev/null`},
	{"P", `cd ~ && f=proj/disklink; ! { cp proj/a.txt $f; }`},
	{"P", `cd ~ && f=proj/disklink; true && { cp proj/a.txt $f; }`},
	{"P", `cd ~ && f=proj/disklink; [[ -n x ]] && if true; then cp proj/a.txt $f; fi`},
	{"P", `cd ~ && f=proj/disklink; for x in 1; do command cp proj/a.txt $f; done`},
	{"P", `cd ~ && f=proj/disklink; for x in 1; do env cp proj/a.txt $f; done`},
	{"P", `cd ~ && f=proj/disklink; for x in 1; do /bin/cp proj/a.txt $f; done`},
	{"P", `cd ~ && f=proj/disklink; for x in 1; do c''p proj/a.txt $f; done`},
	{"P", `cd ~ && f=proj/disklink; for x in 1; do cp -f proj/a.txt $f; done`},
	{"P", `cd ~ && f=proj/disklink; for x in 1; do cp proj/a.txt -- $f; done`},
	{"P", `cd /tmp && cd ~/proj/work && f=disklink; for x in 1; do cp ../a.txt $f; done`},
	{"P", `cd ~/proj/work || exit; f=disklink; for x in 1; do cp ../a.txt $f; done`},
	{"P", `cd ~ && f=proj/disklink; for x in 1; do cp proj/a.txt $f; done; cd ~/proj`},
	{"P", `s=a.txt; cp "$s" disklink`},
	{"P", `s=a.txt; c''p "$s" disklink`},
	{"P", `s=a.txt; "c"p "$s" disklink`},
	{"P", `s=a.txt; c\p "$s" disklink`},
	{"P", `s=a.txt; CP "$s" disklink`},
	{"P", `s=a.txt; /bin/c''p "$s" disklink`},
	{"P", `cd ~/proj/work && s=../a.txt; c''p "$s" disklink`},
	{"P", `s=a.txt; c''p "$s" work/disklink`},
	{"P", `cd ~ && s=proj/a.txt; c''p "$s" proj/disklink`},
	{"P", `cd /tmp; f=disklink; g() { cp ~/proj/a.txt $f; }; cd ~/proj; g`},
	{"B", `cd /tmp; g() { cp ~/proj/a.txt out2.txt; }; cd ~/proj; g`},
	{"B", `cd ~ && f=proj/out2.txt; echo $(cp proj/a.txt $f)`},
	{"B", `cd ~ && f=proj/out2.txt; x=$(cp proj/a.txt $f)`},
	{"B", `cd ~ && f=proj/out2.txt; case x in x) cp proj/a.txt $f;; esac`},
	{"B", `cd ~ && f=proj/out2.txt; while true; do cp proj/a.txt $f; break; done`},
	{"B", `cd ~ && f=proj/out2.txt; for x in 1; do for y in 1; do cp proj/a.txt $f; done; done`},
	{"B", `cd ~ && f=proj/out2.txt; { cp proj/a.txt $f; } >/dev/null`},
	{"B", `cd ~ && f=proj/out2.txt; for x in 1; do command cp proj/a.txt $f; done`},
	{"B", `s=a.txt; c''p "$s" out2.txt`},
	{"B", `s=a.txt; cp "$s" out2.txt`},
	{"B", `cd ~/proj/work && s=../a.txt; cp "$s" out2.txt`},
	{"B", `cd ~ && for x in 1; do cp proj/a.txt proj/out2.txt; done`},
	{"B", `cd ~/proj/build && for f in ../a.txt ../README.md; do cp $f .; done`},
	{"B", `cd ~ && for x in 1; do cp proj/a.txt proj/build/; done`},
	{"B", `cd /tmp && for f in a b; do cp ~/proj/a.txt ~/proj/build/$f.txt; done`},
	{"B", `cd ~/proj/build && { cp ../a.txt out.txt; cp ../README.md out.md; }`},
	{"B", `cd ~ && f=proj/a.txt; for x in 1; do cp $f proj/build/; done`},
	{"B", `cd ~/proj/work && cp ../a.txt . | cat`},
	{"B", `cd ~/proj && if [ -f a.txt ]; then cp a.txt build/; fi`},
}

func TestRVCdvarCorpus7(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX rows")
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for i, row := range rvCdvarRows7 {
				t.Run(fmt.Sprintf("%s/m=%t/%02d", connector, managed, i), func(t *testing.T) {
					home, project := rvCdvarProject(t)
					got := rvCdvarPost(t, home, project, connector, managed, row.cmd)
					verdict := "other"
					switch {
					case strings.HasPrefix(got, `{"action":"block"`):
						verdict = "block"
					case strings.HasPrefix(got, `{"action":"allow"`):
						verdict = "allow"
					}
					keys := "-"
					if strings.Contains(got, "persistence.ssh_authorized_keys_command") {
						keys = "keys"
					}
					fmt.Printf("RVROW7\t%02d\t%s\t%t\t%s\t%s\t%s\t%s\n", i, connector, managed, row.kind, verdict, keys, row.cmd)
				})
			}
		}
	}
}
