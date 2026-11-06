// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build regressioncorpora

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var rvCdvarRows2 = []struct{ kind, cmd string }{
	{"P", `f=disklink; for x in 1; do cp a.txt $f; done`},
	{"P", `cd ~/proj && f=disklink; for x in 1; do cp a.txt $f; done`},
	{"P", `cd ~/proj && f=disklink; if true; then cp a.txt $f; fi`},
	{"P", `cd ~/proj && f=disklink; { cp a.txt $f; }`},
	{"P", `cd ~/proj && f=disklink; (cp a.txt $f)`},
	{"P", `cd ~/proj && f=disklink; true && cp a.txt $f`},
	{"P", `cd ~/proj && f=disklink; false || cp a.txt $f`},
	{"P", `cd ~/proj && f=disklink; while false; do :; done; cp a.txt $f`},
	{"P", `cd ~/proj && f=disklink; cp a.txt $f &`},
	{"P", `cd ~/proj && f=disklink; cp a.txt $f | cat`},
	{"P", `cd ~/proj && f=disklink; ! cp a.txt $f`},
	{"P", `cd ~/proj && f=disklink; time cp a.txt $f`},
	{"P", `cd ~/proj && f=disklink; case x in x) cp a.txt $f;; esac`},
	{"P", `cd ~/proj && f=disklink; for x in 1; do cat a.txt > $f; done`},
	{"P", `pushd ~/proj && f=disklink; for x in 1; do cp a.txt $f; done`},
	{"P", `(cd ~/proj && f=disklink; for x in 1; do cp a.txt $f; done)`},
	{"P", `cd ~/proj && f=disklink; command cp a.txt $f`},
	{"P", `cd ~/proj && f=disklink; cp a.txt $f 2>/dev/null`},
	{"P", `cd ~/proj && f=disklink; cp a.txt "${f}"`},
	{"P", `cd ~/proj && f=disklink; cp a.txt build/../$f`},
	{"P", `(cd ~/proj && f=disklink; cat a.txt > $f)`},
	{"P", `(f=disklink; cat a.txt > $f)`},
	{"P", `(cd ~/proj; f=disklink; cat a.txt > $f)`},
	{"P", `(cd ~/proj && cat a.txt > disklink)`},
	{"P", `(cd ~/proj && f=disklink; echo m >> "$f")`},
	{"P", `f=disklink; tee $f < a.txt`},
	{"P", `f=disklink; install a.txt $f`},
	{"P", `f=disklink; dd if=a.txt of=$f`},
	{"P", `cd ~/proj && f=disklink; cp a.txt $f; cp a.txt out2.txt`},
	{"B", `cd ~/proj && f=out2.txt; for x in 1; do cp a.txt $f; done`},
	{"B", `cd ~/proj && f=out2.txt; if true; then cp a.txt $f; fi`},
	{"B", `cd ~/proj && f=out2.txt; cp a.txt $f | cat`},
	{"B", `cd ~/proj && f=out2.txt; true && cp a.txt $f`},
	{"B", `(cd ~/proj && f=report.txt; cat a.txt > $f)`},
	{"B", `cd ~/proj && for f in a.txt README.md; do cp "$f" build/; done`},
	{"B", `cd ~/proj && f=out2.txt; cp a.txt $f &`},
	// N: the same project without any link (an ordinary checkout)
	{"N", `cd ~/proj && tar -xzf x.tgz -C /tmp && mv /tmp/src /tmp/src-old`},
	{"N", `cd ~/proj && tar -xzf x.tgz && mv src src-old`},
	{"N", `tar -xzf x.tgz -C /tmp && mv /tmp/src /tmp/src-old`},
	{"N", `cd ~/proj && tar -xzf x.tgz -C /tmp`},
	{"N", `mv /tmp/src /tmp/src-old`},
	{"N", `cd ~/proj && find . -name "*.tmp" -exec mv {} build/ \;`},
	{"N", `cd ~/proj && f=a.txt; cp $f build/`},
	{"N", `cd ~/proj && for f in *.txt; do cp $f build/; done`},
	{"N", `cd ~/proj && f=out2.txt; cp a.txt $f`},
	{"N", `cd ~/proj && f=out2.txt; for x in 1; do cp a.txt $f; done`},
	{"N", `cd ~/proj && f=$(ls a.txt); cp $f build/`},
}

func TestRVCdvarCorpus2(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX rows")
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for i, row := range rvCdvarRows2 {
				t.Run(fmt.Sprintf("%s/m=%t/%02d", connector, managed, i), func(t *testing.T) {
					home, project := rvCdvarProject(t)
					if row.kind == "N" {
						for _, link := range []string{filepath.Join(project, "disklink"), filepath.Join(project, "work", "disklink")} {
							if err := os.Remove(link); err != nil {
								t.Fatal(err)
							}
						}
					}
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
					fmt.Printf("RVROW2|%02d|%s|%t|%s|%s|%s|%s\n", i, connector, managed, row.kind, verdict, keys, row.cmd)
				})
			}
		}
	}
}
