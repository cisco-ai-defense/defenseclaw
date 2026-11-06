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

var rvCdvarRows4 = []struct{ kind, cmd string }{
	// after pushd / cd options / subshell: nested shapes not in the committed table
	{"P", `pushd ~/proj && f=disklink; case x in x) cp a.txt $f;; esac`},
	{"P", `cd -L ~/proj && f=disklink; cp a.txt $f &`},
	{"P", `cd -- ~/proj && f=disklink; ! cp a.txt $f`},
	{"P", `pushd ~/proj && f=disklink; while true; do cp a.txt $f; break; done`},
	{"P", `pushd ~/proj && f=disklink; until false; do cp a.txt $f; break; done`},
	{"P", `pushd ~/proj && f=disklink; for x in 1; do cp a.txt "$f"; done`},
	{"P", `cd -L ~/proj && f=disklink; for x in 1; do cp a.txt ${f}; done`},
	{"P", `pushd ~/proj && d=.; for x in 1; do cp a.txt $d/disklink; done`},
	{"P", `pushd ~/proj && f=disklink && for x in 1; do cp a.txt $f; done`},
	{"P", `pushd ~/proj/work && f=disklink; for x in 1; do cp ../a.txt $f; done`},
	{"P", `(pushd ~/proj && f=disklink; cp a.txt $f | cat)`},
	{"P", `(cd -- ~/proj && f=disklink; time cp a.txt $f)`},
	{"P", `(cd ~/proj && f=disklink; case x in x) cp a.txt $f;; esac)`},
	{"P", `(cd ~/proj && f=disklink; cp a.txt $f &)`},
	{"P", `pushd ~/proj && f=disklink; for x in 1; do gcp a.txt $f; done`},
	{"P", `pushd ~/proj && f=disklink; for x in 1; do command cp a.txt $f; done`},
	{"P", `pushd ~/proj && f=disklink; for x in 1; do cp -f -- a.txt $f; done`},
	// after pushd / cd options / subshell: placed (top-level) shapes
	{"P", `pushd ~/proj && f=disklink; true && cp a.txt $f`},
	{"P", `pushd ~/proj && f=disklink; false || cp a.txt $f`},
	{"P", `pushd ~/proj && f=disklink; cp a.txt $f 2>/dev/null`},
	{"P", `pushd ~/proj && f=disklink; command cp a.txt $f`},
	{"P", `pushd ~/proj && f=disklink; (cp a.txt $f)`},
	{"P", `pushd ~/proj && f=disklink; cp a.txt "$f"`},
	{"P", `pushd ~/proj && f=disklink; popd; cp a.txt $f`},
	{"P", `(cd ~/proj && f=disklink; true && cp a.txt $f)`},
	{"P", `cd -L ~/proj && f=disklink; cp -- a.txt $f`},
	// plain cd: nested shapes (the binding stays everywhere; relies on the hookparse5 walk)
	{"P", `cd ~/proj && f=disklink; for x in 1; do cp a.txt "$f"; done`},
	{"P", `cd ~/proj && f=disklink; while true; do cp a.txt $f; break; done`},
	{"P", `cd ~/proj && f=disklink; until false; do cp a.txt $f; break; done`},
	{"P", `cd ~/proj && f=disklink; for x in 1; do cp -f a.txt $f; done`},
	{"P", `cd ~/proj && f=disklink; for x in 1; do command cp a.txt $f; done`},
	{"P", `cd ~/proj && f=disklink; for x in 1; do gcp a.txt $f; done`},
	{"P", `cd ~/proj && f=disklink; if true; then cp a.txt ${f}; fi`},
	{"P", `cd ~/proj/work && f=disklink; for x in 1; do cp ../a.txt $f; done`},
	{"P", `cd ~ && f=proj/disklink; for x in 1; do cp proj/a.txt $f; done`},
	{"P", `cd ~/proj && f=disklink; pushd . ; for x in 1; do cp a.txt $f; done`},
	{"P", `cd ~/proj && d=.; for x in 1; do cp a.txt $d/disklink; done`},
	{"P", `cd ~/proj && f=disklink; cp a.txt $f & wait`},
	{"P", `cd -P ~/proj && f=disklink; for x in 1; do cp a.txt $f; done`},
	// benign twins
	{"B", `pushd ~/proj && f=out2.txt; true && cp a.txt $f`},
	{"B", `pushd ~/proj && f=out2.txt; cp a.txt $f 2>/dev/null`},
	{"B", `pushd ~/proj && f=out2.txt; command cp a.txt $f`},
	{"B", `pushd ~/proj && f=out2.txt; (cp a.txt $f)`},
	{"B", `pushd ~/proj && f=out2.txt; popd; cp a.txt $f`},
	{"B", `cd -L ~/proj && f=out2.txt; cp -- a.txt $f`},
	{"B", `(cd ~/proj && f=out2.txt; true && cp a.txt $f)`},
	{"B", `pushd ~/proj && f=out2.txt; case x in x) cp a.txt $f;; esac`},
	{"B", `cd ~/proj && f=out2.txt; for x in 1; do cp a.txt "$f"; done`},
	{"B", `cd ~/proj && f=out2.txt; while true; do cp a.txt $f; break; done`},
	{"B", `cd ~/proj && f=out2.txt; if true; then cp a.txt ${f}; fi`},
	{"B", `cd ~/proj && f=out2.txt; { cp a.txt $f; }`},
	{"B", `cd ~/proj && f=out2.txt; time cp a.txt $f`},
	{"B", `cd ~/proj && f=a.txt; for x in 1; do cp $f build/; done`},
	{"B", `pushd ~/proj && f=a.txt; cp $f build/`},
	{"B", `pushd ~/proj && f=a.txt; for x in 1; do cp $f build/; done`},
	{"B", `(cd ~/proj && f=a.txt; cp $f build/)`},
	{"B", `cd -L ~/proj && f=a.txt; cp "$f" build/`},
	{"B", `cd ~/proj && d=build; for x in 1; do cp a.txt $d/; done`},
	{"B", `pushd ~/proj && d=build; cp a.txt $d/`},
}

func TestRVCdvarCorpus4(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX rows")
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for i, row := range rvCdvarRows4 {
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
					fmt.Printf("RVROW4\t%02d\t%s\t%t\t%s\t%s\t%s\t%s\n", i, connector, managed, row.kind, verdict, keys, row.cmd)
				})
			}
		}
	}
}
