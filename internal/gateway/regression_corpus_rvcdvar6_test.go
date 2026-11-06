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

var rvCdvarRows6 = []struct{ kind, cmd string }{
	{"P", `pushd ~/proj/build && f=../disklink; for x in 1; do cp ../a.txt $f; done`},
	{"P", `pushd ~/proj/build && f=../disklink; cp ../a.txt $f | cat`},
	{"P", `cd -L ~/proj/build && f=../disklink; if true; then cp ../a.txt $f; fi`},
	{"P", `cd -- ~/proj/build && f=../disklink; time cp ../a.txt $f`},
	{"P", `(cd ~/proj/build && f=../disklink; for x in 1; do cp ../a.txt $f; done)`},
	{"P", `(cd ~/proj/build && f=../disklink; { cp ../a.txt $f; })`},
	{"P", `pushd ~ && f=proj/disklink; for x in 1; do cp proj/a.txt $f; done`},
	{"P", `cd -L ~ && f=proj/disklink; cp proj/a.txt $f | cat`},
	{"P", `(cd ~ && f=proj/disklink; if true; then cp proj/a.txt $f; fi)`},
	{"P", `pushd ~/proj/build && f=../disklink; echo hi; for x in 1; do cp ../a.txt $f; done`},
	{"P", `cd -L ~ && f=proj/disklink; true; for x in 1; do cp proj/a.txt $f; done`},
	{"P", `(cd ~ && f=proj/disklink; echo hi; cp proj/a.txt $f | cat)`},
	{"P", `pushd ~/proj/build && f=../disklink; cp ../a.txt out3.txt; for x in 1; do cp ../a.txt $f; done`},
	{"P", `pushd ~/proj/build && f=../disklink; cp ../a.txt $f`},
	{"P", `(cd ~ && f=proj/disklink; cp proj/a.txt $f)`},
	{"P", `cd -L ~ && f=proj/disklink; cp proj/a.txt $f`},
	{"B", `pushd ~/proj/build && f=../out2.txt; cp ../a.txt $f`},
	{"B", `(cd ~ && f=proj/out2.txt; cp proj/a.txt $f)`},
	{"B", `cd -L ~ && f=proj/out2.txt; cp proj/a.txt $f`},
	{"B", `pushd ~/proj/build && f=../out2.txt; for x in 1; do cp ../a.txt $f; done`},
}

func TestRVCdvarCorpus6(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX rows")
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for i, row := range rvCdvarRows6 {
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
					fmt.Printf("RVROW6\t%02d\t%s\t%t\t%s\t%s\t%s\t%s\n", i, connector, managed, row.kind, verdict, keys, row.cmd)
				})
			}
		}
	}
}
