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

var rvCdvarRows3 = []struct{ kind, cmd string }{
	{"P", `cd -L ~/proj && f=disklink; for x in 1; do cp a.txt $f; done`},
	{"P", `cd -- ~/proj && f=disklink; if true; then cp a.txt $f; fi`},
	{"P", `pushd ~/proj && f=disklink; { cp a.txt $f; }`},
	{"P", `pushd ~/proj && f=disklink; cp a.txt $f | cat`},
	{"P", `(cd ~/proj && f=disklink; if true; then cp a.txt $f; fi)`},
	{"P", `(pushd ~/proj && f=disklink; for x in 1; do cp a.txt $f; done)`},
	{"P", `(cd ~/proj && f=disklink; cp a.txt $f | cat)`},
	{"P", `(cd ~/proj && f=disklink; time cp a.txt $f)`},
	{"P", `pushd ~/proj && f=disklink; for x in 1; do cat a.txt > $f; done`},
	{"P", `(cd ~/proj && f=disklink; { cp a.txt $f; })`},
	{"P", `cd ~/proj && f=disklink; for x in 1; do cp -a a.txt $f; done`},
	{"B", `pushd ~/proj && f=out2.txt; for x in 1; do cp a.txt $f; done`},
	{"B", `(cd ~/proj && f=out2.txt; for x in 1; do cp a.txt $f; done)`},
	{"B", `cd -L ~/proj && f=out2.txt; for x in 1; do cp a.txt $f; done`},
}

func TestRVCdvarCorpus3(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX rows")
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{false, true} {
			for i, row := range rvCdvarRows3 {
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
					fmt.Printf("RVROW3\t%02d\t%s\t%t\t%s\t%s\t%s\t%s\n", i, connector, managed, row.kind, verdict, keys, row.cmd)
				})
			}
		}
	}
}
