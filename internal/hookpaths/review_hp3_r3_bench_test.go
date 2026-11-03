// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hp3r3Script is the gateway round 3 generator (review_hp3_r3_test.go): n
// statements mixing if/for/while/case/{ } with assignments.
func hp3r3Script(n int, many bool) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		k := i
		if !many {
			k = i % 4
		}
		switch i % 6 {
		case 0:
			fmt.Fprintf(&b, "if [ -f src/m%d.c ]; then o%d=build/m%d.o; else o%d=build/gen%d.o; fi\n", i, k, i, k, i)
		case 1:
			fmt.Fprintf(&b, "for f in src/*.c; do b%d=\"${f%%.c}.bak\"; cp \"$f\" \"$b%d\"; done\n", k, k)
		case 2:
			fmt.Fprintf(&b, "while read -r line; do n%d=$line; done < list.txt\n", k)
		case 3:
			fmt.Fprintf(&b, "case \"$MODE\" in debug) c%d=-g ;; release) c%d=-O2 ;; *) c%d=-O0 ;; esac\n", k, k, k)
		case 4:
			fmt.Fprintf(&b, "{ g%d=logs/g%d.log; mkdir -p logs; }\n", k, i)
		case 5:
			fmt.Fprintf(&b, "out%d=build/step%d.txt; printf \"%%s\\n\" \"$o%d\" > \"$out%d\"\n", k, i, k, k)
		}
	}
	return b.String()
}

func hp3r3Home(tb testing.TB) (home, project string) {
	tb.Helper()
	home = filepath.Join(tb.TempDir(), "home")
	project = filepath.Join(home, "project")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(keys), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			tb.Fatal(err)
		}
	}
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		tb.Fatal(err)
	}
	if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(project, "keylink")); err != nil {
		tb.Fatal(err)
	}
	return home, project
}

// BenchmarkHP3R3Resolve is the hook client reading of a benign script with
// many assignments inside compound statements.
func BenchmarkHP3R3Resolve(b *testing.B) {
	home, project := hp3r3Home(b)
	b.Setenv("HOME", home)
	for _, n := range []int{50, 200, 1000} {
		for _, many := range []bool{true, false} {
			payload, err := json.Marshal(map[string]any{"session_id": "b", "hook_event_name": "PreToolUse", "cwd": project,
				"tool_name": "Bash", "tool_input": map[string]any{"command": hp3r3Script(n, many)}})
			if err != nil {
				b.Fatal(err)
			}
			b.Run(fmt.Sprintf("n=%d/many=%v", n, many), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					_ = Resolve(payload)
				}
			})
		}
	}
}
