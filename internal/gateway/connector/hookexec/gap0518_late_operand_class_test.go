// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGAP0518LongOrdinaryOperandsAcrossPrograms(t *testing.T) {
	home := t.TempDir()
	real := filepath.Join(home, "project")
	cwd := filepath.Join(home, "project-link")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, cwd); err != nil {
		t.Fatal(err)
	}
	ssh := filepath.Join(home, ".ssh")
	if err := os.Mkdir(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(ssh, "authorized_keys")
	if err := os.WriteFile(key, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(key, filepath.Join(real, "alias")); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 2000)
	known := make([]string, len(names))
	for i := range names {
		names[i] = fmt.Sprintf("leaf%d.txt", i)
		known[i] = `"$PWD"/` + names[i]
	}
	for _, tc := range []struct {
		name, command string
	}{
		{"touch", "touch " + strings.Join(names, " ")},
		{"touch date", "touch -d 2026-11-06 " + strings.Join(names, " ")},
		{"touch attached date", "touch --date=2026-11-06 " + strings.Join(names, " ")},
		{"touch known cwd", "touch " + strings.Join(known, " ")},
		{"mkdir", "mkdir -p " + strings.Join(names, " ")},
		{"remove missing", "rm -f " + strings.Join(names, " ")},
		{"copy sources", "cp -t . " + strings.Join(names, " ")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call := func(command string) []byte {
				return []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` +
					mustJSONString(cwd) + `,"tool_input":{"command":` + mustJSONString(command) + `}}`)
			}
			if !ordinaryNoAnswerPayloadInHome(call(tc.command), home) {
				t.Fatal("ordinary long call has no late proof")
			}
			for _, index := range []int{0, len(names) / 2, len(names) - 1} {
				withAlias := strings.Replace(tc.command, names[index], "alias", 1)
				if ordinaryNoAnswerPayloadInHome(call(withAlias), home) {
					t.Fatalf("linked protected operand at %d received a late proof", index)
				}
			}
		})
	}
}
