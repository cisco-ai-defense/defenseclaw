// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"
)

// A nested command uses its own shell's binder roles. A runtime printf
// format can affect only names supplied as assignment operands.
func TestG235Round8BinderRoles(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	rows := []struct {
		name, shell, command string
		block                bool
	}{
		{"zsh/separate-link", "/bin/zsh", `f=out2.txt; printf -v f %s disklink; echo marker >> "$f"`, true},
		{"zsh/separate-ordinary", "/bin/zsh", `f=out2.txt; printf -v f %s a.txt; echo marker >> "$f"`, false},
		{"nested/bash", "/bin/zsh", `bash -c 'f=out2.txt; printf -vf %s disklink; echo marker >> "$f"'`, true},
		{"nested/zsh", "/bin/bash", `zsh -c 'f=disklink; printf -vf %s out2.txt; echo marker >> "$f"'`, true},
		{"nested/env-bash", "/bin/zsh", `env -i bash -c 'f=out2.txt; printf -vf %s disklink; echo marker >> "$f"'`, true},
		{"nested/env-zsh", "/bin/bash", `env -- zsh -c 'f=disklink; printf -vf %s out2.txt; echo marker >> "$f"'`, true},
		{"nested/bash-ordinary", "/bin/zsh", `bash -c 'f=out2.txt; printf -vf %s a.txt; echo marker >> "$f"'`, false},
		{"nested/zsh-ordinary", "/bin/bash", `zsh -c 'f=out2.txt; printf -vf %s a.txt; echo marker >> "$f"'`, false},
		{"unknown-format/ordinary", "/bin/bash", `f=out2.txt; printf "$X" hello; cp a.txt "$f"`, false},
		{"unknown-format/link", "/bin/bash", `f=disklink; printf "$X" hello; cp a.txt "$f"`, true},
	}
	for _, row := range rows {
		for _, connector := range []string{"claudecode", "codex"} {
			for _, managed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/managed=%t", row.name, connector, managed), func(t *testing.T) {
					t.Setenv("SHELL", row.shell)
					got := postDynamicWordParityCell(t, home, project, connector, managed, managed, false, row.command, nil)
					want := `{"action":"allow"`
					if row.block {
						want = `{"action":"block"`
					}
					if !strings.HasPrefix(got, want) {
						t.Errorf("verdict %.300s, want %s", got, want)
					}
				})
			}
		}
	}
}
