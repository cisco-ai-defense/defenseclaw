// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestIsShellCommandStringWrapper(t *testing.T) {
	for _, row := range []struct {
		name string
		exec string
		argv []string
		want bool
	}{
		{"bash -c", "bash", []string{"bash", "-c", "true"}, true},
		{"sh -c", "sh", []string{"sh", "-c", "true"}, true},
		{"dash -c", "dash", []string{"dash", "-c", "true"}, true},
		{"absolute path", "/bin/bash", []string{"/bin/bash", "-c", "true"}, true},
		{"windows name", `C:\\Program Files\\Git\\bin\\bash.exe`, []string{"bash.exe", "-c", "true"}, true},
		{"script file", "bash", []string{"bash", "./run.sh"}, false},
		{"stdin", "bash", []string{"bash"}, false},
		{"parse only", "bash", []string{"bash", "-n", "-c", "true"}, false},
		{"login shell", "bash", []string{"bash", "-lc", "true"}, false},
		{"zsh", "zsh", []string{"zsh", "-c", "true"}, false},
		{"not a shell", "sudo", []string{"sudo", "-c", "true"}, false},
		{"empty", "", nil, false},
	} {
		if got := IsShellCommandStringWrapper(WrapperFact{Executable: row.exec, Argv: row.argv}); got != row.want {
			t.Errorf("%s: got %v, want %v", row.name, got, row.want)
		}
	}
}
