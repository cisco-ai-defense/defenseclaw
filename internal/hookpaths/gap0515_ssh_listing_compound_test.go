// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestGAP0515SSHListingCompoundHomePaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home paths")
	}
	for _, row := range []struct{ name, home string }{
		{"macOS", "/Users/alice"},
		{"Linux", "/home/alice"},
	} {
		t.Run(row.name, func(t *testing.T) {
			cwd := filepath.Join(row.home, "project")
			absolute := filepath.Join(row.home, ".ssh")
			for _, command := range []string{
				`ls ~/.ssh; echo done`,
				`ls ~/.ssh && echo done`,
				`ls ~/.ssh; pwd`,
				`ls ~/.ssh && pwd`,
				`ls "$HOME/.ssh"; pwd`,
				`ls ` + absolute + `; pwd`,
			} {
				if got := posixShellDecision(command, cwd, row.home); got != "" {
					t.Errorf("%q: decision %q, want allow", command, got)
				}
			}
			for _, command := range []string{
				`ls ~/.ssh; echo marker >> ~/.ssh/authorized_keys`,
				`ls ~/.ssh && cp payload ~/.ssh/authorized_keys`,
				`ls ~/.ssh; pwd > ~/.ssh/authorized_keys`,
				`ls ~/.ssh && pwd > ~/.ssh/authorized_keys`,
				`ls ` + absolute + `; pwd; echo marker >> ` + filepath.Join(absolute, "authorized_keys"),
			} {
				if got := posixShellDecision(command, cwd, row.home); got != "protected-target" {
					t.Errorf("%q: decision %q, want protected-target", command, got)
				}
			}
		})
	}
}
