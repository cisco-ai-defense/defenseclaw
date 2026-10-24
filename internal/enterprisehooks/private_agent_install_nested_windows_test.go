//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A runnable copy is found at any depth below the profile (GAP-0988), the
// walk never follows a junction as LocalSystem, and a walk over its bound
// says the scan is incomplete.
func TestDiscoverWindowsPrivateInstallsFindCopiesAtAnyDepth(t *testing.T) {
	claude := filepath.Join("node_modules", "@anthropic-ai", "claude-code")
	for _, tc := range []struct {
		name  string
		bound int
		build func(t *testing.T, home, outside string)
		want  []string
	}{
		{name: "npm --prefix copy two folders down", build: func(t *testing.T, home, _ string) {
			windowsClaudeCopy(t, filepath.Join(home, "r21-holder", "deep", "r21-copy", claude), "2.0.77", "cli.js")
		}, want: []string{`claudecode 2.0.77 \r21-holder\deep\r21-copy\node_modules\@anthropic-ai\claude-code`}},
		{name: "a nested dependency of a project's package", build: func(t *testing.T, home, _ string) {
			windowsClaudeCopy(t, filepath.Join(home, "src", "proj", "node_modules", "wrapper", claude), "2.0.77", "cli.js")
		}, want: []string{`claudecode 2.0.77 \src\proj\node_modules\wrapper\node_modules\@anthropic-ai\claude-code`}},
		{name: "a junction to another folder is not followed", build: func(t *testing.T, home, outside string) {
			windowsClaudeCopy(t, filepath.Join(outside, "tools", claude), "2.0.77", "cli.js")
			if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(home, "linked"), outside).CombinedOutput(); err != nil {
				t.Fatalf("mklink /J: %v: %s", err, out)
			}
		}},
		{name: "a profile over the walk bound is incomplete", bound: 16, build: func(t *testing.T, home, _ string) {
			for i := 0; i < 24; i++ {
				if err := os.MkdirAll(filepath.Join(home, "many", fmt.Sprintf("d%02d", i)), 0o755); err != nil {
					t.Fatal(err)
				}
			}
		}, want: []string{"claudecode incomplete " + PrivateInstallSkippedHome}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.bound > 0 {
				previous := privateInstallWalkMaxEntries
				privateInstallWalkMaxEntries = tc.bound
				t.Cleanup(func() { privateInstallWalkMaxEntries = previous })
			}
			home, outside := t.TempDir(), t.TempDir()
			tc.build(t, home, outside)
			var got []string
			for _, install := range DiscoverWindowsPrivateAgentInstalls(home, []string{"claudecode"}) {
				if install.Incomplete {
					skipped, _ := windowsInstallFacts(t, install)["skipped"].(string)
					got = append(got, install.Connector+" incomplete "+skipped)
					continue
				}
				got = append(got, install.Connector+" "+install.Version+" "+strings.TrimPrefix(install.Path, home))
			}
			sort.Strings(got)
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("copies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}
