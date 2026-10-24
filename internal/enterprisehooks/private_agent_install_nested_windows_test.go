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

// A directory opened below a junction must not be read through that junction.
// The same rule closes a rename race that replaces a listed child with a
// junction before its directory handle is opened.
func TestOpenWindowsPrivateWalkDirRejectsReparseAncestors(t *testing.T) {
	home, outside := t.TempDir(), t.TempDir()
	inside := filepath.Join(home, "plain", "nested")
	remote := filepath.Join(outside, "nested")
	for _, dir := range []string{inside, remote} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(remote, "outside-only"), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inside, "inside-only"), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	if file, err := openWindowsPrivateWalkDir(inside); err != nil {
		t.Fatalf("open plain directory: %v", err)
	} else {
		defer file.Close()
		if err := os.Rename(inside, inside+"-held"); err != nil {
			t.Fatalf("rename held directory: %v", err)
		}
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", inside, remote).CombinedOutput(); err != nil {
			t.Fatalf("replace directory with junction: %v: %s", err, out)
		}
		entries, err := file.ReadDir(-1)
		if err != nil || len(entries) != 1 || entries[0].Name() != "inside-only" {
			t.Fatalf("held handle listed the replacement: entries=%v error=%v", entries, err)
		}
	}
	link := filepath.Join(home, "linked")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, outside).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	for _, dir := range []string{link, filepath.Join(link, "nested")} {
		file, err := openWindowsPrivateWalkDir(dir)
		if file != nil {
			_ = file.Close()
		}
		if err == nil {
			t.Errorf("opened a directory through reparse path %s", dir)
		}
	}
	// A substituted drive has no reparse attribute on its directory handle.
	// The handle's final path must still match the local drive path we opened.
	var mappedDrive string
	for letter := 'Z'; letter >= 'P'; letter-- {
		candidate := string(letter) + ":"
		if err := exec.Command("subst", candidate, outside).Run(); err == nil {
			mappedDrive = candidate
			break
		}
	}
	if mappedDrive == "" {
		t.Skip("no free drive letter for substituted-drive check")
	}
	t.Cleanup(func() { _ = exec.Command("subst", mappedDrive, "/D").Run() })
	file, err := openWindowsPrivateWalkDir(filepath.Join(mappedDrive+`\`, "nested"))
	if file != nil {
		_ = file.Close()
	}
	if err == nil {
		t.Fatal("opened a directory through a substituted drive")
	}
}
