// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func buildGitListFixture(t *testing.T, output string, outputBytes int) string {
	t.Helper()
	binDir := t.TempDir()
	name := "git"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	source := filepath.Join(binDir, "main.go")
	program := "package main\nimport (\"bytes\"; \"fmt\"; \"os\")\nvar _ = bytes.Repeat\nvar _ = fmt.Print\nvar _ = os.Stdout\nfunc main() {"
	if outputBytes > 0 {
		program += fmt.Sprintf(" _, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, %d)) ", outputBytes)
	} else {
		program += " fmt.Print(" + strconv.Quote(output) + ") "
	}
	program += "}\n"
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("go", "build", "-o", filepath.Join(binDir, name), source).Run(); err != nil {
		t.Fatalf("build git fixture: %v", err)
	}
	return binDir
}

// TestRunGitList_CapsRunawayStdout (L-2) verifies the io.LimitReader
// guard rejects a git invocation that streams more than the byte cap
// instead of buffering it all into the gateway's RAM.
//
// We avoid spinning up a real git: the function just exec's git, so we
// substitute a tiny shim by writing a fake `git` script into a temp
// directory and prepending it to PATH for the duration of the test.
// The shim writes more than runGitListMaxBytes bytes to stdout, which
// exercises the cap in runGitList without needing a real repo.
func TestRunGitList_CapsRunawayStdout(t *testing.T) {
	// 16 MiB > runGitListMaxBytes (8 MiB).
	binDir := buildGitListFixture(t, "", runGitListMaxBytes*2)

	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cwd := t.TempDir()
	_, err := runGitList(context.Background(), cwd, "ls-files")
	if err == nil {
		t.Fatalf("runGitList accepted runaway stdout — L2 regression")
	}
	if !strings.Contains(err.Error(), "exceeded") &&
		!strings.Contains(err.Error(), "read stdout") {
		t.Fatalf("runGitList error %q does not mention the cap; was the io.LimitReader guard removed?", err)
	}
}

// TestRunGitList_HostileRepoIgnoresLocalConfig (CRITICAL regression)
// constructs a worktree whose .git/config sets core.fsmonitor and
// core.hooksPath to commands that, if executed by git, would
// side-channel a marker into a tempfile. The gitsafe wrapper MUST
// suppress those settings via -c overrides so git runs cleanly and
// no marker file is ever created.
//
// The test uses the real `git` binary (skipping when absent) because
// the threat model is specifically: git itself is the attacker's
// jumping-off point. Running through the wrapper proves the
// mitigations apply end-to-end.
func TestRunGitList_HostileRepoIgnoresLocalConfig(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("real git not on PATH")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh available")
	}
	repo := t.TempDir()
	marker := filepath.Join(t.TempDir(), "pwned.txt")
	gitDir := filepath.Join(repo, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "objects"), 0o700); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0o700); err != nil {
		t.Fatalf("mkdir refs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatalf("write HEAD: %v", err)
	}
	// A hostile config: every executable git config knob that has
	// historically been used for RCE in malicious worktree CVEs.
	hostileConfig := fmt.Sprintf(`[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
	fsmonitor = "sh -c 'echo fsmonitor > %s'"
	hooksPath = "%s"
	useReplaceRefs = true
	editor = "sh -c 'echo editor > %s'"
[diff]
	external = "sh -c 'echo diff > %s'"
[uploadpack]
	packObjectsHook = "sh -c 'echo packhook > %s'"
`, marker, gitDir, marker, marker, marker)
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte(hostileConfig), 0o600); err != nil {
		t.Fatalf("write hostile config: %v", err)
	}
	// Plant a hooks/pre-commit just in case core.hooksPath escaped
	// the override; runGitList only reads, but layered defense.
	if err := os.WriteFile(filepath.Join(gitDir, "pre-commit"),
		[]byte(fmt.Sprintf("#!/bin/sh\necho hooks > %s\n", marker)), 0o700); err != nil {
		t.Fatalf("write pre-commit: %v", err)
	}

	// runGitList swallows the diff-against-HEAD error in
	// gitChangedFiles by combining with ls-files; here we invoke
	// directly so we exercise both the env scrub and the -c flags.
	if _, err := runGitList(context.Background(), repo, "ls-files", "--others", "--exclude-standard"); err != nil {
		// Errors are acceptable as long as no helper fired.
		t.Logf("runGitList (acceptable) error: %v", err)
	}
	if _, err := runGitList(context.Background(), repo, "diff", "--name-only", "HEAD", "--"); err != nil {
		t.Logf("runGitList diff (acceptable) error: %v", err)
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		data, _ := os.ReadFile(marker)
		t.Fatalf("hostile config triggered: marker=%q content=%q (CRITICAL regression — gitsafe wrapper failed)", marker, data)
	}
}

func TestRunGitList_AcceptsSmallOutput(t *testing.T) {
	binDir := buildGitListFixture(t, "a\nb\nc\n", 0)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	got, err := runGitList(context.Background(), t.TempDir(), "ls-files")
	if err != nil {
		t.Fatalf("runGitList: %v", err)
	}
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}
