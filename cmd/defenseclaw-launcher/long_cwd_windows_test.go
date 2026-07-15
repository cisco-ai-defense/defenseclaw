// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLauncherLongWorkingDirectoryHelper(t *testing.T) {
	if os.Getenv("DEFENSECLAW_LAUNCHER_LONG_CWD_HELPER") != "1" {
		return
	}
	if err := os.Chdir(os.Getenv("DEFENSECLAW_LAUNCHER_LOGICAL_CWD")); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Print(cwd)
	os.Exit(0)
}

func TestLauncherWorkingDirectorySupportsPathBeyondMAXPath(t *testing.T) {
	root := t.TempDir()
	for len(root) < 285 {
		root = filepath.Join(root, "defenseclaw-launcher-long-repository-segment")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if len(root) <= 260 {
		t.Fatalf("fixture path length=%d, want >260", len(root))
	}

	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	}()
	logical, processDir, err := launcherWorkingDirectories(filepath.Dir(os.Args[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(logical, `\\?\`) {
		t.Fatalf("logical directory=%q, want extended path", logical)
	}
	if len(processDir) > 260 || !filepath.IsAbs(processDir) {
		t.Fatalf("process directory=%q, want short absolute volume root", processDir)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestLauncherLongWorkingDirectoryHelper$")
	cmd.Dir = processDir
	cmd.Env = append(os.Environ(),
		"DEFENSECLAW_LAUNCHER_LONG_CWD_HELPER=1",
		"DEFENSECLAW_LAUNCHER_LOGICAL_CWD="+logical,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("launch from %d-character cwd: %v\n%s", len(root), err, output)
	}
	actualInfo, err := os.Stat(strings.TrimSpace(string(output)))
	if err != nil {
		t.Fatalf("stat child cwd %q: %v", output, err)
	}
	wantInfo, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(actualInfo, wantInfo) {
		t.Fatalf("child cwd=%q, want file identity of %q", output, root)
	}
}
