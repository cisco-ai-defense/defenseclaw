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
	"strings"
	"testing"
)

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
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh available")
	}
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	gitShim := filepath.Join(binDir, "git")
	// 16 MiB > runGitListMaxBytes (8 MiB). Each "x" line is 4097
	// bytes including newline so we need ~4100 lines to exceed the
	// cap; printing a 16-MiB block via head is simpler.
	script := fmt.Sprintf(`#!/bin/sh
# Emit %d bytes of payload (well over runGitListMaxBytes).
yes "spam-line-that-is-not-trivially-short" | head -c %d
exit 0
`, runGitListMaxBytes*2, runGitListMaxBytes*2)
	if err := os.WriteFile(gitShim, []byte(script), 0o700); err != nil {
		t.Fatalf("write git shim: %v", err)
	}

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

func TestRunGitList_AcceptsSmallOutput(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh available")
	}
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	gitShim := filepath.Join(binDir, "git")
	script := `#!/bin/sh
printf 'a\nb\nc\n'
exit 0
`
	if err := os.WriteFile(gitShim, []byte(script), 0o700); err != nil {
		t.Fatalf("write git shim: %v", err)
	}
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
