// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package agentprocess

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkingDirectoryReadsAProcessCurrentFolder(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if got := workingDirectory(os.Getpid()); got != dir {
		t.Errorf("workingDirectory = %q, want %q", got, dir)
	}
	if got := workingDirectory(1 << 30); got != "" {
		t.Errorf("workingDirectory of a missing process = %q, want empty", got)
	}
}
