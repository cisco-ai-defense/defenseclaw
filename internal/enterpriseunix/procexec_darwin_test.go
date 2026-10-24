// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterpriseunix

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A process started as ./name has a relative exec path; the kernel names
// the absolute path of its image (GOOS=darwin only, natively).
func TestProcessImagePathNamesARelativelyLaunchedImage(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(dir, "agent-copy")
	if err := os.WriteFile(copied, data, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("./agent-copy", "30")
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	pid := cmd.Process.Pid
	if got, err := processExecPath(pid); err != nil || got != "./agent-copy" {
		t.Fatalf("exec path = %q, %v; want the relative ./agent-copy", got, err)
	}
	want, err := filepath.EvalSymlinks(copied)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := processImagePath(pid); err != nil || got != want {
		t.Fatalf("image path = %q, %v; want %q", got, err, want)
	}
	if got := absoluteExecPath("./agent-copy", func() (string, error) { return processImagePath(pid) }); got != want {
		t.Fatalf("absoluteExecPath = %q, want %q", got, want)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	if got, err := processImagePath(os.Getpid()); err != nil || got != self {
		t.Fatalf("own image path = %q, %v; want %q", got, err, self)
	}
	if _, err := processImagePath(0); err == nil {
		t.Fatal("pid 0 has no image path")
	}
}
