// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-1515: a write through a directory junction lands in the junction
// target. Go reports a junction as os.ModeIrregular, so the write-target walk
// must follow it like a symbolic link, also when the key file does not exist
// yet (a staged "*** Add File: sshlink/authorized_keys" patch).
func TestWriteTargetFollowsAJunctionParentToTheKeyFile(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows junction")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	build := filepath.Join(cwd, "build")
	for _, dir := range []string{ssh, cwd, build} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(cwd, "sshlink"), ssh).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v %s", err, out)
	}
	want := filepath.Join(ssh, "authorized_keys")
	operand := filepath.Join(cwd, "sshlink", "authorized_keys")
	for name, resolve := range map[string]func(string) (string, bool){
		"write": ResolveWriteTarget,
		"patch": ResolvePatchWriteTarget,
	} {
		got, ok := resolve(operand)
		if !ok || !samePathName(got, want) {
			t.Fatalf("%s target of %s = %q, %v; want %q", name, operand, got, ok, want)
		}
	}
	plain := filepath.Join(build, "authorized_keys")
	if got, ok := ResolveWriteTarget(plain); !ok || !samePathName(got, plain) {
		t.Fatalf("plain directory target = %q, %v; want %q", got, ok, plain)
	}
}
