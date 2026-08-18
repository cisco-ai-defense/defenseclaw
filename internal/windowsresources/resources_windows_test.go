// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package windowsresources

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestApplyPreservesGoVersionMetadata(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve resource test source path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	executable := filepath.Join(t.TempDir(), "defenseclaw-startup.exe")

	build := exec.Command("go", "build", "-o", executable, "./cmd/defenseclaw-startup")
	build.Dir = repositoryRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Go metadata probe: %v\n%s", err, output)
	}

	versionMetadata := func() []byte {
		t.Helper()
		command := exec.Command("go", "version", "-m", executable)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("read Go build metadata: %v\n%s", err, output)
		}
		return output
	}
	before := versionMetadata()
	if !bytes.Contains(before, []byte("github.com/defenseclaw/defenseclaw")) {
		t.Fatalf("Go metadata probe omitted the module identity:\n%s", before)
	}

	icon := filepath.Join(repositoryRoot, filepath.FromSlash(IconSource))
	if err := Apply(executable, ComponentStartup, "1.2.3", icon); err != nil {
		t.Fatalf("apply Windows resources: %v", err)
	}
	if err := Verify(executable, ComponentStartup, "1.2.3", icon); err != nil {
		t.Fatalf("verify Windows resources: %v", err)
	}
	after := versionMetadata()
	if !bytes.Equal(after, before) {
		t.Fatalf("Windows resource mutation changed go version -m metadata\nbefore:\n%s\nafter:\n%s", before, after)
	}
}
