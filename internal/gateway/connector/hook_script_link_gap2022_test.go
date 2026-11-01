package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// GAP-2022: a link put in place of a generated hook script made every render
// write through the link, so the script stayed a link and doctor --fix never
// converged. The render replaces the link with a regular file and leaves the
// link's target alone.
func TestWriteHookScriptsReplacesALinkInPlaceOfAGeneratedScript(t *testing.T) {
	hookDir := filepath.Join(t.TempDir(), "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere.sh")
	original := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(target, original, 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(hookDir, "inspect-tool.sh")
	if err := os.Symlink(target, script); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}

	if err := writeHookScriptsCommon(hookDir, "127.0.0.1:18970", "test-token", nil); err != nil {
		t.Fatalf("writeHookScriptsCommon: %v", err)
	}

	info, err := os.Lstat(script)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("inspect-tool.sh is still %v, want a regular file", info.Mode())
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("the link target was rewritten: %q", got)
	}
}
