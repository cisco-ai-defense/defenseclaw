// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A directive that goes through a link into a directory the user cannot open
// is a target the hook client describes (it reports the empty answer and the
// link text), where the gateway's own reading of it is unknown. A link whose
// text holds a line break stays unknown for both: a patch parser could read the
// name as another directive.
func TestApplyPatchClientTargetsKeepALinkIntoAClosedDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX link walk")
	}
	root := t.TempDir()
	project := filepath.Join(root, "proj")
	closed := filepath.Join(root, "closed")
	for _, dir := range []string{project, closed} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		"plain":  filepath.Join(closed, "notes.txt"),
		"broken": filepath.Join(closed, "line\nbreak"),
	} {
		if err := os.Symlink(target, filepath.Join(project, link)); err != nil {
			t.Skipf("no symlinks: %v", err)
		}
	}
	if err := os.Chmod(closed, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
	envelope := func(name string) json.RawMessage {
		args, _ := json.Marshal(map[string]any{"command": "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: " + name + "\n+x\n*** End Patch\nEOF\n"})
		return args
	}
	if _, ok := ApplyPatchWriteTargets("Bash", envelope("plain"), "", project, root); ok {
		t.Fatal("the gateway reading of a link into a closed directory is known")
	}
	targets, ok := ApplyPatchClientTargets("Bash", envelope("plain"), "", project, root)
	if !ok || len(targets) != 1 || targets[0] != filepath.Join(project, "plain") {
		t.Fatalf("client targets = %v, %v; want the link", targets, ok)
	}
	if _, ok := ApplyPatchClientTargets("Bash", envelope("broken"), "", project, root); ok {
		t.Fatal("a link text with a line break is a known target")
	}
}
