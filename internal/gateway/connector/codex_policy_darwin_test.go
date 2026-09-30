// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"path/filepath"
	"testing"
)

// /etc is a symlink on macOS, and the trusted-path checks refuse symlinked
// ancestors, so the machine requirements must be read through a canonical
// path (seen live: every per-user Codex setup failed once DefenseClaw had
// published /etc/codex/requirements.toml).
func TestCodexSystemRequirementsPathIsCanonicalOnDarwin(t *testing.T) {
	path, err := codexSystemRequirementsPath()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(filepath.Dir(path))
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != dir {
		t.Fatalf("requirements path %q has a symlinked ancestor (%s -> %s)", path, dir, resolved)
	}
	if _, ok, err := readCodexSystemRequirements(path, true); err != nil {
		t.Fatalf("readCodexSystemRequirements(%q) = ok=%v err=%v", path, ok, err)
	}
}
