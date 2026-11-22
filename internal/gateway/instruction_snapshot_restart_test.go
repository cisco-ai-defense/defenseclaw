// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// A session's snapshot records every directory of the working directory's
// chain, the file system root (a Windows drive root, "c:") included, and a
// gateway restart restores all of them.
func TestInstructionStartupRecordKeepsTheRootDirectory(t *testing.T) {
	testenv.IsolateAccount(t)
	// The snapshot also lists the user's own instruction files
	// (~/.claude/CLAUDE.md, ~/.codex/AGENTS.md); a box that has them must not
	// change what this test sees: the same-host home is os.UserHomeDir.
	home := instructionIdentityTestRoot(t)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	project := t.TempDir()
	dataDir := t.TempDir()
	newGateway := func() *APIServer {
		api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
		api.scannerCfg.DataDir = dataDir
		return api
	}
	auth := withAuthenticatedHookConnector(t.Context(), "codex")
	newGateway().applyInstructionStartup(auth, "codex", "live", "SessionStart", "", project)
	root := filepath.VolumeName(project) + string(filepath.Separator)
	rootKey, ok := instructionDirectoryKey(root)
	if !ok {
		t.Fatalf("no directory key for %q", root)
	}
	if err := os.WriteFile(filepath.Join(project, "AGENTS.md"), []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := newGateway().applyInstructionStartup(auth, "codex", "live", "PreToolUse", "", project)
	if !got.startupKnown || !slices.Contains(got.startupDirs, rootKey) || len(got.startupFiles) != 0 {
		t.Fatalf("restart did not restore the snapshot with root %q: %+v", rootKey, got)
	}
}
