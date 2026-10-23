// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestGAP0781ConditionalProjectPatches(t *testing.T) {
	root := t.TempDir()
	cwd, home := filepath.Join(root, "project"), root
	command := "if [ -f race.txt ]; then rg -Fx -- 't7-copy-race' race.txt >/dev/null || apply_patch <<'PATCH'\n" +
		"*** Begin Patch\n*** Update File: race.txt\n@@\n+t7-copy-race\n*** End Patch\nPATCH\nelse\n" +
		"apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: race.txt\n+t7-copy-race\n*** End Patch\nPATCH\nfi\n" +
		"rg -n -Fx -- 't7-copy-race' race.txt"
	targets, known := ApplyPatchWriteTargets("exec_command", nil, command, cwd, home)
	if !known || len(targets) != 2 || targets[0] != filepath.Join(cwd, "race.txt") || targets[1] != targets[0] {
		t.Fatalf("ordinary patch targets = %q, known=%v", targets, known)
	}
	if got := ActionCommandDecision(command, cwd, home); got != "" {
		t.Fatalf("ordinary project patch blocked: %s", got)
	}
	protected := strings.Replace(command, "*** Add File: race.txt", "*** Add File: ../.ssh/authorized_keys", 1)
	if got := ActionCommandDecision(protected, cwd, home); got == "" {
		t.Fatal("conditional patch with a protected target allowed")
	}
	unknown := strings.Replace(command, "*** Add File: race.txt", "*** Add File: $TARGET", 1)
	if _, ok := ApplyPatchWriteTargets("exec_command", nil, unknown, cwd, home); ok {
		t.Fatal("computed patch target was treated as resolved")
	}
	if got := ActionCommandDecision(unknown, cwd, home); got == "" {
		t.Fatal("conditional patch with a computed target allowed")
	}
}
