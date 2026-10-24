// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR104LeadHermesPatchLinkTarget(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(project, "w0-v4a-link")
	protected := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.Symlink(filepath.Join(project, "d")+"\n*** Add File: "+protected, link); err != nil {
		t.Fatal(err)
	}
	patch := "*** Begin Patch\n*** Add File: w0-v4a-link\n+marker\n*** End Patch\n"
	args, err := json.Marshal(map[string]string{"mode": "patch", "patch": patch})
	if err != nil {
		t.Fatal(err)
	}
	if _, known := ApplyPatchWriteTargets("apply_patch", args, "", project, home); known {
		t.Fatal("patch link with a directive-bearing target was treated as a proved ordinary file effect")
	}
	if target, ok := ResolveWriteTarget(link); !ok || !strings.Contains(target, "\n") {
		t.Fatalf("ordinary file-open target=%q known=%v", target, ok)
	}
	if target, ok := ResolvePatchWriteTarget(link); ok {
		t.Fatalf("patch link target %q was treated as a proved ordinary destination", target)
	}
	ordinary := filepath.Join(project, "ordinary-link")
	if err := os.Symlink(filepath.Join(project, "ordinary.txt"), ordinary); err != nil {
		t.Fatal(err)
	}
	if target, ok := ResolveWriteTarget(ordinary); !ok || target != filepath.Join(project, "ordinary.txt") {
		t.Fatalf("ordinary link target=%q known=%v", target, ok)
	}
}
