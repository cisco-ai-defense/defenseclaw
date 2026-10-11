// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enforce

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-1007: the gateway asks the hook guardian to remove a quarantined skill
// whose name ends with a dot or a space by its exact extended path, and the
// guardian checks that path against the ordinary enrolled roots. It refused
// every such request as outside the watched folders, so the skill stayed.
func TestGuardianRemovesExtendedTrailingNameSource(t *testing.T) {
	root := longTestPath(t, t.TempDir())
	skills := filepath.Join(root, "user", "skills")
	quarantine := filepath.Join(root, "quarantine")
	sibling := filepath.Join(skills, "tdot")
	if err := os.MkdirAll(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tdot.", "tsp "} {
		source := `\\?\` + skills + `\` + name
		if err := os.Mkdir(source, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source+`\SKILL.md`, []byte("# exact\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// The gateway plans with extended roots and copies before it asks.
		plan, err := NewAssetQuarantinePlan(`\\?\`+quarantine, []string{`\\?\` + skills}, "skill", name, "claudecode", source)
		if err != nil {
			t.Fatal(err)
		}
		if err := ensureContainedDirectory(filepath.Dir(plan.QuarantinePath), plan.QuarantineRoot); err != nil {
			t.Fatal(err)
		}
		if err := copyAssetPath(plan.SourcePath, plan.QuarantinePath); err != nil {
			t.Fatal(err)
		}
		request := QuarantineRemovalRequest{
			Version: quarantineRemovalVersion, ID: "rec-1007", TargetType: "skill",
			SourcePath: plan.SourcePath, QuarantinePath: plan.QuarantinePath, ContentHash: plan.ContentHash,
		}
		for _, refused := range []string{skills + `\` + name, `\\?\` + skills + `\x\..\` + name} {
			bad := request
			bad.SourcePath = refused
			if _, _, err := VerifyQuarantineRemoval(bad, []string{skills}, quarantine); err == nil {
				t.Fatalf("%q: the guardian accepted %s", name, refused)
			}
		}
		got, gotRoot, err := VerifyQuarantineRemoval(request, []string{skills}, quarantine)
		if err != nil || got != source || gotRoot != skills {
			t.Fatalf("%q: verify = %q, %q, %v; want the exact source under %s", name, got, gotRoot, err, skills)
		}
		if err := removeAssetPath(got, gotRoot); err != nil {
			t.Fatalf("%q: remove: %v", name, err)
		}
		if _, err := os.Lstat(source); !os.IsNotExist(err) {
			t.Fatalf("%q: exact source remains: %v", name, err)
		}
	}
	if _, err := os.Lstat(sibling); err != nil {
		t.Fatalf("the normal sibling changed: %v", err)
	}
}
