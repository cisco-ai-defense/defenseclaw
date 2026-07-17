// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAssetQuarantineAndRestorePreserveHashAndOwnership(t *testing.T) {
	root := t.TempDir()
	skillsRoot := filepath.Join(root, "skills")
	quarantineRoot := filepath.Join(root, "quarantine")
	source := filepath.Join(skillsRoot, "review-pr")
	if err := os.MkdirAll(filepath.Join(source, "nested"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "SKILL.md"), []byte("review safely\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "rules.txt"), []byte("rule\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, err := NewAssetQuarantinePlan(
		quarantineRoot, []string{skillsRoot}, "skill", "review-pr", "codex", source,
	)
	if err != nil {
		t.Fatal(err)
	}
	if plan.OwnershipJSON == "" || plan.OwnershipJSON == "{}" {
		t.Fatalf("ownership marker = %q", plan.OwnershipJSON)
	}
	if want := filepath.Join(quarantineRoot, "skills", "codex", "review-pr"); plan.QuarantinePath != want {
		t.Fatalf("quarantine path = %q, want %q", plan.QuarantinePath, want)
	}
	if err := ExecuteAssetQuarantine(plan, "journal-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatalf("source still exists after quarantine: %v", err)
	}
	if matches, err := AssetContentHashMatches(plan.QuarantinePath, plan.ContentHash); err != nil || !matches {
		t.Fatalf("quarantine hash match=%t err=%v", matches, err)
	}

	if err := ExecuteAssetRestore(AssetRestorePlan{
		RecordID: "journal-1", TargetType: "skill", TargetName: "review-pr",
		QuarantineRoot: quarantineRoot, QuarantinePath: plan.QuarantinePath,
		RestorePath: source, AllowedRoots: []string{skillsRoot}, ContentHash: plan.ContentHash,
	}); err != nil {
		t.Fatal(err)
	}
	if matches, err := AssetContentHashMatches(source, plan.ContentHash); err != nil || !matches {
		t.Fatalf("restore hash match=%t err=%v", matches, err)
	}
	if _, err := os.Lstat(plan.QuarantinePath); !os.IsNotExist(err) {
		t.Fatalf("quarantine remains after restore: %v", err)
	}
}

func TestAssetRestoreCompletesCrashWithBothVerifiedCopies(t *testing.T) {
	root := t.TempDir()
	skillsRoot := filepath.Join(root, "skills")
	quarantineRoot := filepath.Join(root, "quarantine")
	source := filepath.Join(skillsRoot, "review-pr")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "SKILL.md"), []byte("content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := NewAssetQuarantinePlan(
		quarantineRoot, []string{skillsRoot}, "skill", "review-pr", "", source,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := ExecuteAssetQuarantine(plan, "journal-2"); err != nil {
		t.Fatal(err)
	}
	if err := copyAssetPath(plan.QuarantinePath, source); err != nil {
		t.Fatal(err)
	}
	if err := ExecuteAssetRestore(AssetRestorePlan{
		RecordID: "journal-2", TargetType: "skill", TargetName: "review-pr",
		QuarantineRoot: quarantineRoot, QuarantinePath: plan.QuarantinePath,
		RestorePath: source, AllowedRoots: []string{skillsRoot}, ContentHash: plan.ContentHash,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(plan.QuarantinePath); !os.IsNotExist(err) {
		t.Fatalf("crash recovery retained quarantine: %v", err)
	}
}

func TestAssetQuarantineRejectsSourceOutsideConfiguredRoots(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside", "review-pr")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAssetQuarantinePlan(
		filepath.Join(root, "quarantine"), []string{filepath.Join(root, "skills")},
		"skill", "review-pr", "codex", outside,
	); err == nil {
		t.Fatal("outside source was accepted")
	}
}

func TestAssetQuarantineRejectsEmptyRootAndRelativePlan(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := pathWithinRoots(
		filepath.Join(workingDirectory, "asset"), []string{""}, false,
	); err == nil {
		t.Fatal("empty source root was accepted")
	}

	err = ExecuteAssetQuarantine(AssetQuarantinePlan{
		TargetType: "skill", TargetName: "asset",
		SourcePath: "skills/asset", SourceRoot: "skills",
		QuarantinePath: "quarantine/skills/asset", QuarantineRoot: "quarantine",
		ContentHash: strings.Repeat("0", 64),
	}, "record")
	if err == nil {
		t.Fatal("relative quarantine plan was accepted")
	}
}
