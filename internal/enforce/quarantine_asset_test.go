// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

func TestAssetRestoreRejectsRelativePathsBeforeFilesystemMutation(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	fixtureName := filepath.Base("quarantine_asset_test.go")
	fixturePath := filepath.Join(workingDirectory, fixtureName)
	before, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	restorePath := filepath.Join(
		workingDirectory, ".win-aud-071-relative-restore", fixtureName,
	)
	base := AssetRestorePlan{
		RecordID: "record", TargetType: "skill", TargetName: fixtureName,
		QuarantineRoot: workingDirectory, QuarantinePath: fixturePath,
		RestorePath: restorePath, AllowedRoots: []string{workingDirectory},
		ContentHash: strings.Repeat("0", 64),
	}
	tests := []struct {
		name   string
		mutate func(*AssetRestorePlan)
	}{
		{"quarantine root", func(plan *AssetRestorePlan) {
			plan.QuarantineRoot = "."
		}},
		{"quarantine path", func(plan *AssetRestorePlan) {
			plan.QuarantinePath = fixtureName
		}},
		{"restore path", func(plan *AssetRestorePlan) {
			plan.RestorePath = filepath.Join(".win-aud-071-relative-restore", fixtureName)
		}},
		{"allowed root", func(plan *AssetRestorePlan) {
			plan.AllowedRoots = []string{"."}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := base
			test.mutate(&plan)
			err := ExecuteAssetRestore(plan)
			if err == nil || !strings.Contains(err.Error(), "absolute") {
				t.Fatalf("relative restore plan error = %v, want absolute-path rejection", err)
			}
		})
	}
	after, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("relative restore plan mutated quarantine fixture")
	}
	if _, err := os.Lstat(restorePath); !os.IsNotExist(err) {
		t.Fatalf("relative restore plan created destination: %v", err)
	}
}

// GAP-0202: a source the process may only read (a managed Windows gateway in
// an enrolled user's folder) is removed by the hook guardian on request, and
// the guardian refuses a source outside the watched folders.
func TestQuarantineSourceTheProcessMayNotDeleteIsRemovedByTheGuardian(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a folder the test process may not delete in")
	}
	root := t.TempDir()
	skillsRoot := filepath.Join(root, "user", "skills")
	quarantineRoot := filepath.Join(root, "quarantine")
	source := filepath.Join(skillsRoot, "bad-skill")
	if err := os.MkdirAll(skillsRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("marker\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	plan, err := NewAssetQuarantinePlan(quarantineRoot, []string{skillsRoot}, "skill", "bad-skill", "claudecode", source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(skillsRoot, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(skillsRoot, 0o755) })
	channel := QuarantineRemovalChannelFor(filepath.Join(root, "data"), filepath.Join(root, "guardian"))
	SetQuarantineSourceRemover(channel.Remover(10 * time.Second))
	t.Cleanup(func() { SetQuarantineSourceRemover(nil) })
	refused := make(chan error, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			channel.ServeOnce(func(request QuarantineRemovalRequest) error {
				outside := request
				outside.SourcePath = filepath.Join(root, "elsewhere", "bad-skill")
				_, _, err := VerifyQuarantineRemoval(outside, []string{skillsRoot}, quarantineRoot)
				select {
				case refused <- err:
				default:
				}
				found, _, err := VerifyQuarantineRemoval(request, []string{skillsRoot}, quarantineRoot)
				if err != nil {
					return err
				}
				_ = os.Chmod(skillsRoot, 0o755)
				return os.Remove(found)
			})
		}
	}()

	if err := ExecuteAssetQuarantine(plan, "rec-gap0202"); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatalf("source still present: %v", err)
	}
	if err := requireAssetHash(plan.QuarantinePath, plan.ContentHash); err != nil {
		t.Fatal(err)
	}
	if err := <-refused; err == nil {
		t.Fatal("the guardian accepted a source outside the watched folders")
	}
}

// GAP-0414: the guardian could not remove the source of a signed-out
// Microsoft Entra ID user (no S4U logon); it answered with an error and
// forgot the request, so the skill stayed in the profile. A deferred removal
// is kept and retried until it succeeds.
func TestDeferredQuarantineRemovalIsRetriedUntilItSucceeds(t *testing.T) {
	root := t.TempDir()
	channel := QuarantineRemovalChannelFor(filepath.Join(root, "data"), filepath.Join(root, "guardian"))
	request := QuarantineRemovalRequest{
		Version: quarantineRemovalVersion, ID: "rec-gap0414", Nonce: "n1", TargetType: "skill",
		SourcePath: filepath.Join(root, "skills", "bad"), QuarantinePath: filepath.Join(root, "quarantine", "bad"),
		ContentHash: strings.Repeat("a", 64),
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(channel.RequestDir, request.ID+".json")
	if err := os.MkdirAll(channel.RequestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(requestPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	channel.ServeOnce(func(QuarantineRemovalRequest) error {
		return fmt.Errorf("%w: the owner is signed out", ErrQuarantineRemovalDeferred)
	})
	var result QuarantineRemovalResult
	if err := readQuarantineRemovalFile(filepath.Join(channel.ResultDir, request.ID+".json"), &result); err != nil || result.OK ||
		!strings.Contains(result.Error, "deferred") {
		t.Fatalf("deferred answer = %+v, %v", result, err)
	}
	if err := os.Remove(requestPath); err != nil { // the gateway collected its answer
		t.Fatal(err)
	}
	signedIn, retries := false, 0
	retry := func(got QuarantineRemovalRequest) error {
		retries++
		if got.ID != request.ID || got.SourcePath != request.SourcePath {
			t.Fatalf("retried %+v", got)
		}
		if !signedIn {
			return ErrQuarantineRemovalDeferred
		}
		return nil
	}
	channel.ServeDeferred(retry)
	signedIn = true
	channel.ServeDeferred(retry)
	channel.ServeDeferred(retry)
	if retries != 2 {
		t.Fatalf("deferred removal ran %d times, want 2 (kept while signed out, dropped once removed)", retries)
	}
}
