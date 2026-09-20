// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func newQuarantineProvenanceStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestQuarantineProvenanceCreateIsAtomicAcrossConnectorOwnership(t *testing.T) {
	store := newQuarantineProvenanceStore(t)
	ctx := context.Background()
	root := t.TempDir()
	input := CreateQuarantineRecordInput{
		TargetType: "skill", TargetName: "review-pr",
		OriginalPath:   filepath.Join(root, "skills", "review-pr"),
		QuarantinePath: filepath.Join(root, "quarantine", "skills", "codex", "review-pr"),
		ContentHash:    strings.Repeat("ab", 32), Reason: "watcher enforcement",
		State: QuarantineStatePending, OwnershipJSON: `{"mode":448}`,
		Connectors: []string{"codex", ""},
	}
	record, err := store.CreateQuarantineRecord(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != QuarantineStatePending || record.ContentHash != input.ContentHash ||
		record.OriginalPath != filepath.Clean(input.OriginalPath) ||
		record.QuarantinePath != filepath.Clean(input.QuarantinePath) {
		t.Fatalf("record = %#v", record)
	}
	if len(record.Connectors) != 2 || record.Connectors[0] != "" || record.Connectors[1] != "codex" {
		t.Fatalf("connectors = %#v", record.Connectors)
	}

	conflict := input
	conflict.ContentHash = strings.Repeat("cd", 32)
	conflict.Connectors = []string{"claudecode"}
	if _, err := store.CreateQuarantineRecord(ctx, conflict); err == nil {
		t.Fatal("conflicting quarantine identity was accepted")
	}
	claudeRecords, err := store.ListQuarantineRecordsForConnector(
		ctx, "skill", "review-pr", "claudecode",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(claudeRecords) != 0 {
		t.Fatalf("failed transaction associated connector: %#v", claudeRecords)
	}
}

func TestCompleteQuarantineRestorePreservesInstallAndRuntimeBlocks(t *testing.T) {
	store := newQuarantineProvenanceStore(t)
	ctx := context.Background()
	root := t.TempDir()
	original := filepath.Join(root, "skills", "review-pr")
	quarantine := filepath.Join(root, "quarantine", "skills", "codex", "review-pr")
	if err := store.SetActionField("skill", "review-pr", "install", "block", "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionField("skill", "review-pr", "file", "quarantine", "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionField("skill", "review-pr", "runtime", "disable", "fixture"); err != nil {
		t.Fatal(err)
	}
	record, err := store.CreateQuarantineRecord(ctx, CreateQuarantineRecordInput{
		TargetType: "skill", TargetName: "review-pr",
		OriginalPath: original, QuarantinePath: quarantine,
		ContentHash: strings.Repeat("ab", 32), State: QuarantineStatePending,
		OwnershipJSON: `{"mode":448}`, Connectors: []string{"codex", ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateQuarantineRecordState(
		ctx, record.ID, QuarantineStateRestoring, original,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteQuarantineRestore(ctx, record.ID, original); err != nil {
		t.Fatal(err)
	}

	entry, err := store.GetAction("skill", "review-pr")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil || entry.Actions.Install != "block" ||
		entry.Actions.Runtime != "disable" || entry.Actions.File != "" ||
		entry.SourcePath != filepath.Clean(original) {
		t.Fatalf("restored global action = %#v", entry)
	}
	if got, err := store.GetQuarantineRecord(ctx, record.ID); err != nil || got != nil {
		t.Fatalf("retired quarantine record = %#v err=%v", got, err)
	}
	codexEntry, err := store.GetActionForConnector("skill", "review-pr", "codex")
	if err != nil {
		t.Fatal(err)
	}
	if codexEntry == nil || codexEntry.SourcePath != filepath.Clean(original) || codexEntry.Actions.File != "" {
		t.Fatalf("restored connector action = %#v", codexEntry)
	}
}
