// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"
	"time"
)

func newRuntimeAssetStateTestStore(t *testing.T) *Store {
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

func TestRuntimeAssetStateMigrationIsAppendOnly(t *testing.T) {
	if got := migrations[len(migrations)-1].description; got !=
		"runtime assets: add durable connector session provenance state" {
		t.Fatalf("last migration = %q, runtime asset migration must stay append-only", got)
	}
	if ownership, ok := retentionAuditMigrationCatalog["runtime_asset_state"]; !ok || ownership != retentionOwnedProtected {
		t.Fatalf("runtime_asset_state retention ownership = %v, present=%v", ownership, ok)
	}
	store := newRuntimeAssetStateTestStore(t)
	version, err := store.SchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Fatalf("schema version = %d, want %d", version, len(migrations))
	}
	var table string
	if err := store.db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'runtime_asset_state'`,
	).Scan(&table); err != nil {
		t.Fatalf("runtime_asset_state migration missing: %v", err)
	}
}

func TestRuntimeAssetStateUpsertAndConnectorSessionScope(t *testing.T) {
	store := newRuntimeAssetStateTestStore(t)
	ctx := context.Background()
	first := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	second := first.Add(time.Minute)
	initial := RuntimeAssetState{
		Connector: "codex", SessionID: "fresh-session", TargetType: "skill",
		TargetName: "review-pr", SourcePath: `D:\fixture\skills\review-pr`,
		RuntimeSurface: "prompt_selection", HookEvent: "UserPromptSubmit",
		Provenance: "codex_prompt_selection", State: RuntimeAssetSelected,
		FirstObserved: first, LastObserved: first,
	}
	if err := store.RecordRuntimeAssetState(ctx, initial); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordRuntimeAssetState(ctx, RuntimeAssetState{
		Connector: "codex", SessionID: "fresh-session", TargetType: "skill",
		TargetName: "review-pr", RuntimeSurface: "prompt_selection",
		HookEvent: "UserPromptSubmit", Provenance: "codex_prompt_selection",
		State: RuntimeAssetBlocked, FirstObserved: first, LastObserved: second,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetRuntimeAssetState(
		ctx, "codex", "fresh-session", "skill", "review-pr",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.State != RuntimeAssetBlocked {
		t.Fatalf("state = %#v, want blocked", got)
	}
	if got.SourcePath != initial.SourcePath {
		t.Fatalf("source path = %q, want preserved %q", got.SourcePath, initial.SourcePath)
	}
	if !got.FirstObserved.Equal(first) || !got.LastObserved.Equal(second) {
		t.Fatalf("observation window = %s..%s", got.FirstObserved, got.LastObserved)
	}

	if err := store.RecordRuntimeAssetState(ctx, RuntimeAssetState{
		Connector: "claudecode", SessionID: "fresh-session", TargetType: "skill",
		TargetName: "review-pr", RuntimeSurface: "prompt_expansion",
		HookEvent: "UserPromptExpansion", Provenance: "claudecode_prompt_expansion",
		State: RuntimeAssetSelected, FirstObserved: first, LastObserved: second,
	}); err != nil {
		t.Fatal(err)
	}
	states, err := store.ListRuntimeAssetStatesForSession(
		ctx, "codex", "fresh-session",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Connector != "codex" {
		t.Fatalf("connector-scoped states = %#v", states)
	}
}

func TestRuntimeAssetLoadedStateIsAvailableFor071(t *testing.T) {
	store := newRuntimeAssetStateTestStore(t)
	err := store.RecordRuntimeAssetState(context.Background(), RuntimeAssetState{
		Connector: "codex", SessionID: "session-071", TargetType: "skill",
		TargetName: "review-pr", SourcePath: `D:\fixture\skills\review-pr`,
		RuntimeSurface: "native_load", HookEvent: "SkillLoaded",
		Provenance: "connector_load_attestation", State: RuntimeAssetLoaded,
	})
	if err != nil {
		t.Fatalf("071 load-state handoff rejected: %v", err)
	}
}
