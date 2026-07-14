// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func TestStoreRetainsOpenedPathIdentityAcrossWorkingDirectoryChange(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	root := t.TempDir()
	openedFrom := filepath.Join(root, "opened-from")
	initializedFrom := filepath.Join(root, "initialized-from")
	for _, directory := range []string{openedFrom, initializedFrom} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chdir(openedFrom); err != nil {
		t.Fatal(err)
	}
	openedIdentity, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join("nested", "..", "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	want := filepath.Join(openedIdentity, "audit.db")
	if store.DatabasePath() != want {
		t.Fatalf("opened database identity = %q, want %q", store.DatabasePath(), want)
	}
	if err := os.Chdir(initializedFrom); err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("initialize after cwd change: %v", err)
	}
	if store.DatabasePath() != want || !store.Ready() {
		t.Fatalf("ready store identity = %q ready=%t", store.DatabasePath(), store.Ready())
	}
	if _, err := os.Stat(filepath.Join(initializedFrom, "audit.db")); !os.IsNotExist(err) {
		t.Fatalf("readiness revalidated or created a different cwd-relative database: %v", err)
	}
}

func TestStorePublishesReadinessOnlyAfterPragmasAndDurableWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.DatabasePath() != path {
		t.Fatalf("database path identity = %q, want constructor identity", store.DatabasePath())
	}
	if store.Ready() {
		t.Fatal("new store reported ready before Init")
	}
	if _, err := NewEventHistoryWriter(
		store, nil, nil,
		testLocalProfileResolver{profile: observabilityredaction.ProfileNone},
	); err == nil {
		t.Fatal("event-history writer captured a pre-Init store")
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if !store.Ready() {
		t.Fatal("initialized store did not report ready")
	}
	if err := store.verifyMandatoryPragmas(context.Background()); err != nil {
		t.Fatal(err)
	}
	var generation int64
	if err := store.db.QueryRow(`SELECT verification_generation
		FROM observability_store_readiness WHERE id=1`).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if generation != 1 {
		t.Fatalf("readiness generation = %d, want 1", generation)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if store.Ready() {
		t.Fatal("closed store remained ready")
	}
	if store.DatabasePath() != path {
		t.Fatal("immutable database path identity changed after close")
	}
	if err := store.Init(); err == nil {
		t.Fatal("closed store accepted Init")
	}
}

func TestStoreInitIsConcurrentAndIdempotent(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	const workers = 12
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errs <- store.Init()
		}()
	}
	close(start)
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var generation int64
	if err := store.db.QueryRow(`SELECT verification_generation
		FROM observability_store_readiness WHERE id=1`).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if generation != 1 {
		t.Fatalf("concurrent Init readiness writes = %d, want 1", generation)
	}
}

func TestStoreInitRejectsMissingProtectedCorrectnessTable(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "missing-protected.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.db.Exec(`CREATE TABLE schema_version (
		version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for index, migration := range migrations {
		if err := store.applyMigration(index+1, migration); err != nil {
			t.Fatalf("migration %d: %v", index+1, err)
		}
	}
	if _, err := store.db.Exec(`DROP TABLE alert_acknowledgement_health`); err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err == nil {
		t.Fatal("store with missing protected correctness table reported ready")
	}
	if store.Ready() {
		t.Fatal("failed protected-table verification published readiness")
	}
}

func TestStoreInitRejectsMissingCorrelationIdentityClaimsTable(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "missing-correlation-claims.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.db.Exec(`CREATE TABLE schema_version (
		version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for index, migration := range migrations {
		if err := store.applyMigration(index+1, migration); err != nil {
			t.Fatalf("migration %d: %v", index+1, err)
		}
	}
	if _, err := store.db.Exec(`DROP TABLE correlation_identity_claims`); err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err == nil {
		t.Fatal("store with missing correlation identity claims table reported ready")
	}
	if store.Ready() {
		t.Fatal("failed correlation-table verification published readiness")
	}
}

type mutableLocalProfileResolver struct {
	profiles map[observability.Bucket]observabilityredaction.Profile
	engine   *observabilityredaction.Engine
}

func (resolver *mutableLocalProfileResolver) eventHistoryProjectionBinding() localProjectionBindingSnapshot {
	return localProjectionBindingSnapshot{
		graphDigest: testEventHistoryGraphDigest,
		profiles:    cloneLocalProjectionProfiles(resolver.profiles),
		engine:      resolver.engine,
	}
}

func TestEventHistoryWriterSnapshotsCompleteLocalProfileBinding(t *testing.T) {
	store := newV8HistoryStore(t)
	none, _ := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileNone)
	strict, _ := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileStrict)
	resolver := &mutableLocalProfileResolver{
		profiles: make(map[observability.Bucket]observabilityredaction.Profile),
		engine:   testEventHistoryProjectionEngine,
	}
	for _, bucket := range observability.Buckets() {
		resolver.profiles[bucket] = none
	}
	writer, err := NewEventHistoryWriter(store, nil, nil, resolver)
	if err != nil {
		t.Fatal(err)
	}
	resolver.profiles[observability.BucketSecurityFinding] = strict

	record := newV8HistoryRecord(t, "profile-snapshot", "binding remains immutable")
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := writer.Append(record, projection); err != nil {
		t.Fatalf("resolver mutation changed writer binding: %v", err)
	}
}

func TestEventHistoryWriterRejectsIncompleteProfileBinding(t *testing.T) {
	store := newV8HistoryStore(t)
	none, _ := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileNone)
	resolver := &mutableLocalProfileResolver{
		profiles: map[observability.Bucket]observabilityredaction.Profile{
			observability.BucketSecurityFinding: none,
		},
		engine: testEventHistoryProjectionEngine,
	}
	if _, err := NewEventHistoryWriter(store, nil, nil, resolver); err == nil {
		t.Fatal("incomplete local profile binding was accepted")
	}
}
