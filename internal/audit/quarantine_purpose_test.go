// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func TestQuarantinePurposeMigrationContract(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	present, err := hasColumnDB(store.db, "quarantine_records", "purpose")
	if err != nil {
		t.Fatalf("purpose column lookup: %v", err)
	}
	if !present {
		t.Fatal("quarantine_records.purpose was not migrated")
	}

	now := time.Now().UTC()
	insert := func(id, quarantinePath string, purpose *string) error {
		if purpose == nil {
			_, err = store.db.Exec(
				`INSERT INTO quarantine_records (
					id, target_type, target_name, original_path, quarantine_path,
					content_hash, reason, state, ownership_json, created_at, updated_at
				) VALUES (?, 'skill', ?, ?, ?, ?, '', 'active', '{}', ?, ?)`,
				id, id, filepath.Join(t.TempDir(), id), quarantinePath, "sha256-"+id, now, now,
			)
			return err
		}
		_, err = store.db.Exec(
			`INSERT INTO quarantine_records (
				id, target_type, target_name, original_path, quarantine_path,
				content_hash, purpose, reason, state, ownership_json, created_at, updated_at
			) VALUES (?, 'skill', ?, ?, ?, ?, ?, '', 'active', '{}', ?, ?)`,
			id, id, filepath.Join(t.TempDir(), id), quarantinePath, "sha256-"+id, *purpose, now, now,
		)
		return err
	}

	if err := insert("legacy-default", filepath.Join(t.TempDir(), "legacy"), nil); err != nil {
		t.Fatalf("insert default purpose: %v", err)
	}
	var got string
	if err := store.db.QueryRow(
		`SELECT purpose FROM quarantine_records WHERE id = 'legacy-default'`,
	).Scan(&got); err != nil {
		t.Fatalf("read default purpose: %v", err)
	}
	if got != "operator" {
		t.Fatalf("legacy purpose = %q, want operator", got)
	}

	for _, purpose := range []string{"operator", "watcher-enforcement", "runtime-isolation"} {
		purpose := purpose
		if err := insert(purpose, filepath.Join(t.TempDir(), purpose), &purpose); err != nil {
			t.Fatalf("insert canonical purpose %q: %v", purpose, err)
		}
	}

	invalid := "runtime"
	if err := insert("invalid", filepath.Join(t.TempDir(), "invalid"), &invalid); err == nil {
		t.Fatal("non-canonical quarantine purpose was accepted")
	}
}
