// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
)

// applyMigration runs a migration in a storeMigrationTx that carries the
// store's Secure Client flag, so a migration that installs a store-dependent
// schema object (the retention insert trigger) installs the store's form
// from the start (rel-1-0-6:GAP-0267).
func TestApplyMigrationTellsTheMigrationTheStoresSecureClientFlag(t *testing.T) {
	for _, secureClient := range []bool{false, true} {
		var options []StoreOption
		if secureClient {
			options = append(options, WithSecureClientSchema())
		}
		store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"), options...)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Init(); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
		var said, told bool
		probe := migration{description: "test: read the store's form", apply: func(ex dbExecer) error {
			form, ok := ex.(interface{ secureClientMigration() bool })
			said = ok
			if ok {
				told = form.secureClientMigration()
			}
			return nil
		}}
		err = store.applyMigration(len(migrations)+1, probe)
		closeErr := store.Close()
		if err != nil {
			t.Fatal(err)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		if !said || told != secureClient {
			t.Fatalf("secure client store %t: the migration was told %t (executor says %t); want the store's flag", secureClient, told, said)
		}
	}
}
