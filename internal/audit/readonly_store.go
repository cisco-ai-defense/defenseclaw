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
	"database/sql"
	"fmt"
	"path/filepath"
)

// OpenReadOnlyDB opens an existing audit database read-only and
// query-only for an administrator's review. It never creates the file,
// runs a migration, changes a pragma or file mode, or reclaims ownership,
// so reading the managed gateway's service-owned store cannot make a
// second writer beside the running gateway or leave root-owned files in
// its data directory. The caller validates who may own the path.
func OpenReadOnlyDB(dbPath string) (*sql.DB, error) {
	db, err := openAuditReadOnly(dbPath)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: open %s read-only: %w", filepath.Clean(dbPath), err)
	}
	return db, nil
}

// OpenReadOnlyStore returns a Store over an existing, initialized audit
// database for its query methods (finding states, history). The store is
// opened with OpenReadOnlyDB; its write methods fail on the read-only
// connection.
func OpenReadOnlyStore(dbPath string) (*Store, error) {
	db, err := OpenReadOnlyDB(dbPath)
	if err != nil {
		return nil, err
	}
	var schemaVersion int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&schemaVersion); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: %s is not an initialized audit database: %w", filepath.Clean(dbPath), err)
	}
	if schemaVersion == 0 {
		_ = db.Close()
		return nil, fmt.Errorf("audit: %s has no schema yet", filepath.Clean(dbPath))
	}
	store := &Store{db: db, dbPath: filepath.Clean(dbPath)}
	store.ready.Store(true)
	return store, nil
}
