// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"os"
)

// PendingMigrations reports how many schema migrations the audit store at
// dbPath still has to apply, read-only. A missing file has none: the gateway
// creates a new store at the current schema. The gateway launcher uses it to
// apply a long one-time upgrade (the pre-1.0 history purge on a 2 GB 0.x
// audit.db) before its readiness clock starts (GAP-1909).
func PendingMigrations(dbPath string) (int, error) {
	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	} else if err != nil {
		return 0, fmt.Errorf("audit: %w", err)
	}
	db, err := OpenReadOnlyDB(dbPath)
	if err != nil {
		return 0, err
	}
	defer db.Close() //nolint:errcheck -- read-only handle.
	present, err := tableExists(db, "schema_version")
	if err != nil {
		return 0, err
	}
	if !present {
		return len(migrations), nil
	}
	current := 0
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&current); err != nil {
		return 0, fmt.Errorf("audit: read schema version: %w", err)
	}
	if current >= len(migrations) {
		return 0, nil
	}
	return len(migrations) - current, nil
}
