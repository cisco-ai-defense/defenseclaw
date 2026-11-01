// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import "database/sql"

// openSQLite opens an audit connection with the standalone pragmas, for tests
// only: a production open picks its pragmas with auditPragmasFor, so a Secure
// Client store keeps main's map (review round 2 of rel-1-0-6 GAP-0327).
func openSQLite(dbPath string) (*sql.DB, error) {
	return openSQLiteWithPragmas(dbPath, auditPragmas)
}
