// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import "testing"

// scripts/keep-pre-1.0-audit-history.py (make all) keys on this schema
// version to tell a 0.x audit history from a 1.x one (GAP-1469).
func TestHistoricalEvidencePurgeIsMigration33(t *testing.T) {
	if _, version := historicalEvidencePurgeMigration(t); version != 33 {
		t.Fatalf("historical evidence purge is migration %d; update PURGE_MIGRATION in scripts/keep-pre-1.0-audit-history.py", version)
	}
}
