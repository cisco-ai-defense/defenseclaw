// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import "fmt"

const historicalEvidencePurgeMigrationDescription = "privacy: purge pre-cutover audit evidence"

// purgeHistoricalEvidence removes every finding and audit-event row that was
// present when this migration began. Store.applyMigration wraps this helper and
// the schema-version insert in one transaction, so an upgrade exposes either
// the complete destructive cutoff or the complete pre-upgrade history.
//
// These are active tables, not retired schema: current writers and queries keep
// using them after the one-time row purge. Validate the mandatory affected
// schema before deleting anything, then remove scan children before their
// parent so SQLite foreign keys and the v8 scan integrity trigger remain
// enforced. The migration-1 findings table may be absent on a partial
// pre-cutover database; absence is treated only as already-empty cleanup, not
// as a compatibility promise. A present table is purged.
func purgeHistoricalEvidence(ex dbExecer) error {
	if ex == nil {
		return fmt.Errorf("audit: historical evidence purge has no database")
	}

	findingsPresent, err := tableExists(ex, "findings")
	if err != nil {
		return fmt.Errorf("audit: verify historical evidence table findings: %w", err)
	}
	for _, table := range [...]string{"scan_findings", "scan_results", "audit_events"} {
		present, err := tableExists(ex, table)
		if err != nil {
			return fmt.Errorf("audit: verify historical evidence table %s: %w", table, err)
		}
		if !present {
			return fmt.Errorf("audit: mandatory historical evidence table %s is missing", table)
		}
	}

	statements := []string{"DELETE FROM scan_findings", "DELETE FROM scan_results", "DELETE FROM audit_events"}
	if findingsPresent {
		statements = append([]string{"DELETE FROM findings"}, statements...)
	}
	for _, statement := range statements {
		if _, err := ex.Exec(statement); err != nil {
			return fmt.Errorf("audit: purge pre-cutover evidence with %q: %w", statement, err)
		}
	}
	return nil
}
