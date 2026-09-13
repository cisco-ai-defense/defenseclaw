// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import "fmt"

// migrateToolChainReturnedCredentialSourceState adds only the value-free,
// closed source enum needed to bind one reviewed acquisition or exact-read
// invocation to its authoritative result. Credential bytes, material classes,
// excerpts, hashes, paths, and lengths never enter the audit database.
func migrateToolChainReturnedCredentialSourceState(ex dbExecer) error {
	const column = "returned_credential_source"
	exists, err := hasColumnDB(ex, "guardrail_chain_pending_actions", column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if _, err := ex.Exec(`ALTER TABLE guardrail_chain_pending_actions
		ADD COLUMN returned_credential_source INTEGER NOT NULL DEFAULT 0
		CHECK (returned_credential_source IN (0, 1, 2, 3, 4))`); err != nil {
		return fmt.Errorf("add pending returned credential source: %w", err)
	}
	return nil
}
