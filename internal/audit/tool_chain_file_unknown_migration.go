// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import "fmt"

// migrateToolChainFileUnknownState adds the stored copy of
// guardrail.ToolChainMatches.FileUnknownJoinMask to each chain event: the
// detected chains of that event that joined only through the file-unknown
// marker. A replay of the event returns it with the masks it already
// returns. The default 0 is the fail-safe reading: a row written before
// this column existed is resolved, so upgraded state never turns an Agent
// Substrate egress refusal into an alert.
func migrateToolChainFileUnknownState(ex dbExecer) error {
	const column = "file_unknown_chain_mask"
	exists, err := hasColumnDB(ex, "guardrail_chain_events", column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if _, err := ex.Exec(`ALTER TABLE guardrail_chain_events
		ADD COLUMN file_unknown_chain_mask INTEGER NOT NULL DEFAULT 0
		CHECK (file_unknown_chain_mask BETWEEN 0 AND 2147483647)`); err != nil {
		return fmt.Errorf("add chain event file-unknown mask: %w", err)
	}
	return nil
}
