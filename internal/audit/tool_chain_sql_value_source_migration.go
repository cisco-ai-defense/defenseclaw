// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import "fmt"

// migrateToolChainSQLValueSourceState adds only the value-free source
// descriptor needed to bind a reviewed SQL invocation to its authoritative
// result. The table class is a closed enum and the resource identity is an
// opaque digest; SQL text, result bytes, and extracted values never enter the
// audit database.
func migrateToolChainSQLValueSourceState(ex dbExecer) error {
	for _, column := range []struct {
		name  string
		query string
	}{
		{
			name: "sql_value_source_table_class",
			query: `ALTER TABLE guardrail_chain_pending_actions
				ADD COLUMN sql_value_source_table_class TEXT NOT NULL DEFAULT ''
				CHECK (sql_value_source_table_class IN
					('', 'credentials', 'oauth_tokens', 'employees'))`,
		},
		{
			name: "sql_value_source_resource_digest",
			query: `ALTER TABLE guardrail_chain_pending_actions
				ADD COLUMN sql_value_source_resource_digest TEXT NOT NULL DEFAULT ''
				CHECK ((sql_value_source_resource_digest = '') OR
					(length(sql_value_source_resource_digest) = 64 AND
					sql_value_source_resource_digest NOT GLOB '*[^0-9a-f]*'))`,
		},
	} {
		exists, err := hasColumnDB(
			ex, "guardrail_chain_pending_actions", column.name,
		)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := ex.Exec(column.query); err != nil {
			return fmt.Errorf("add pending SQL value source %s: %w", column.name, err)
		}
	}
	return nil
}
