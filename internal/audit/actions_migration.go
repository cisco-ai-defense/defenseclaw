// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// AutomaticInstallBlockReasonPrefixes start the reason of an install block a
// scan verdict wrote (the gateway watcher, and the CLI scan and install
// paths). Such a row is enforcement journal, not operator intent.
var AutomaticInstallBlockReasonPrefixes = []string{"auto-block:", "post-scan:", "post-install scan:", "scan:"}

// IsAutomaticInstallBlock reports whether an install block reason is a scan
// verdict's rather than an operator's.
func IsAutomaticInstallBlock(reason string) bool {
	reason = strings.TrimSpace(reason)
	for _, prefix := range AutomaticInstallBlockReasonPrefixes {
		if strings.HasPrefix(reason, prefix) {
			return true
		}
	}
	return false
}

// OperatorAdmissionRows returns the actions rows that carry operator
// block/allow intent: install=allow, or install=block with a reason that is
// not a scan verdict's. Since config_version 9 that intent lives in
// config.yaml asset_policy, and these rows are the migration input (OSS
// only). Everything else in the table is the enforcement journal.
func (s *Store) OperatorAdmissionRows() ([]ActionEntry, error) {
	rows, err := s.queryActions(
		`SELECT id, target_type, target_name, source_path, actions_json, reason, updated_at, connector
		 FROM actions WHERE json_extract(actions_json, '$.install') IN ('block', 'allow')
		 ORDER BY target_type, target_name, connector`)
	if err != nil {
		return nil, err
	}
	out := rows[:0]
	for _, row := range rows {
		if row.Actions.Install == "block" && IsAutomaticInstallBlock(row.Reason) {
			continue
		}
		out = append(out, row)
	}
	return out, nil
}

// ClearInstallActions removes the install field from the rows with ids, in
// one transaction, deleting rows left with no action. The migration calls it
// only after the config that took over the rows is committed, so an
// operator row is moved, never copied twice.
func (s *Store) ClearInstallActions(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: begin clearing install actions: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	now := time.Now().UTC()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx,
			`UPDATE actions SET actions_json = json_remove(actions_json, '$.install'), updated_at = ? WHERE id = ?`,
			now, id); err != nil {
			return fmt.Errorf("audit: clear install action %s: %w", id, err)
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM actions WHERE id = ? AND actions_json IN ('{}', 'null', '')`, id); err != nil {
			return fmt.Errorf("audit: drop empty action %s: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit clearing install actions: %w", err)
	}
	return nil
}
