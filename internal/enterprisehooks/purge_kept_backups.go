// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// keptManagedBackupsError keeps recovery state whenever a connector teardown
// leaves a backup, or the remaining backups cannot be read.
func keptManagedBackupsError(dataDir string) error {
	backups := filepath.Join(dataDir, "connector_backups")
	targets, err := connector.ManagedFileBackupTargets(dataDir)
	if err != nil {
		return fmt.Errorf("enterprise hooks: kept the per-user state for its backups: a backup in %s cannot be read (%v); fix or remove that backup, then rerun the purge", backups, err)
	}
	if len(targets) == 0 {
		return nil
	}
	return fmt.Errorf("enterprise hooks: kept the per-user state for its backups: %s differs from what DefenseClaw wrote, so DefenseClaw left it and its backup in %s; to keep the file as it is, delete that backup, or put back the file DefenseClaw wrote; then rerun the purge",
		strings.Join(targets, ", "), backups)
}
