// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The standalone Linux and macOS guardian records the targets it put back
// as well (GAP-0499); Secure Client macOS does not.
func init() {
	enterpriseHookGuardianRestoresEnabled = enterpriseHooksStandaloneUnixActive
}

// recordEnterpriseHookStandaloneUnixRestores dates the targets the
// standalone Unix pass that started at since put back. That pass lists them
// in hookGuardianRepairsFile, for the lifecycle's repair report, only when
// it repaired one, and names each by account and connector; the pass's rows
// give the account's uid. A pass that repaired nothing still drops the
// entries of targets that left the manifest. It returns the recorder's
// error.
func recordEnterpriseHookStandaloneUnixRestores(stderr io.Writer, dataDir string, since time.Time, run enterpriseHookReconcileRun) error {
	var restored []enterpriseHookGuardianRestore
	if run.Repairs > 0 {
		restored = enterpriseHookStandaloneUnixRepairedTargets(dataDir, since, run.Rows)
	}
	return recordEnterpriseHookGuardianRestores(stderr, dataDir, run.Rows, restored)
}

func enterpriseHookStandaloneUnixRepairedTargets(dataDir string, since time.Time, rows []enterpriseHookReconcileRow) []enterpriseHookGuardianRestore {
	path := filepath.Join(strings.TrimSpace(dataDir), hookGuardianRepairsFile)
	info, err := os.Lstat(path)
	if err != nil {
		return nil
	}
	data, err := readEnterpriseHookBoundedFile(path, info, hookGuardianRestoresMaxBytes, "hook guardian repair record")
	if err != nil {
		return nil
	}
	var record struct {
		UpdatedAt string `json:"updated_at"`
		Repaired  []struct {
			User      string `json:"user"`
			Connector string `json:"connector"`
		} `json:"repaired"`
	}
	if json.Unmarshal(data, &record) != nil {
		return nil
	}
	updated, err := time.Parse(time.RFC3339Nano, record.UpdatedAt)
	if err != nil || updated.Before(since) {
		// A record of an earlier pass: this one could not write it.
		return nil
	}
	var restored []enterpriseHookGuardianRestore
	for _, repair := range record.Repaired {
		for _, row := range rows {
			if row.UID <= 0 || row.User != repair.User || !strings.EqualFold(row.Connector, repair.Connector) {
				continue
			}
			uid := row.UID
			restored = append(restored, enterpriseHookGuardianRestore{
				UID: &uid, User: row.User, Connector: row.Connector, RestoredAt: updated.UTC().Format(time.RFC3339Nano),
			})
			break
		}
	}
	return restored
}
