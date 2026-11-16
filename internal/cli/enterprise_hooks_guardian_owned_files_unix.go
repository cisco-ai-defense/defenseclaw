// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// writeEnterpriseHookGuardianOwnedFiles records, for every target this
// standalone Linux or macOS pass verified or repaired, the fingerprints of
// its DefenseClaw-only hook files as the pass left them
// (enterprisehooks.GuardianOwnedFilesFile). Status and verify compare the
// files with it, so a file overwritten after the pass is reported until the
// next pass puts it back (GAP-0044). A file the pass accepted as absent is
// optional and not recorded. owned maps a row index to that target's
// exclusive-writer files.
func writeEnterpriseHookGuardianOwnedFiles(stderr io.Writer, dataDir string, rows []enterpriseHookReconcileRow, uids map[int]int, owned map[int][]string) error {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil
	}
	indexes := make([]int, 0, len(owned))
	for index := range owned {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	record := enterprisehooks.GuardianOwnedFilesRecord{Version: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	for _, index := range indexes {
		if index < 0 || index >= len(rows) || !rows[index].OK || rows[index].Pending {
			continue
		}
		row := rows[index]
		target := enterprisehooks.GuardianOwnedTarget{User: row.User, UID: uids[index], Connector: strings.ToLower(strings.TrimSpace(row.Connector))}
		for _, path := range owned[index] {
			fingerprint := enterpriseHookOwnedFileFingerprint(path)
			if fingerprint == "absent" {
				continue
			}
			target.Files = append(target.Files, enterprisehooks.GuardianOwnedFile{Path: path, Fingerprint: fingerprint})
		}
		record.Targets = append(record.Targets, target)
	}
	data, dropped, err := enterprisehooks.MarshalGuardianOwnedFilesRecord(record)
	if err != nil {
		return err
	}
	path := filepath.Join(dataDir, enterprisehooks.GuardianOwnedFilesFile)
	if dropped > 0 {
		fmt.Fprintf(stderr, "[hook-guardian] warn: the record of verified hook files in %s would pass %d bytes; left out its %d last targets\n", path, enterprisehooks.GuardianOwnedFilesMaxBytes, dropped)
	}
	return writeEnterpriseHookProtectedFile(path, data)
}
