// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// GuardianOwnedFilesFile records, in the standalone Linux and macOS
// guardian's data directory, the state each target's DefenseClaw-only hook
// files (the hook scripts, the connector-scoped token, the runtime records)
// had when the guardian last verified or repaired that target. Status and
// verify compare the files with it: between two guardian passes a user can
// overwrite one of them, and the guardian's last report alone still read as
// protected (GAP-0044). The guardian writes it (internal/cli) and the Linux
// and macOS lifecycle (internal/enterpriseunix) reads it. It is root-only:
// a fingerprint is a SHA-256 digest, never file content.
const GuardianOwnedFilesFile = "hook_guardian_owned_files.json"

// GuardianOwnedFilesMaxBytes bounds the record.
const GuardianOwnedFilesMaxBytes = 4 << 20

// GuardianOwnedFile is one file and its fingerprint (OwnedFileFingerprint).
type GuardianOwnedFile struct {
	Path        string `json:"path"`
	Fingerprint string `json:"fingerprint"`
}

// GuardianOwnedTarget is one verified target's owned files.
type GuardianOwnedTarget struct {
	User      string              `json:"user"`
	UID       int                 `json:"uid,omitempty"`
	Connector string              `json:"connector"`
	Files     []GuardianOwnedFile `json:"files"`
}

// GuardianOwnedFilesRecord is the version 1 record.
type GuardianOwnedFilesRecord struct {
	Version   int                   `json:"version"`
	UpdatedAt string                `json:"updated_at"`
	Targets   []GuardianOwnedTarget `json:"targets"`
}

// OwnedFileFingerprint names the state of the file at path: "absent", a
// non-regular entry by its type, "unreadable", or (ownedFileStateFingerprint)
// the SHA-256 digest of its content with its permission bits; on Windows its
// size, modification time and attributes, because a read handle there would
// make the agent's own write of its config fail with a sharing violation.
// It never follows a link at the name and never blocks on a FIFO. Two equal fingerprints mean the file holds what it
// held; the guardian's watch loop compares them to tell its own writes from
// a user's, and status to tell a file changed since the guardian's pass.
func OwnedFileFingerprint(path string) string {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "absent"
	}
	if err != nil {
		return "unreadable"
	}
	if !info.Mode().IsRegular() {
		return "irregular:" + info.Mode().Type().String()
	}
	return ownedFileStateFingerprint(path, info)
}

// ChangedFiles returns the target's files whose fingerprint (through
// fingerprint, which maps a recorded path to the file to read) is no longer
// the recorded one.
func (target GuardianOwnedTarget) ChangedFiles(fingerprint func(string) string) []string {
	var changed []string
	for _, file := range target.Files {
		if fingerprint(file.Path) != file.Fingerprint {
			changed = append(changed, file.Path)
		}
	}
	return changed
}

// ReadGuardianOwnedFilesRecord reads and checks the record at path, without
// following a link at its name. A missing record returns an os.ErrNotExist
// error.
func ReadGuardianOwnedFilesRecord(path string) (GuardianOwnedFilesRecord, error) {
	if _, err := os.Lstat(path); err != nil {
		return GuardianOwnedFilesRecord{}, err
	}
	data, err := safefile.ReadRegularFileBounded(path, GuardianOwnedFilesMaxBytes)
	if err != nil {
		return GuardianOwnedFilesRecord{}, err
	}
	var record GuardianOwnedFilesRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return GuardianOwnedFilesRecord{}, fmt.Errorf("invalid hook guardian owned-files record: %w", err)
	}
	if record.Version != 1 {
		return GuardianOwnedFilesRecord{}, fmt.Errorf("invalid hook guardian owned-files record: version %d", record.Version)
	}
	for _, target := range record.Targets {
		if strings.TrimSpace(target.Connector) == "" {
			return GuardianOwnedFilesRecord{}, errors.New("invalid hook guardian owned-files record: a target names no connector")
		}
	}
	return record, nil
}

// MarshalGuardianOwnedFilesRecord encodes record, dropping the last targets
// until it fits GuardianOwnedFilesMaxBytes; it returns how many it dropped.
func MarshalGuardianOwnedFilesRecord(record GuardianOwnedFilesRecord) ([]byte, int, error) {
	record.Version = 1
	dropped := 0
	for {
		data, err := json.Marshal(record)
		if err != nil {
			return nil, dropped, err
		}
		if len(data) <= GuardianOwnedFilesMaxBytes || len(record.Targets) == 0 {
			return data, dropped, nil
		}
		record.Targets = record.Targets[:len(record.Targets)-1]
		dropped++
	}
}
