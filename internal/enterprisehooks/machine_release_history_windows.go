// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsMachineReleaseHistoryFile is the administrator-only record, beside
// the deployment record in <StateRoot>\install, of the DefenseClaw releases
// this computer's managed deployment ran. Setup adds the release its prior
// deployment record names at every install, upgrade and repair
// (Update-DefenseClawReleaseHistory), so the first upgrade from 1.0.10 or
// older seeds it with the release it replaces. Only the standalone deployment
// record names its release, so only the standalone profile has the history
// and reads it (WindowsProtectedTargetFromOtherRelease). Only an administrator or
// SYSTEM can write it. A target's hook-contract lock cannot stand in for it:
// the lock is in the account's own DefenseClaw folder, which the account owns
// and can write (GAP-1537, GAP-0644).
const windowsMachineReleaseHistoryFile = "release_history.json"

// windowsMachineReleaseHistoryLimit bounds the read; the record names a few
// releases.
const windowsMachineReleaseHistoryLimit = 64 << 10

var (
	// windowsMachineReleaseHistoryPath resolves the record. Tests replace it.
	windowsMachineReleaseHistoryPath = defaultWindowsMachineReleaseHistoryPath
	// windowsMachineReleaseHistoryTrustCheck refuses a record that anyone
	// but an administrator or SYSTEM could have written. Tests replace it.
	windowsMachineReleaseHistoryTrustCheck = func(path string) error {
		return managed.ValidateTrustedFilePath(path, "machine release history")
	}
)

// defaultWindowsMachineReleaseHistoryPath is <StateRoot>\install\
// release_history.json. A guardian service has its StateRoot pinned in its
// administrator-owned service environment as the authorization folder
// <StateRoot>\hook-guardian-state; any other process reads the profile's
// production StateRoot.
func defaultWindowsMachineReleaseHistoryPath() (string, error) {
	if auth := os.Getenv(managed.HookGuardianAuthorizationDirEnv); auth != "" {
		if auth != strings.TrimSpace(auth) || strings.ContainsAny(auth, "\x00\r\n") ||
			!filepath.IsAbs(auth) || filepath.Clean(auth) != auth ||
			!strings.EqualFold(filepath.Base(auth), "hook-guardian-state") {
			return "", fmt.Errorf("enterprise hooks: %s is not an exact <StateRoot>\\hook-guardian-state folder",
				managed.HookGuardianAuthorizationDirEnv)
		}
		return filepath.Join(filepath.Dir(auth), "install", windowsMachineReleaseHistoryFile), nil
	}
	profile := managed.ProfileSecureClient
	if windowsEnterpriseStandaloneProcess() {
		profile = managed.ProfileStandalone
	}
	roots, err := winpath.TrustedEnterpriseRoots(profile)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(roots.MetadataPath), windowsMachineReleaseHistoryFile), nil
}

// windowsMachineRanRelease reports that the machine release history names
// release. No record, or an empty release, is no; a record an account could
// have written, or one that does not parse, is an error, which every caller
// reads as no.
func windowsMachineRanRelease(release string) (bool, error) {
	want := normalizeWindowsRecordedRelease(release)
	if want == "" {
		return false, nil
	}
	path, err := windowsMachineReleaseHistoryPath()
	if err != nil {
		return false, err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err := windowsMachineReleaseHistoryTrustCheck(path); err != nil {
		return false, err
	}
	file, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: read the machine release history: %w", err)
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, windowsMachineReleaseHistoryLimit+1))
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: read the machine release history: %w", err)
	}
	if len(body) > windowsMachineReleaseHistoryLimit {
		return false, errors.New("enterprise hooks: the machine release history is too large")
	}
	var record struct {
		SchemaVersion int      `json:"schema_version"`
		Releases      []string `json:"releases"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}), &record); err != nil {
		return false, fmt.Errorf("enterprise hooks: parse the machine release history: %w", err)
	}
	if record.SchemaVersion != 1 {
		return false, fmt.Errorf("enterprise hooks: machine release history schema_version %d is not 1", record.SchemaVersion)
	}
	for _, recorded := range record.Releases {
		if normalizeWindowsRecordedRelease(recorded) == want {
			return true, nil
		}
	}
	return false, nil
}

// normalizeWindowsRecordedRelease compares the release a lock records
// (version.Current().BinaryVersion of its writer) with one the deployment
// record names (the payload's product_version): case and a leading v aside,
// they are the same string.
func normalizeWindowsRecordedRelease(release string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(release)), "v")
}
