// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

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
)

// maximumStandaloneTombstone bounds the deployment record the recovery
// watcher reads; the lifecycle writes a few kilobytes.
const maximumStandaloneTombstone = 128 << 10

// standaloneCommittedUninstallUnsettled reports whether a committed
// standalone uninstall still has postcommit work: its recorded purge has not
// removed the tombstone (the tombstone goes with the state root), or the
// install root or the managed-hook teardown journal remains. A settled
// state-keeping uninstall keeps its tombstone for good and needs no replay.
// The lifecycle module decides the same way
// (Test-DefenseClawCommittedUninstallUnsettled).
func standaloneCommittedUninstallUnsettled(layout managed.StandaloneLayout, metadataPath string) (bool, error) {
	purge, err := standaloneTombstonePurgeRequested(metadataPath)
	if err != nil {
		return false, err
	}
	if purge {
		return true, nil
	}
	if strings.TrimSpace(layout.InstallRoot) == "" || strings.TrimSpace(layout.LifecycleDir) == "" {
		return false, errors.New("cannot prove standalone uninstall recovery is settled: the layout names no install root or lifecycle folder")
	}
	for _, path := range []string{
		layout.InstallRoot,
		filepath.Join(layout.LifecycleDir, "managed-hooks-teardown-journal.json"),
	} {
		if _, err := os.Lstat(path); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("cannot prove standalone uninstall recovery is settled: %w", err)
		}
	}
	return false, nil
}

// standaloneTombstonePurgeRequested reads the uninstall mode the tombstone
// recorded at its commit: the purge, and the per-user purge (Setup PURGE=1)
// that is part of it. A tombstone from before 1.0.4 records none and is a
// state-keeping uninstall for recovery; a malformed mode, or a per-user purge
// without its purge, is refused, never guessed. The lifecycle module reads
// the same fields (Get-DefenseClawTombstonePurgeRequested,
// Get-DefenseClawTombstonePurgeUserStateRequested).
func standaloneTombstonePurgeRequested(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("cannot read the recorded uninstall mode: %w", err)
	}
	body, err := io.ReadAll(io.LimitReader(file, maximumStandaloneTombstone+1))
	closeErr := file.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return false, fmt.Errorf("cannot read the recorded uninstall mode: %w", err)
	}
	if len(body) > maximumStandaloneTombstone {
		return false, errors.New("cannot read the recorded uninstall mode: the deployment record is too large")
	}
	var record struct {
		Installed *bool           `json:"installed"`
		Purge     json.RawMessage `json:"uninstall_purge_requested"`
		UserState json.RawMessage `json:"uninstall_purge_user_state_requested"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}), &record); err != nil {
		return false, fmt.Errorf("cannot read the recorded uninstall mode: %w", err)
	}
	if record.Installed == nil || *record.Installed {
		return false, errors.New("cannot read the recorded uninstall mode: the deployment record is not an uninstall tombstone")
	}
	purge, err := standaloneTombstoneMode(record.Purge, "purge")
	if err != nil {
		return false, err
	}
	userState, err := standaloneTombstoneMode(record.UserState, "per-user purge")
	if err != nil {
		return false, err
	}
	if userState && !purge {
		return false, errors.New("uninstall tombstone records a per-user purge without its uninstall purge")
	}
	return purge, nil
}

// standaloneTombstoneMode decodes one recorded uninstall mode field: absent
// is false, anything but a JSON boolean is refused.
func standaloneTombstoneMode(raw json.RawMessage, name string) (bool, error) {
	if raw == nil {
		return false, nil
	}
	var mode bool
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &mode) != nil {
		return false, fmt.Errorf("uninstall tombstone has an invalid recorded %s mode", name)
	}
	return mode, nil
}
