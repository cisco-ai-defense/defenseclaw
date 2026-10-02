// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The standalone enumerator keeps two small records beside targets.yaml:
// the unprotected-agents record status and verify read, and its enrollment
// group cache. Both carry the manifest's exact protection (SYSTEM and
// Administrators only, protected DACL) in the same protected directory.

// WriteWindowsProtectedRecordAtomic publishes data at path under the
// manifest's AdminFile contract through a protected staging file and an
// atomic replace. An identical record is left untouched (changed=false).
func WriteWindowsProtectedRecordAtomic(path string, data []byte) (bool, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return false, fmt.Errorf("enterprise hooks: protected record path must be absolute: %q", path)
	}
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	if err := windowsTargetsManifestAncestorTrust(dir); err != nil {
		return false, fmt.Errorf("enterprise hooks: validate protected record parent ancestry: %w", err)
	}
	if err := validateWindowsTargetsManifestObject(dir, true); err != nil {
		return false, fmt.Errorf("enterprise hooks: validate protected record parent: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		if err := validateWindowsTargetsManifestObject(path, false); err != nil {
			return false, fmt.Errorf("enterprise hooks: validate existing protected record: %w", err)
		}
		if current, readErr := readWindowsBoundedPlainFile(path, int64(len(data))+1); readErr == nil && bytes.Equal(current, data) {
			return false, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("enterprise hooks: inspect protected record %s: %w", path, err)
	}
	tmp, err := os.CreateTemp(dir, ".defenseclaw-record-*.new")
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: create protected record staging file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := windowsTargetsManifestProtect(tmpPath, false); err != nil {
		return false, fmt.Errorf("enterprise hooks: protect protected record staging file: %w", err)
	}
	tmp, err = os.OpenFile(tmpPath, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return false, err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := validateWindowsTargetsManifestObject(tmpPath, false); err != nil {
		return false, fmt.Errorf("enterprise hooks: validate protected record staging file: %w", err)
	}
	if _, err := os.Lstat(path); err == nil {
		if err := validateWindowsTargetsManifestObject(path, false); err != nil {
			return false, fmt.Errorf("enterprise hooks: validate protected record before replace: %w", err)
		}
	}
	if err := windowsTargetsManifestReplace(tmpPath, path); err != nil {
		return false, fmt.Errorf("enterprise hooks: replace protected record %s: %w", path, err)
	}
	if err := validateWindowsTargetsManifestObject(path, false); err != nil {
		return true, fmt.Errorf("enterprise hooks: validate published protected record %s: %w", path, err)
	}
	return true, nil
}

// readWindowsProtectedRecord reads a record written by
// WriteWindowsProtectedRecordAtomic, refusing one without the exact
// protection. A missing record returns an os.ErrNotExist error.
func readWindowsProtectedRecord(path string, limit int64) ([]byte, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	if err := validateWindowsTargetsManifestObject(path, false); err != nil {
		return nil, err
	}
	return readWindowsBoundedPlainFile(path, limit)
}

// ReadWindowsUnprotectedAgents reads the enumerator's unprotected-agents
// record for manifestPath. A missing record is an empty list.
func ReadWindowsUnprotectedAgents(manifestPath string) ([]UnprotectedAgent, error) {
	data, err := readWindowsProtectedRecord(UnprotectedAgentsPath(manifestPath), UnprotectedAgentsMaxBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseUnprotectedAgents(data)
}

// WriteWindowsUnprotectedAgents publishes the unprotected-agents record for
// manifestPath.
func WriteWindowsUnprotectedAgents(manifestPath string, agents []UnprotectedAgent) (bool, error) {
	data, err := MarshalUnprotectedAgents(agents)
	if err != nil {
		return false, err
	}
	return WriteWindowsProtectedRecordAtomic(UnprotectedAgentsPath(manifestPath), data)
}

func readWindowsBoundedPlainFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("enterprise hooks: %s is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("enterprise hooks: %s exceeds %d bytes", path, limit)
	}
	return data, nil
}
