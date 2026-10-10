// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

import (
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The Windows form of GAP-1265: a folder the gateway account may not
// traverse answers ERROR_ACCESS_DENIED, which a jsonl destination turns into
// a warning and the audit database keeps as a config error.
func TestObservabilityV8JSONLDestinationBehindDeniedFolderWarnsOnWindows(t *testing.T) {
	dataDir := t.TempDir()
	denied := filepath.Join(dataDir, "rv13")
	original := observabilityV8EvalSymlinks
	observabilityV8EvalSymlinks = func(path string) (string, error) {
		if strings.HasPrefix(strings.ToLower(path), strings.ToLower(denied)) {
			return "", &fs.PathError{Op: "lstat", Path: path, Err: syscall.ERROR_ACCESS_DENIED}
		}
		return original(path)
	}
	t.Cleanup(func() { observabilityV8EvalSymlinks = original })
	assertObservabilityV8DeniedJSONLWarns(t, dataDir, denied)
}
