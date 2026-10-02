// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// serviceLogPath is empty off Windows: systemd and launchd already capture
// the helper's stderr.
func serviceLogPath() string { return "" }

// openHelperLog opens the log for append without following a symlink at the
// leaf.
func openHelperLog(path string) (*os.File, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("sensor helper log path must be clean and absolute")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("sensor helper log has an unsafe file type")
	}
	return file, nil
}
