// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package daemon

import "os"

// removePIDFileIf preserves the historical Unix cleanup behavior. Windows
// needs a handle-bound implementation because pathname replacement and delete
// are separate operations there; see pidfile_windows.go.
func removePIDFileIf(path string, matches func([]byte) bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !matches(data) {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
