// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package safefile

import "os"

// DefenseClaw's supported native targets have a handle-bound change time.
// Keep other Go targets buildable while still detecting ordinary in-place
// mutations through exact size and modification time.
func readStabilitySnapshot(file *os.File) (readStability, error) {
	info, err := file.Stat()
	if err != nil {
		return readStability{}, err
	}
	return readStability{
		size:     info.Size(),
		modified: info.ModTime().UnixNano(),
	}, nil
}
