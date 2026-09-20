// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package safefile

import (
	"os"

	"golang.org/x/sys/unix"
)

func readStabilitySnapshot(file *os.File) (readStability, error) {
	var status unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &status); err != nil {
		return readStability{}, err
	}
	return readStability{
		size:     status.Size,
		modified: status.Mtim.Sec*1_000_000_000 + status.Mtim.Nsec,
		changed:  status.Ctim.Sec*1_000_000_000 + status.Ctim.Nsec,
	}, nil
}
