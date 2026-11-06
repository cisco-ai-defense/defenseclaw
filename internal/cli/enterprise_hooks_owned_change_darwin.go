// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"os"
	"syscall"
)

func enterpriseHookOwnedFileChangeTime(info os.FileInfo) [2]int64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return [2]int64{stat.Ctimespec.Sec, stat.Ctimespec.Nsec}
	}
	return [2]int64{}
}
