// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"os"
	"syscall"
)

func enterpriseHookOwnedFileChangeTime(info os.FileInfo) [2]int64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return [2]int64{stat.Ctim.Sec, stat.Ctim.Nsec}
	}
	return [2]int64{}
}
