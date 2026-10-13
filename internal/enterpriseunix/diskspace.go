// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"
	"syscall"
)

// codeDiskSpaceLow names a nearly full filesystem under the gateway's audit
// database or logs.
const codeDiskSpaceLow = "disk_space_low"

// diskSpaceLowBytes and diskSpaceLowPercent are the warning thresholds: less
// than 256 MiB, or less than 2% of the filesystem, available.
const (
	diskSpaceLowBytes   = 256 << 20
	diskSpaceLowPercent = 2
)

// diskSpace reports the bytes available to unprivileged writers, the size
// and the device of the filesystem holding path.
func diskSpace(path string) (avail, total, device uint64, err error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return 0, 0, 0, err
	}
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, 0, 0, err
	}
	block := uint64(fs.Bsize)
	return uint64(fs.Bavail) * block, uint64(fs.Blocks) * block, uint64(st.Dev), nil
}

// warnLowDiskSpace warns when the filesystem holding the audit database or
// the logs is nearly full. Enforcement holds on a full disk, but nothing an
// administrator reads said so before the audit trail stopped (GAP-0514).
func (l *lifecycle) warnLowDiskSpace() {
	env := l.env
	seen := map[uint64]bool{}
	for _, dir := range []string{env.Layout.DataDir, env.Layout.LogDir} {
		avail, total, device, err := env.DiskSpace(env.P(dir))
		if err != nil || total == 0 || seen[device] {
			continue
		}
		seen[device] = true
		if avail >= diskSpaceLowBytes && avail*100 >= total*diskSpaceLowPercent {
			continue
		}
		l.result.AddWarning(codeDiskSpaceLow, fmt.Sprintf("the filesystem holding %s has %.1f MiB free (%.1f%%): enforcement continues, but the audit database and logs stop recording when it fills; free space on it",
			dir, float64(avail)/(1<<20), float64(avail)*100/float64(total)))
	}
}
