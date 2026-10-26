// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// nativeOTLPTakeBackMarkerOwnerTrusted refuses a take-back-pending marker
// that another account owns (GAP-2021): its owner must be the owner of the
// data directory it sits in, root, or this process's effective user.
func nativeOTLPTakeBackMarkerOwnerTrusted(path string, info os.FileInfo) error {
	dirInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	fileStat, okFile := info.Sys().(*syscall.Stat_t)
	dirStat, okDir := dirInfo.Sys().(*syscall.Stat_t)
	if !okFile || !okDir {
		return fmt.Errorf("take-back marker %s: owner unavailable", path)
	}
	if !nativeOTLPTakeBackOwnerUIDTrusted(fileStat.Uid, dirStat.Uid, uint32(os.Geteuid())) {
		return fmt.Errorf("take-back marker %s: owner uid %d is not the data directory's owner", path, fileStat.Uid)
	}
	return nil
}

func nativeOTLPTakeBackOwnerUIDTrusted(owner, dirOwner, euid uint32) bool {
	return owner == dirOwner || owner == 0 || owner == euid
}
