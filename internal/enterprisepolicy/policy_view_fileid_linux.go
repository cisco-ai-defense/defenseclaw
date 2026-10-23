// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package enterprisepolicy

import (
	"fmt"
	"os"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func policyViewFilePin(info os.FileInfo, data []byte) (managed.PolicyViewFilePin, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return managed.PolicyViewFilePin{}, fmt.Errorf("policy-view source is not a regular file with stat data")
	}
	pin := managed.PolicyViewFilePin{
		Size: info.Size(), Mode: uint32(info.Mode()), Device: uint64(stat.Dev), Inode: stat.Ino,
		MTime: info.ModTime().UnixNano(), CTime: stat.Ctim.Sec*1e9 + stat.Ctim.Nsec,
	}
	if data != nil {
		pin.SHA256 = sha256Hex(data)
	}
	return pin, nil
}
