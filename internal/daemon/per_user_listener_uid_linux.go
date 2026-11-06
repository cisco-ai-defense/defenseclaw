// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

func gatewayProcessUID(pid int) (int, error) {
	info, err := os.Stat("/proc/" + strconv.Itoa(pid))
	if err != nil {
		return -1, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, fmt.Errorf("process %d has no Unix owner", pid)
	}
	return int(stat.Uid), nil
}
