// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procidentity

import (
	"os"
	"strconv"
	"strings"
)

func ended(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// The state (field 3) follows the command name's last ')'.
	stat := string(data)
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return false
	}
	fields := strings.Fields(stat[end+1:])
	return len(fields) > 0 && (fields[0] == "Z" || fields[0] == "X" || fields[0] == "x")
}
