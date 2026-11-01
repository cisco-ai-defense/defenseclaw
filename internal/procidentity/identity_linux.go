// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procidentity

import (
	"os"
	"strconv"
	"strings"
)

func of(pid int) (string, bool) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", false
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", false
	}
	// The command name (field 2) is in parentheses and may hold spaces, so
	// the fields are counted from the last ')'; fields[0] is field 3.
	stat := string(data)
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return "", false
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 20 {
		return "", false
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	id := strings.TrimSpace(string(boot))
	if err != nil || id == "" || strings.Trim(id, "0123456789abcdef-") != "" {
		return "", false
	}
	return id + " " + strconv.FormatUint(ticks, 10), true
}
