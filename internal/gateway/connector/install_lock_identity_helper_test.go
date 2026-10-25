// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// installLockIdentityOf is the proc-start record install.sh writes on Linux
// for process pid ("<boot_id> <starttime>", hookexec processIdentityOf), and
// the same record with another start (a reused pid); it skips off Linux.
func installLockIdentityOf(t *testing.T, pid int) (identity, reused string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the proc-start record is written on Linux")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	text := string(stat)
	fields := strings.Fields(text[strings.LastIndexByte(text, ')')+1:])
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(string(boot))
	return id + " " + strconv.FormatUint(ticks, 10), id + " " + strconv.FormatUint(ticks+1, 10)
}
