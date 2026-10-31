// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// accountAgentProcessMayRun reports whether a running process of the account
// that owns dataDir, other than this one, names agent in its command line
// (Linux /proc). Anything it cannot read counts as a process that may run it.
func accountAgentProcessMayRun(dataDir, agent string) bool {
	info, err := os.Lstat(dataDir)
	if err != nil {
		return true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return true
	}
	agent = strings.ToLower(agent)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		dir := filepath.Join("/proc", entry.Name())
		process, err := os.Lstat(dir)
		if err != nil {
			continue // it ended
		}
		if owner, ok := process.Sys().(*syscall.Stat_t); !ok || owner.Uid != stat.Uid {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return true
		}
		// Any argument that names the agent counts (its launcher, a
		// python -m module, a path in its install): a wider match only
		// keeps a tombstone longer.
		if bytes.Contains(bytes.ToLower(cmdline), []byte(agent)) {
			return true
		}
	}
	return false
}
