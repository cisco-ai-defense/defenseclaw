// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package managed

import (
	"os"
	"strings"
)

// InUnmappedRootUserNamespace reports whether this process runs in a user
// namespace that does not map the host's root (uid 0), as a contained
// scanner does: files root owns there read as the overflow owner.
func InUnmappedRootUserNamespace() bool {
	data, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[1] == "0" {
			return false
		}
	}
	return true
}
