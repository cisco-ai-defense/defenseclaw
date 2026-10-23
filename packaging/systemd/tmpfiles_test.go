// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package systemdunits

import (
	"strings"
	"testing"
)

// The package postinstall calls systemd-tmpfiles --create on a live host.
// The socket directory must be created on that call as it was in 1.0.3.
func TestHookSocketTmpfilesEntryAppliesOnLiveInstall(t *testing.T) {
	data, err := ReadFile(TmpfilesName)
	if err != nil {
		t.Fatal(err)
	}
	const socketDir = "/run/defenseclaw-hook"
	var entries [][]string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == socketDir {
			entries = append(entries, fields)
		}
	}
	if len(entries) != 1 || len(entries[0]) != 6 || strings.Join(entries[0], " ") != "d /run/defenseclaw-hook 0755 defenseclaw defenseclaw -" {
		t.Fatalf("live tmpfiles must create the hook socket directory once: %v", entries)
	}
}
