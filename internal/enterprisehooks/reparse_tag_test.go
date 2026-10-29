// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "testing"

func TestHarmlessWindowsReparseTag(t *testing.T) {
	for tag, want := range map[uint32]bool{
		0x80000017: true,  // WOF / Compact OS
		0x80000013: true,  // Data Deduplication
		0x9000001A: true,  // cloud files placeholder
		0x9000301A: true,  // cloud files placeholder, provider variant
		0xA000000C: false, // symbolic link
		0xA0000003: false, // mount point / junction
		0x8000001B: false, // app execution alias
		0x80000023: false, // AF_UNIX socket
		0x00000001: false, // non-Microsoft tag
		0x9000001B: false, // unknown
	} {
		if got := harmlessWindowsReparseTag(tag); got != want {
			t.Errorf("harmlessWindowsReparseTag(0x%08x) = %t, want %t", tag, got, want)
		}
	}
}
