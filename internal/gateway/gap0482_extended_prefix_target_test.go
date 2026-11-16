// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// rel-1-0-6:GAP-0482 (review 1): the dead-share fallback reads a write
// target the hook could not resolve by its spelling. The extended-length
// prefix (\\?\UNC\, \\?\) is no wildcard: an ordinary target behind it is
// ordinary, as without it. A protected spelling stays protected with or
// without the prefix, and a wildcard after the prefix stays uncertain.
func TestGAP0482ExtendedPrefixWriteTargetIsReadByItsPath(t *testing.T) {
	for _, row := range []struct {
		target   string
		ordinary bool
	}{
		{`\\server\share\notes.txt`, true},
		{`\\?\UNC\server\share\notes.txt`, true},
		{`\\?\unc\192.0.2.7\share\w.txt`, true},
		{`//server/share/notes.txt`, true},
		{`//?/UNC/server/share/notes.txt`, true},
		{`\\?\C:\Users\u\notes.txt`, true},
		{`\\server\share\.ssh\authorized_keys`, false},
		{`\\?\UNC\server\share\.ssh\authorized_keys`, false},
		{`\\?\UNC\server\share\authorized_keys`, false},
		{`\\?\UNC\localhost\C$\Users\u\.ssh\authorized_keys`, false},
		{`\\?\UNC\localhost\C$\Users\u\notes.txt`, false},
		{`\\?\C:\Users\u\.ssh\authorized_keys`, false},
		{`\\?\C:\ProgramData\ssh\administrators_authorized_keys`, false},
		{`\\?\C:\Users\u\SSH~1\notes.txt`, false},
		{`\\?\UNC\server\share\notes?.txt`, false},
		{`\\?\UNC\server\share\..\notes.txt`, false},
	} {
		if got := windowsLocationOrdinaryWriteTarget(row.target); got != row.ordinary {
			t.Errorf("windowsLocationOrdinaryWriteTarget(%q) = %v, want %v", row.target, got, row.ordinary)
		}
	}
}
