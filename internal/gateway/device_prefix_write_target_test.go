// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// rel-1-0-6 GAP-0482: the ? or . of a Win32 \\?\ or \\.\ prefix is path
// syntax, not a wildcard: a write spelled \\?\UNC\host\share\x or \\?\C:\x
// is judged by the names that follow. A protected spelling behind the
// prefix and every other device path stay unknown (not ordinary).
func TestGAP0482DevicePrefixIsNoWildcardInAnOrdinaryWriteTarget(t *testing.T) {
	for target, ordinary := range map[string]bool{
		`\\?\UNC\192.0.2.1\share\w.txt`:           true,
		`//?/unc/192.0.2.1/share/w.txt`:           true,
		`\\.\UNC\fileserver\team\notes.txt`:       true,
		`\\?\C:\Users\alice\proj\out.txt`:         true,
		`//./c:/work/out.txt`:                     true,
		`\\fileserver\team\notes.txt`:             true,
		`\\?\C:\Users\alice\.ssh\authorized_keys`: false,
		`\\?\UNC\fileserver\team\.ssh\config`:     false,
		`\\?\UNC\localhost\c$\Users\a\x`:          false,
		`\\?\UNC\fileserver\team\authorized_keys`: false,
		`\\?\C:\Users\alice\SSH~1\x`:              false,
		`\\?\GLOBALROOT\Device\HarddiskVolume1\x`: false,
		`\\?\Volume{0b1c}\Users\alice\x`:          false,
		`\\?\C:\Users\alice\proj\..\.ssh\id`:      false,
		`\\?\UNC\fileserver\team\*.txt`:           false,
	} {
		if got := windowsLocationOrdinaryWriteTarget(target); got != ordinary {
			t.Errorf("windowsLocationOrdinaryWriteTarget(%q) = %v, want %v", target, got, ordinary)
		}
	}
}
