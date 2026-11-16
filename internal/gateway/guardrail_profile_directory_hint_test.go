// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// GAP-0712: the advice for a directory that does not answer names winbind on
// a winbind host and SSSD on other Linux hosts.
func TestDirectoryDownHintNamesTheHostsDirectoryService(t *testing.T) {
	orig := directoryUsesWinbind
	t.Cleanup(func() { directoryUsesWinbind = orig })
	directoryUsesWinbind = func() bool { return true }
	if hint := directoryDownHint("linux"); !strings.Contains(hint, "wbinfo --ping-dc") || strings.Contains(hint, "SSSD") {
		t.Fatalf("winbind host hint = %q", hint)
	}
	directoryUsesWinbind = func() bool { return false }
	if hint := directoryDownHint("linux"); !strings.Contains(hint, "sssctl domain-status") {
		t.Fatalf("SSSD host hint = %q", hint)
	}
	if hint := directoryDownHint("darwin"); !strings.Contains(hint, "dsconfigad -show") {
		t.Fatalf("macOS hint = %q", hint)
	}
}
