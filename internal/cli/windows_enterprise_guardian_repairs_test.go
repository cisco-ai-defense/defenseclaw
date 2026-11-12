// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
	"time"
)

// GAP-0573: the guardian puts a drifted runtime folder ACL back within
// seconds, before ensure looks; ensure names each repair the guardian logged
// since the last lifecycle run, once per path and reason.
func TestWindowsGuardianRepairsAfter(t *testing.T) {
	loc := time.FixedZone("PST", -8*3600)
	log := strings.Join([]string{
		`2026/11/04 18:38:19 defenseclaw_repair object="RuntimeDirectory" path="C:\\ProgramData\\Cisco\\DefenseClaw\\runtime" principal="S-1-5-32-545" reason="untrusted principal S-1-5-32-545 has write access"`,
		`2026/11/04 19:38:24 [hook-guardian] reconcile reason=fsnotify`,
		`2026/11/04 19:38:24 defenseclaw_repair object="RuntimeDirectory" path="C:\\ProgramData\\Cisco\\DefenseClaw\\runtime" principal="S-1-5-32-545" reason="untrusted principal S-1-5-32-545 has write access"`,
		`2026/11/04 19:40:24 defenseclaw_repair object="RuntimeDirectory" path="C:\\ProgramData\\Cisco\\DefenseClaw\\runtime" principal="S-1-5-32-545" reason="untrusted principal S-1-5-32-545 has write access"`,
		`2026/11/04 19:40:25 defenseclaw_accept object="RuntimeFile" path="C:\\x"`,
	}, "\r\n")
	since := time.Date(2026, 11, 5, 3, 35, 55, 500e6, time.UTC) // 19:35:55.5 PST
	got := windowsGuardianRepairsAfter(log, since, loc)
	want := `C:\ProgramData\Cisco\DefenseClaw\runtime at 2026-11-05T03:40:24Z (untrusted principal S-1-5-32-545 has write access)`
	if len(got) != 1 || got[0] != want {
		t.Fatalf("repairs = %q, want [%q]", got, want)
	}
	if got := windowsGuardianRepairsAfter(log, since.Add(time.Hour), loc); len(got) != 0 {
		t.Fatalf("no repair after the last run: %q", got)
	}
}
