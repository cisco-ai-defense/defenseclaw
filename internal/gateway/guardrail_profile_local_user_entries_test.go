// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0197 unit rows: a local account (Linux /etc/passwd, the local macOS
// node, the Windows SAM) is selected by its uid or SID and by .\name, on
// Windows also by COMPUTER\name, never by its bare name (GAP-0305, GAP-0313).
func TestLocalAccountUsersEntriesSelectByIDAndDotName(t *testing.T) {
	for _, tc := range []struct {
		platform, id, computer string
		kind                   string
	}{
		{"linux", "1601", "", useridentity.KindForID("1601")},
		{"darwin", "502", "", useridentity.KindForID("502")},
		{"windows", "S-1-5-21-1004336348-1177238915-682003330-1001", "WIN-E7", useridentity.KindWindowsSID},
	} {
		t.Run(tc.platform, func(t *testing.T) {
			subject := profileSubjectFromVerified(VerifiedSubject{UserID: tc.id, IDKind: tc.kind, UserName: "e7local",
				Directory: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, AccountDomain: tc.computer, ResolvedAt: time.Now()}}, false)
			if !subject.localAccount {
				t.Fatalf("not a local subject: %+v", subject)
			}
			if userEntryMatches(&subject, "e7local") {
				t.Fatal("a bare name selected a local account")
			}
			for _, entry := range []string{tc.id, `.\e7local`, `.\E7LOCAL`} {
				if !userEntryMatches(&subject, entry) {
					t.Fatalf("users entry %q did not select the local account", entry)
				}
			}
			if tc.computer != "" && !userEntryMatches(&subject, tc.computer+`\e7local`) {
				t.Fatalf("COMPUTER\\name did not select the local account")
			}
		})
	}
}
