// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review of GAP-0551 (loop 2): a UPN SSSD InfoPipe stopped reporting is kept
// for the same account incarnation only: a uid handed to another account of
// the same name in the same SSSD domain (deleted and created again with
// another SID) does not inherit the first account's UPN for a day. Since
// loop 3 both records must name it: a previous record a guardian before
// 1.0.4 wrote names none, and after an upgrade the uid and name may already
// be another account's, so its UPN is not copied into the new record (the
// UPN then needs a fresh InfoPipe answer), nor into a record whose own
// incarnation is unknown.
func TestKeepVerifiedInfoPipeUPNNeedsTheSameIncarnation(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	// Both records carry the same SID, which w2b-g-enum requires as well.
	previous := IdentitySpoolRecord{Key: "5000", User: "alice", SSSDDomain: "corp.example", AccountSID: "S-1-5-21-1-1-1-500", AccountIncarnation: "sid:S-1-5-21-1-1-1-500",
		UPNSource: UPNSourceInfoPipe, UpdatedAt: now.Add(-15 * time.Minute),
		Facts: useridentity.DirectoryFacts{UPN: "alice@corp.example", Principal: "alice@corp.example"}}
	fresh := IdentitySpoolRecord{Key: "5000", User: "alice", SSSDDomain: "corp.example", AccountSID: "S-1-5-21-1-1-1-500", AccountIncarnation: "sid:S-1-5-21-1-1-1-501",
		UpdatedAt: now}
	if got, kept := KeepVerifiedInfoPipeUPN(fresh, previous, nil); kept || got.Facts.UPN != "" {
		t.Fatalf("record of another incarnation = %+v, kept %v; want no UPN carried over", got, kept)
	}
	fresh.AccountIncarnation = previous.AccountIncarnation
	if got, kept := KeepVerifiedInfoPipeUPN(fresh, previous, nil); !kept || got.Facts.UPN != "alice@corp.example" {
		t.Fatalf("record of the same incarnation = %+v, kept %v; want the UPN kept", got, kept)
	}
	unknown := fresh
	unknown.AccountIncarnation = ""
	if got, kept := KeepVerifiedInfoPipeUPN(unknown, previous, nil); kept || got.Facts.UPN != "" {
		t.Fatalf("record of an unknown incarnation = %+v, kept %v; want no UPN carried over", got, kept)
	}
	// The upgrade case: the legacy record is CORP's former alice, the fresh
	// one names the account that holds the uid and name now.
	previous.AccountIncarnation = ""
	fresh.AccountIncarnation = "sid:S-1-5-21-1-1-1-501"
	if got, kept := KeepVerifiedInfoPipeUPN(fresh, previous, nil); kept || got.Facts.UPN != "" {
		t.Fatalf("record after a legacy record = %+v, kept %v; want the former account's UPN not carried over", got, kept)
	}
}
