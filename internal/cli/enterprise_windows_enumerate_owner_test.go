// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// rel-1-0-2 GAP-0618: the SID an account last resolved to stood in for every
// failed lookup for the life of the enumerator. It stands in for at most
// enterpriseWindowsEnumerateKnownSIDMaxAge; after that the account is
// unknown until a lookup answers.
func TestWindowsEnumeratorUsesAKnownAccountSIDOnlyWhileItIsRecent(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	previous := enterpriseWindowsEnumerateNow
	t.Cleanup(func() { enterpriseWindowsEnumerateNow = previous })
	enterpriseWindowsEnumerateNow = func() time.Time { return now }
	var known enterpriseWindowsKnownSIDs
	const key, sid, newer = `dclab\alice`, "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-2002"
	if got := known.remember(key, ""); got != "" {
		t.Fatalf("an account never resolved = %q", got)
	}
	if got := known.remember(key, sid); got != sid {
		t.Fatalf("an answered lookup = %q", got)
	}
	now = now.Add(enterpriseWindowsEnumerateKnownSIDMaxAge)
	if got := known.remember(key, ""); got != sid {
		t.Fatalf("a failed lookup within the bound = %q, want %q", got, sid)
	}
	now = now.Add(time.Second)
	if got := known.remember(key, ""); got != "" {
		t.Fatalf("a failed lookup past the bound = %q, want unknown", got)
	}
	if got := known.remember(key, newer); got != newer {
		t.Fatalf("a new answer = %q", got)
	}
	if got := known.remember(key, ""); got != newer {
		t.Fatalf("a failed lookup after a new answer = %q, want %q", got, newer)
	}
}

// rel-1-0-2 GAP-0618: where the snapshot's owner is the session's signed-in
// account, an agent started in that session as another account is judged by
// its own token account, not the session's.
func TestWindowsEnumeratorJudgesASessionOwnedAgentByItsTokenAccount(t *testing.T) {
	const session = "S-1-5-21-1-2-3-1001"
	for _, tc := range []struct {
		name    string
		process inventory.AgentProcess
		want    string
	}{
		{"token SID", inventory.AgentProcess{OwnerSID: session, User: `DCLAB\alice`}, session},
		{"session SID with a token account", inventory.AgentProcess{OwnerSID: session, OwnerSIDFromSession: true, User: `DCLAB\bob`}, ""},
		{"session SID without a token account", inventory.AgentProcess{OwnerSID: session, OwnerSIDFromSession: true}, session},
	} {
		if got := enterpriseWindowsRunningAgentSnapshotSID(tc.process); got != tc.want {
			t.Fatalf("%s: SID %q, want %q", tc.name, got, tc.want)
		}
	}
}
