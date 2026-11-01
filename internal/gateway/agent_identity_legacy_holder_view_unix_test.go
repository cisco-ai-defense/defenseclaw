// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// GAP-2086 (1.0.3 -> 1.0.4 -> 1.0.5): A held the uid under 1.0.3 and had
// an agent turn there (its row names no account token). A 1.0.4 gateway
// never served the uid again, so the homes file keeps it as a legacy holder
// whose sighting is A's last hook. A is deleted and B created under the
// same name, uid and home path, and the guardian's record proves B's newer
// home before B's first hook. The view adopts the uid's first token then:
// it carries B's home proof (the home is younger than the sighting), which
// shows no continuity with A, so another holder is known and root's first
// view by name and by uid lists none of A's rows. A home older than the
// sighting (A itself) keeps its row.
func TestLegacyHolderViewHidesTheEarlierHoldersRowsOnceTheNewHomeIsProven(t *testing.T) {
	for _, recreated := range []bool{true, false} {
		f := newRecreatedAccountFixture(t)
		const oldRow = "agt-00000000002086a1"
		sighted := time.Unix(3_000_000, 0)
		body := `{"format":{"format":1},"` + f.id + `":{"home":"` + f.home + `","name":"alice","legacy_holder":true,"first_seen":` +
			strconv.FormatInt(sighted.UnixNano(), 10) + `,"pre_token_holder":true}}`
		if err := os.WriteFile(f.store, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		f.start()
		if err := f.inv.UpsertAgentIdentities(context.Background(), []inventory.AgentIdentityRecord{{AgentID: oldRow, UserID: f.id,
			UserName: "alice", Connector: "codex", FirstSeen: sighted.Add(-time.Hour), LastSeen: sighted}}); err != nil {
			t.Fatal(err)
		}
		birth := sighted.Add(-24 * time.Hour)
		if recreated {
			birth = sighted.Add(4 * time.Minute)
		}
		home := "home:2049:3000:" + strconv.FormatInt(birth.UnixNano(), 10)
		f.guardian(home)
		proof := strconv.Itoa(f.uid) + ":" + home
		for _, user := range []string{"alice", f.id} {
			rows := f.view(viewOf(user, proof))
			if _, listed := rows[oldRow]; listed == recreated {
				t.Fatalf("recreated=%v: view --user %s lists=%v the 1.0.3 holder's row (%v)", recreated, user, listed, listedIDs(rows))
			}
		}
	}
}
