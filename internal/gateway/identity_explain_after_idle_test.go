// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"testing"
	"time"
)

// GAP-1145: an account whose cached facts sat idle for over an hour, and
// whose group membership then changed, is explained from a lookup of
// explain's own, not from the expired facts: explain names the new group,
// and with the directory away it reports the failure instead of describing
// the old facts (and the old profile) as what requests get now.
func TestExplainAfterAnHourIdleDoesNotPresentExpiredFacts(t *testing.T) {
	c := newOracleTestCache()
	if _, ok := c.cache.get("94404145", true); !ok {
		t.Fatal("first hook lookup returned no facts")
	}
	c.set(identityDirectoryMaxAge+time.Minute, "dc-sbx-devs@dclab.test", nil)
	facts, err := explainDirectoryFacts(c.cache, "94404145")
	if err != nil || len(facts.Groups) != 1 || facts.Groups[0] != "dc-sbx-devs@dclab.test" {
		t.Fatalf("explain after an hour idle = %+v, %v; want the changed membership", facts, err)
	}

	down := newOracleTestCache()
	if _, ok := down.cache.get("94404146", true); !ok {
		t.Fatal("first hook lookup returned no facts")
	}
	down.set(identityDirectoryMaxAge+time.Minute, "dc-sbx-devs@dclab.test", errors.New("LSA: the domain controller does not answer"))
	if facts, err := explainDirectoryFacts(down.cache, "94404146"); err == nil {
		t.Fatalf("explain with the directory away after an hour idle = %+v; want the lookup failure, not the expired facts", facts)
	}
	if facts, _, ok := down.cache.peek("94404146"); ok {
		t.Fatalf("the cache view explain prints still holds the expired facts %+v", facts)
	}
}
