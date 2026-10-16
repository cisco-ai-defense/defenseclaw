// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"testing"
	"time"
)

// GAP-0529: peek, which explain reads for an account the directory cannot
// name now, reports only facts a request would still be served: not past
// maxAge, and not once the guardian record they were built from is no longer
// trusted, which get drops inside the hour too (GAP-1268).
func TestIdentityCachePeekDropsFactsRequestsNoLongerGet(t *testing.T) {
	down := errors.New("SSSD NSS responder: i/o timeout")
	c := newOracleTestCache()
	recordUntil := c.now.Add(10 * time.Minute)
	c.cache.trustedUntil = func(string, time.Time) time.Time { return recordUntil }
	if _, ok := c.cache.get("94404116", true); !ok {
		t.Fatal("first lookup returned no facts")
	}
	if _, _, ok := c.cache.peek("94404116"); !ok {
		t.Fatal("peek did not report facts requests use")
	}
	c.set(11*time.Minute, "", down)
	if facts, _, ok := c.cache.peek("94404116"); ok {
		t.Fatalf("peek reported %+v, built from a record that is no longer trusted", facts)
	}
	if facts, ok := c.cache.get("94404116", false); ok {
		t.Fatalf("get served %+v after peek", facts)
	}

	aged := newOracleTestCache()
	if _, ok := aged.cache.get("94404117", true); !ok {
		t.Fatal("first lookup returned no facts")
	}
	aged.set(identityDirectoryMaxAge+time.Minute, "", down)
	if facts, _, ok := aged.cache.peek("94404117"); ok {
		t.Fatalf("peek reported %+v, older than maxAge", facts)
	}
	if _, _, ok := aged.cache.peek("94404118"); ok {
		t.Fatal("peek reported facts for a key never looked up")
	}
}
