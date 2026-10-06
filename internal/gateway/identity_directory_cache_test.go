// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// TestIdentityDirectoryCacheWaitsForColdLookup pins the cold-cache budget: a
// blocking caller gets facts from a lookup slower than a fast local one, as a
// cold SSSD lookup is, instead of default_lookup_failed.
func TestIdentityDirectoryCacheWaitsForColdLookup(t *testing.T) {
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		time.Sleep(400 * time.Millisecond)
		return useridentity.DirectoryFacts{Groups: []string{"dc-ml-team@dclab.test"}, ResolvedAt: time.Now()}, nil
	})
	if facts, ok := cache.get("1201", true); !ok || len(facts.Groups) != 1 {
		t.Fatalf("cold blocking lookup = %+v, %v; want the resolved facts", facts, ok)
	}
}
