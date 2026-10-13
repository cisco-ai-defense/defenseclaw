// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"testing"
)

// The memoised match returns what the uncached walk returns, for verified,
// unverified and failed-lookup subjects, and the cache stays bounded.
func TestProfileMatchMemoisationAgreesWithTheWalk(t *testing.T) {
	set, err := newGuardrailProfileSet(profileSecurityConfig(), nil, true)
	if err != nil || set == nil {
		t.Fatalf("newGuardrailProfileSet: %v", err)
	}
	subjects := []*profileSubject{
		nil,
		{UserID: "1001", UPN: "Alice@corp.example"},
		{UserID: "1002", Groups: []string{"S-1-5-21-1", `corp\contractors`}},
		{UserID: "1003", UserName: "bob", Groups: []string{"dcidr-grp"}},
		{UserID: "1003", UserName: "bob"},
		{UserID: "1001", UPN: "alice@corp.example", LookupFailed: true},
	}
	for round := 0; round < 2; round++ { // the second round is served from the cache
		for _, subject := range subjects {
			for _, source := range []string{"", profileSubjectVerified} {
				for _, connectorName := range []string{"", "cursor", "codex"} {
					for _, agent := range []string{"", "agt-0123456789abcdef"} {
						got := set.match(subject, source, connectorName, agent)
						want := set.matchUncached(subject, source, connectorName, agent)
						if got != want {
							t.Fatalf("round %d match(%+v,%q,%q,%q) = %+v, walk says %+v", round, subject, source, connectorName, agent, got, want)
						}
					}
				}
			}
		}
	}
	for i := 0; i < profileMatchCacheSize+500; i++ {
		set.match(&profileSubject{UserID: fmt.Sprint(i)}, profileSubjectVerified, "cursor", "")
	}
	if n := len(set.matches.entries); n > profileMatchCacheSize {
		t.Fatalf("cache holds %d decisions, bound is %d", n, profileMatchCacheSize)
	}
}
