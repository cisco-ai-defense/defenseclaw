// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"testing"
	"time"
)

// W19 review (loop round 1): the AD UPN cache still answers with its last
// good UPN through a failed TranslateNameW (GAP-0129), and reports that
// answer as unconfirmed so an agent identity row does not list it as a
// current fact. The answers lookup gives are the GAP-0129 ones.
func TestADUPNCacheReportsTheLastGoodAnswerUnconfirmed(t *testing.T) {
	const sid, sam = "S-1-5-21-1-2-3-1105", `CORP\alice`
	now := time.Unix(1_800_000_000, 0)
	answer := "alice@corp.example.com"
	var started, finish chan struct{}
	cache := newADUPNCache(func(string) string {
		if started != nil {
			close(started)
			<-finish
		}
		return answer
	})
	cache.now = func() time.Time { return now }
	step := func(name, want string, wantUnconfirmed bool, wait time.Duration) {
		t.Helper()
		got := cache.lookup(sid, sam, wait)
		if unconfirmed := cache.unconfirmed(sid, sam, got); got != want || unconfirmed != wantUnconfirmed {
			t.Fatalf("%s: lookup = %q, unconfirmed %t; want %q, unconfirmed %t", name, got, unconfirmed, want, wantUnconfirmed)
		}
	}
	// blockNext makes the next translation wait until release is called.
	blockNext := func() (release func()) {
		started, finish = make(chan struct{}), make(chan struct{})
		return func() {
			<-started
			close(finish)
			started = nil
		}
	}

	step("verified", "alice@corp.example.com", false, time.Second)
	answer, now = "", now.Add(adUPNTTL)
	step("failed refresh keeps the last good UPN", "alice@corp.example.com", true, time.Second)
	now = now.Add(adUPNFailureTTL - time.Second)
	step("inside the failure lifetime", "alice@corp.example.com", true, time.Second)

	now = now.Add(2 * time.Second)
	answer = "renamed@corp.example.com"
	release := blockNext()
	step("retry still running after a failure", "alice@corp.example.com", true, 0)
	release()
	step("rename verified", "renamed@corp.example.com", false, time.Second)
	if !cache.unconfirmed(sid, sam, "alice@corp.example.com") {
		t.Fatal("the UPN before the rename is still reported confirmed")
	}

	// A refresh of a verified answer that has not finished: the latest
	// completed translation verified the UPN it gives.
	now = now.Add(adUPNTTL)
	release = blockNext()
	step("refresh running after a success", "renamed@corp.example.com", false, 0)
	release()
	step("refresh verified", "renamed@corp.example.com", false, time.Second)

	// An answer the cache does not hold for the identity, such as another
	// SID's under a reused account name, is not confirmed.
	if !cache.unconfirmed("S-1-5-21-1-2-3-1106", sam, "renamed@corp.example.com") {
		t.Fatal("another SID's answer is reported confirmed")
	}
}
