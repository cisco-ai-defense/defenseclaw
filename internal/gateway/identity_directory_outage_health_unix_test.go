// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// status-v2 GAP-0011: on a bound Mac a lookup waits on Open Directory for a
// minute and more while the domain controllers do not answer, and health
// counted nothing until it ended, after the outage. A lookup unanswered for a
// a minute counts its account as failing; its answer
// ends that.
func TestHealthCountsALookupTheDirectoryDoesNotAnswer(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Unix(2_000_000, 0).UnixNano())
	release := make(chan struct{})
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		<-release
		return useridentity.DirectoryFacts{Groups: []string{"engineering"}, ResolvedAt: time.Now()}, nil
	})
	cache.logf = nil
	cache.now = func() time.Time { return time.Unix(0, clock.Load()) }
	if _, ok := cache.get("1435629419", false); ok {
		t.Fatal("a cold lookup answered at once")
	}
	clock.Add(int64(time.Minute - time.Second))
	if h := cache.health(); h.Failing != 0 {
		t.Fatalf("a lookup %s old counted as failing: %+v", time.Minute-time.Second, h)
	}
	clock.Add(int64(2 * time.Second))
	h := cache.health()
	if h.Failing != 1 || len(h.Accounts) != 1 || h.Accounts[0] != "1435629419" || !strings.Contains(h.LastError, "has not answered") {
		t.Fatalf("a lookup the directory has not answered for %s: health %+v; want the account failing", time.Minute+time.Second, h)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		cache.mu.Lock()
		done := cache.entries["1435629419"].inflight == nil
		cache.mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the lookup did not end")
		}
		time.Sleep(time.Millisecond)
	}
	if h := cache.health(); h.Failing != 0 {
		t.Fatalf("the answered lookup still counts as failing: %+v", h)
	}
}

// status-v2 GAP-0011: a bound Mac answers "no such account" for a directory
// account it holds in no cache while its domain controllers do not answer.
// Health took a new user's lookup that failed so for a query of an account
// that does not exist and stayed ok through the outage. While the guardian
// lists a domain away the answer is not definitive and counts as a failure;
// with the directory answering it still says nothing about the directory.
func TestHealthCountsANewUsersNoSuchAccountDuringAnOutage(t *testing.T) {
	previous := directoryUnreachable
	t.Cleanup(func() { directoryUnreachable = previous })
	for _, away := range []bool{true, false} {
		directoryUnreachable = func(string) bool { return away }
		cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
			return useridentity.DirectoryFacts{}, unixidentity.ErrNotFound
		})
		cache.logf = nil
		// A new user's first lookup (explain, a refresh), no hook yet.
		if answer := cache.explain("1435629420", time.Second); answer.ok {
			t.Fatalf("away=%t: the failed lookup gave facts", away)
		}
		h := cache.health()
		switch {
		case away && h.Failing != 1:
			t.Fatalf("a new account the directory could not name during an outage: health %+v; want failing 1", h)
		case !away && h.Failing != 0:
			t.Fatalf("an account the answering directory does not hold counted as a directory failure: %+v", h)
		}
	}
}
