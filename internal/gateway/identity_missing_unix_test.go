// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	osuser "os/user"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func TestUnixDefinitiveMissingAccount(t *testing.T) {
	if !definitiveMissingAccount(unixidentity.ErrNotFound) || !definitiveMissingAccount(osuser.UnknownUserIdError(1001)) {
		t.Fatal("NSS definitive absence counted as an outage")
	}
	cache := newIdentityDirectoryCache(nil)
	if cache.gone == nil || cache.confirmGone {
		t.Fatal("NSS absence must remain visible after an unrelated local lookup")
	}
}

func TestUnknownAccountDoesNotRaiseDirectoryHealthWarning(t *testing.T) {
	clock := time.Now()
	missing := false
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		if missing {
			return useridentity.DirectoryFacts{}, unixidentity.ErrNotFound
		}
		return useridentity.DirectoryFacts{ResolvedAt: clock}, nil
	})
	cache.now = func() time.Time { return clock }
	missing = true
	if answer := cache.explain("59999", time.Second); answer.ok || answer.reason == "" {
		t.Fatalf("unknown-account explain = %+v, want a named refusal", answer)
	}
	if health := cache.health(); health.Failing != 0 {
		t.Fatalf("unknown account changed directory health: %+v", health)
	}
	if _, ok := cache.get("59999", true); ok {
		t.Fatal("a hook request for the missing uid must not get directory facts")
	}
	if health := cache.health(); health.Failing != 1 {
		t.Fatalf("unresolved hook caller must still warn: %+v", health)
	}
	missing = false
	if answer := cache.explain("1001", time.Second); !answer.ok {
		t.Fatalf("known-account explain = %+v", answer)
	}
	clock = clock.Add(6 * time.Second)
	missing = true
	if answer := cache.explain("1001", time.Second); answer.reason == "" {
		t.Fatalf("known account disappearance lost cause: %+v", answer)
	}
	if health := cache.health(); health.Failing != 2 {
		t.Fatalf("known account disappearance hidden: %+v", health)
	}
}
