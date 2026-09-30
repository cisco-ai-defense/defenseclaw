// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// slowPeerResolver answers every uid at once except slowUID, whose lookup
// blocks until release is closed (a directory user whose NSS lookup hangs).
type slowPeerResolver struct {
	unixidentity.Resolver
	slowUID   int
	started   chan struct{}
	release   chan struct{}
	once      sync.Once
	slowCalls atomic.Int32
}

func (r *slowPeerResolver) LookupUID(uid int) (unixidentity.Account, error) {
	if uid == r.slowUID {
		r.slowCalls.Add(1)
		r.once.Do(func() { close(r.started) })
		<-r.release
	}
	return unixidentity.Account{Name: fmt.Sprintf("user%d", uid), UID: uid, Home: fmt.Sprintf("/home/user%d", uid)}, nil
}

func useTestPeerResolver(t *testing.T, resolver unixidentity.Resolver) {
	t.Helper()
	previous := managedHookPeerHomes
	managedHookPeerHomes = &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver { return resolver },
		now:         time.Now,
	}
	t.Cleanup(func() { managedHookPeerHomes = previous })
}

// TestManagedHookSocketSlowAccountLookupDoesNotDelayOtherCallers: net/http
// runs ConnContext in its single accept loop. The caller's account lookup
// must not run there, or one directory user whose lookup hangs holds up the
// hook connections of every other user on the host. Other connections of the
// slow account wait for its lookup instead of each starting one.
func TestManagedHookSocketSlowAccountLookupDoesNotDelayOtherCallers(t *testing.T) {
	resolver := &slowPeerResolver{slowUID: 5001, started: make(chan struct{}), release: make(chan struct{})}
	useTestPeerResolver(t, resolver)
	var accepted atomic.Int32
	restoreCredentials := hookSocketPeerCredentials
	hookSocketPeerCredentials = func(net.Conn) (peercred.Credentials, error) {
		// The first accepted connection is the slow caller, every later
		// one another account.
		if accepted.Add(1) == 1 {
			return peercred.Credentials{UID: 5001, GID: 5001, PID: 101}, nil
		}
		return peercred.Credentials{UID: 5002, GID: 5002, PID: 102}, nil
	}
	t.Cleanup(func() { hookSocketPeerCredentials = restoreCredentials })
	socket, _, _ := startTestHookSocketServer(t, hookSocketTestServer{})

	slowDone := make(chan error, 1)
	go func() {
		_, _, err := hookSocketPost(hookSocketClient(socket, 20*time.Second), "/api/v1/not-a-hook-route", []byte(`{}`))
		slowDone <- err
	}()
	select {
	case <-resolver.started:
	case <-time.After(5 * time.Second):
		close(resolver.release)
		t.Fatal("the slow caller's account lookup never started")
	}
	shared := make(chan string, 4)
	for i := 0; i < cap(shared); i++ {
		go func() { shared <- managedHookPeerHomes.lookup(5001) }()
	}

	start := time.Now()
	status, body, err := hookSocketPost(hookSocketClient(socket, 3*time.Second), "/api/v1/not-a-hook-route", []byte(`{}`))
	elapsed := time.Since(start)
	close(resolver.release)
	if err != nil {
		t.Fatalf("another account's request waited behind a slow account lookup: %v after %s", err, elapsed)
	}
	if status != http.StatusForbidden || elapsed > 2*time.Second {
		t.Fatalf("other caller = %d %q after %s, want a prompt refusal of the unknown route", status, body, elapsed)
	}
	if err := <-slowDone; err != nil {
		t.Fatalf("the slow caller's own request failed: %v", err)
	}
	for i := 0; i < cap(shared); i++ {
		if home := <-shared; home != "/home/user5001" {
			t.Fatalf("a shared lookup answered %q", home)
		}
	}
	if got := resolver.slowCalls.Load(); got != 1 {
		t.Fatalf("lookups of the slow account = %d, want one shared lookup", got)
	}
}

// transientPeerResolver fails every lookup with a directory error that is not
// a definitive "no such account".
type transientPeerResolver struct {
	unixidentity.Resolver
	calls atomic.Int32
	err   error
}

func (r *transientPeerResolver) LookupUID(int) (unixidentity.Account, error) {
	r.calls.Add(1)
	return unixidentity.Account{}, r.err
}

// TestManagedHookPeerLookupReusesAFailedLookupBriefly: a directory outage must
// cost one lookup per uid per retry interval, not one (or two: name and home)
// per connection, and a definitive "no such account" is kept for the full TTL.
func TestManagedHookPeerLookupReusesAFailedLookupBriefly(t *testing.T) {
	for _, test := range []struct {
		name       string
		err        error
		retryAfter time.Duration
	}{
		{"transient", errors.New("getent: timed out"), managedHookPeerLookupRetry},
		{"not found", unixidentity.ErrNotFound, managedHookPeerHomeTTL},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := &transientPeerResolver{err: test.err}
			now := time.Unix(2_000_000, 0)
			cache := &managedHookPeerHomeCache{
				newResolver: func() unixidentity.Resolver { return resolver },
				now:         func() time.Time { return now },
			}
			for i := 0; i < 3; i++ {
				if home, name := cache.lookup(4001), cache.lookupName(4001); home != "" || name != "" {
					t.Fatalf("failed lookup resolved %q %q", home, name)
				}
			}
			if got := resolver.calls.Load(); got != 1 {
				t.Fatalf("resolver calls inside the retry interval = %d, want 1", got)
			}
			now = now.Add(test.retryAfter - time.Second)
			cache.lookup(4001)
			if got := resolver.calls.Load(); got != 1 {
				t.Fatalf("resolver asked again before the interval ended (%d calls)", got)
			}
			now = now.Add(2 * time.Second)
			cache.lookup(4001)
			if got := resolver.calls.Load(); got != 2 {
				t.Fatalf("resolver calls after the interval = %d, want 2", got)
			}
		})
	}
}
