//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"strconv"
	"sync"
	"time"
)

// CachingResolver memoizes definitive answers (found or ErrNotFound) for
// one enumeration or reconcile cycle. Transient errors are never cached so
// a directory outage is retried on the next call. Call Reset between cycles.
type CachingResolver struct {
	inner Resolver
	mu    sync.Mutex
	users map[string]cachedAccount
	uids  map[int]cachedAccount
	grps  map[string]cachedGroup
	gids  map[int]cachedGroup
	ids   map[string]cachedGroupIDs
}

type cachedGroupIDs struct {
	ids []int
	at  time.Time
}

type cachedAccount struct {
	account Account
	err     error
}

type cachedGroup struct {
	group Group
	err   error
}

// NewCachingResolver wraps inner.
func NewCachingResolver(inner Resolver) *CachingResolver {
	c := &CachingResolver{inner: inner}
	c.Reset()
	return c
}

// Reset drops every cached answer.
func (c *CachingResolver) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.users = map[string]cachedAccount{}
	c.uids = map[int]cachedAccount{}
	c.grps = map[string]cachedGroup{}
	c.gids = map[int]cachedGroup{}
	c.ids = map[string]cachedGroupIDs{}
}

// ResetKeepingGroupIDs drops every cached answer except the group lists
// resolved within maxAge. A hook guardian pass that a file change armed runs
// seconds after the last one: on macOS each account's list is confirmed with
// one dsmemberutil run per group (GAP-0528), about 1.5 s per pass on an
// Active Directory host, which put the repair of a rewritten Hermes hooks
// block past its 3 s bound (r103 GAP-0045, GAP-1825). Accounts, homes and
// uids are always asked again.
func (c *CachingResolver) ResetKeepingGroupIDs(maxAge time.Duration) {
	c.mu.Lock()
	kept := map[string]cachedGroupIDs{}
	for key, hit := range c.ids {
		if age := time.Since(hit.at); age >= 0 && age < maxAge {
			kept[key] = hit
		}
	}
	c.mu.Unlock()
	c.Reset()
	c.mu.Lock()
	c.ids = kept
	c.mu.Unlock()
}

func cacheable(err error) bool { return err == nil || IsNotFound(err) }

func (c *CachingResolver) LookupUser(name string) (Account, error) {
	c.mu.Lock()
	if hit, ok := c.users[name]; ok {
		c.mu.Unlock()
		return hit.account, hit.err
	}
	c.mu.Unlock()
	account, err := c.inner.LookupUser(name)
	if cacheable(err) {
		c.mu.Lock()
		c.users[name] = cachedAccount{account, err}
		if err == nil {
			c.uids[account.UID] = cachedAccount{account, nil}
		}
		c.mu.Unlock()
	}
	return account, err
}

func (c *CachingResolver) LookupUID(uid int) (Account, error) {
	c.mu.Lock()
	if hit, ok := c.uids[uid]; ok {
		c.mu.Unlock()
		return hit.account, hit.err
	}
	c.mu.Unlock()
	account, err := c.inner.LookupUID(uid)
	if cacheable(err) {
		c.mu.Lock()
		c.uids[uid] = cachedAccount{account, err}
		if err == nil {
			c.users[account.Name] = cachedAccount{account, nil}
		}
		c.mu.Unlock()
	}
	return account, err
}

// ForgetUID drops the cached answer for uid, so the next lookup asks the
// directory again.
func (c *CachingResolver) ForgetUID(uid int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.uids, uid)
}

func (c *CachingResolver) LookupGroup(name string) (Group, error) {
	c.mu.Lock()
	if hit, ok := c.grps[name]; ok {
		c.mu.Unlock()
		return hit.group, hit.err
	}
	c.mu.Unlock()
	group, err := c.inner.LookupGroup(name)
	if cacheable(err) {
		c.mu.Lock()
		c.grps[name] = cachedGroup{group, err}
		c.mu.Unlock()
	}
	return group, err
}

func (c *CachingResolver) LookupGroupID(gid int) (Group, error) {
	c.mu.Lock()
	if hit, ok := c.gids[gid]; ok {
		c.mu.Unlock()
		return hit.group, hit.err
	}
	c.mu.Unlock()
	group, err := c.inner.LookupGroupID(gid)
	if cacheable(err) {
		c.mu.Lock()
		c.gids[gid] = cachedGroup{group, err}
		c.mu.Unlock()
	}
	return group, err
}

func (c *CachingResolver) GroupIDs(account Account) ([]int, error) {
	key := account.Name + "\x00" + strconv.Itoa(account.UID)
	c.mu.Lock()
	if hit, ok := c.ids[key]; ok {
		c.mu.Unlock()
		return append([]int{}, hit.ids...), nil
	}
	c.mu.Unlock()
	ids, err := c.inner.GroupIDs(account)
	if err == nil {
		c.mu.Lock()
		c.ids[key] = cachedGroupIDs{ids: append([]int{}, ids...), at: time.Now()}
		c.mu.Unlock()
	}
	return ids, err
}

func (c *CachingResolver) ListUsers() ([]Account, bool, error) {
	return c.inner.ListUsers()
}
