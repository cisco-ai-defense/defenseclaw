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
	ids   map[string][]int
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
	c.ids = map[string][]int{}
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
		return append([]int{}, hit...), nil
	}
	c.mu.Unlock()
	ids, err := c.inner.GroupIDs(account)
	if err == nil {
		c.mu.Lock()
		c.ids[key] = append([]int{}, ids...)
		c.mu.Unlock()
	}
	return ids, err
}

func (c *CachingResolver) ListUsers() ([]Account, bool, error) {
	return c.inner.ListUsers()
}
