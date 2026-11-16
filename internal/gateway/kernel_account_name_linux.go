//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

const kernelBlockNameCacheTTL = time.Minute

type kernelBlockNameEntry struct {
	name    string
	expires time.Time
}

type kernelBlockNameCache struct {
	mu     sync.Mutex
	names  map[int]kernelBlockNameEntry
	lookup func(int) (string, error)
	now    func() time.Time
}

func (cache *kernelBlockNameCache) name(uid int) string {
	if uid < 0 {
		return ""
	}
	now := cache.now()
	cache.mu.Lock()
	if entry, ok := cache.names[uid]; ok && now.Before(entry.expires) {
		cache.mu.Unlock()
		return entry.name
	}
	cache.mu.Unlock()

	name, err := cache.lookup(uid)
	if err != nil {
		name = ""
	}
	cache.mu.Lock()
	if len(cache.names) >= 1024 {
		cache.names = make(map[int]kernelBlockNameEntry)
	}
	if cache.names == nil {
		cache.names = make(map[int]kernelBlockNameEntry)
	}
	cache.names[uid] = kernelBlockNameEntry{name: name, expires: cache.now().Add(kernelBlockNameCacheTTL)}
	cache.mu.Unlock()
	return name
}

var kernelBlockNames = &kernelBlockNameCache{
	lookup: func(uid int) (string, error) {
		account, err := unixidentity.Default(context.Background()).LookupUID(uid)
		return account.Name, err
	},
	now: time.Now,
}

func kernelBlockUIDName(uid int) string { return kernelBlockNames.name(uid) }
