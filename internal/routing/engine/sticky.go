// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"container/list"
	"sync"
	"time"
)

// Sticky routing (DESIGN 16.4): the classifier answer of a conversation is
// reused for its later calls, so a tool loop does not flip models (prompt
// cache, thinking signatures, encrypted reasoning). It replaces only the
// classifier step; policy, admin and deny still run on every call.
const (
	stickyTTL           = 30 * time.Minute // absolute, not sliding
	stickyMaxEntries    = 4096
	stickyMaxPerSubject = 256
)

type stickyKey struct {
	subject      string
	connector    string
	conversation string
	requested    string
	policy       string
}

type stickyEntry struct {
	key     stickyKey
	result  ClassifyResult
	expires time.Time
}

// StickyCache is the conversation cache (one per gateway, shared by every
// generation engine).
type StickyCache struct {
	mu         sync.Mutex
	ll         *list.List
	items      map[stickyKey]*list.Element
	perSubject map[string]int
	now        func() time.Time
}

// NewStickyCache returns an empty cache.
func NewStickyCache() *StickyCache {
	return &StickyCache{ll: list.New(), items: map[stickyKey]*list.Element{}, perSubject: map[string]int{}, now: time.Now}
}

func (c *StickyCache) get(k stickyKey) (ClassifyResult, bool) {
	if c == nil || k.conversation == "" {
		return ClassifyResult{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[k]
	if !ok {
		return ClassifyResult{}, false
	}
	e := el.Value.(*stickyEntry)
	if c.now().After(e.expires) {
		c.removeLocked(el)
		return ClassifyResult{}, false
	}
	c.ll.MoveToFront(el)
	return e.result, true
}

func (c *StickyCache) put(k stickyKey, r ClassifyResult) {
	if c == nil || k.conversation == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[k]; ok {
		c.removeLocked(el)
	}
	if c.perSubject[k.subject] >= stickyMaxPerSubject {
		// Evict the oldest entry of this subject only, so one caller cannot
		// push everyone else out of the shared cache.
		for el := c.ll.Back(); el != nil; el = el.Prev() {
			if el.Value.(*stickyEntry).key.subject == k.subject {
				c.removeLocked(el)
				break
			}
		}
	}
	for c.ll.Len() >= stickyMaxEntries {
		c.removeLocked(c.ll.Back())
	}
	el := c.ll.PushFront(&stickyEntry{key: k, result: r, expires: c.now().Add(stickyTTL)})
	c.items[k] = el
	c.perSubject[k.subject]++
}

func (c *StickyCache) removeLocked(el *list.Element) {
	e := el.Value.(*stickyEntry)
	c.ll.Remove(el)
	delete(c.items, e.key)
	if c.perSubject[e.key.subject]--; c.perSubject[e.key.subject] <= 0 {
		delete(c.perSubject, e.key.subject)
	}
}
