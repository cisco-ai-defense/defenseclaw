// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"container/list"
	"sync"
)

// lruLabels is a bounded, mutex-guarded map of path key -> pathLabel with
// least-recently-used eviction. It caps the per-session labeled-path memory so
// a long session cannot grow it without bound (brief step 1).
type lruLabels struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	m   map[string]*list.Element
}

type lruEntry struct {
	key string
	val pathLabel
}

func newLRU(max int) *lruLabels {
	if max <= 0 {
		max = defaultMaxLabeledPaths
	}
	return &lruLabels{max: max, ll: list.New(), m: make(map[string]*list.Element, max)}
}

func (c *lruLabels) put(key string, val pathLabel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		el.Value.(*lruEntry).val = val
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&lruEntry{key: key, val: val})
	c.m[key] = el
	if c.ll.Len() > c.max {
		last := c.ll.Back()
		if last != nil {
			c.ll.Remove(last)
			delete(c.m, last.Value.(*lruEntry).key)
		}
	}
}

func (c *lruLabels) get(key string) (pathLabel, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*lruEntry).val, true
	}
	return pathLabel{}, false
}

func (c *lruLabels) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
