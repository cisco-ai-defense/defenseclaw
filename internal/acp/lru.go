// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import "container/list"

// lruMap is a map that keeps at most max entries and drops the least
// recently used one to take a new one. It is not safe for concurrent use:
// the proxy state holds its own lock around it.
type lruMap[V any] struct {
	max     int
	entries map[string]*list.Element
	order   *list.List // front is the most recently used
}

type lruEntry[V any] struct {
	key   string
	value V
}

func newLRUMap[V any](max int) *lruMap[V] {
	return &lruMap[V]{max: max, entries: map[string]*list.Element{}, order: list.New()}
}

// get returns the value of key and marks it used.
func (m *lruMap[V]) get(key string) (V, bool) {
	element, ok := m.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	m.order.MoveToFront(element)
	return element.Value.(*lruEntry[V]).value, true
}

// has reports that key is held, without marking it used.
func (m *lruMap[V]) has(key string) bool {
	_, ok := m.entries[key]
	return ok
}

// put stores value under key and marks it used. A full map drops its least
// recently used entry first.
func (m *lruMap[V]) put(key string, value V) {
	if element, ok := m.entries[key]; ok {
		element.Value.(*lruEntry[V]).value = value
		m.order.MoveToFront(element)
		return
	}
	for len(m.entries) >= m.max && m.order.Len() > 0 {
		oldest := m.order.Back()
		delete(m.entries, oldest.Value.(*lruEntry[V]).key)
		m.order.Remove(oldest)
	}
	m.entries[key] = m.order.PushFront(&lruEntry[V]{key: key, value: value})
}

func (m *lruMap[V]) len() int { return len(m.entries) }
