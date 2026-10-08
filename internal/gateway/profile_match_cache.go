// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

// profileMatchCacheSize bounds the memoised decisions of one profile set. The
// directory cache holds up to 4,096 accounts, and each account asks for a
// handful of (connector, agent) combinations.
const profileMatchCacheSize = 8192

// profileMatchCache memoises guardrailProfileSet.match. The decision is a pure
// function of the set and the match inputs (the verified subject, where it came
// from, the connector and the agent), and walking 2,000 assignments against
// every group of an account takes from 130 us (3 groups) to 13 ms (400 groups)
// -- twice per hook, since the hook resolves again once the agent identity is
// attached. The cache lives on the set, so a reload drops it with the set.
//
// Keys are SHA-256 digests of every input, so a hit can never return another
// subject's profile.
type profileMatchCache struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]profileDecision
	ring    [][sha256.Size]byte
	next    int
}

func newProfileMatchCache() *profileMatchCache {
	return &profileMatchCache{
		entries: make(map[[sha256.Size]byte]profileDecision, 256),
		ring:    make([][sha256.Size]byte, 0, profileMatchCacheSize),
	}
}

// profileMatchKey digests the inputs of match with length prefixes, so no two
// different inputs share a key.
func profileMatchKey(subject *profileSubject, source, connectorName, agent string) [sha256.Size]byte {
	h := sha256.New()
	var n [8]byte
	put := func(s string) {
		binary.LittleEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	put(source)
	put(connectorName)
	put(agent)
	if subject == nil {
		put("\x00nil")
	} else {
		put("subject")
		put(subject.UserID)
		put(subject.IDKind)
		put(subject.UserName)
		put(subject.Principal)
		put(subject.UPN)
		put(subject.Domain)
		put(subject.AccountDomain)
		if subject.LookupFailed {
			put("lookup-failed")
		} else {
			put("lookup-ok")
		}
		binary.LittleEndian.PutUint64(n[:], uint64(len(subject.Groups)))
		h.Write(n[:])
		for _, g := range subject.Groups {
			put(g)
		}
	}
	var key [sha256.Size]byte
	h.Sum(key[:0])
	return key
}

func (c *profileMatchCache) get(key [sha256.Size]byte) (profileDecision, bool) {
	c.mu.Lock()
	d, ok := c.entries[key]
	c.mu.Unlock()
	return d, ok
}

func (c *profileMatchCache) put(key [sha256.Size]byte, d profileDecision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; ok {
		return
	}
	if len(c.ring) < profileMatchCacheSize {
		c.ring = append(c.ring, key)
	} else {
		delete(c.entries, c.ring[c.next])
		c.ring[c.next] = key
		c.next = (c.next + 1) % profileMatchCacheSize
	}
	c.entries[key] = d
}
