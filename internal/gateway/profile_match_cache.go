// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"
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
	entries map[[sha256.Size]byte]profileMatchEntry
	ring    [][sha256.Size]byte
	next    int
}

// profileMatchEntry is one memoised decision and the uid or SID it was made
// for, so forgetUser can drop one account's decisions.
type profileMatchEntry struct {
	decision profileDecision
	userID   string
}

func newProfileMatchCache() *profileMatchCache {
	return &profileMatchCache{
		entries: make(map[[sha256.Size]byte]profileMatchEntry, 256),
		ring:    make([][sha256.Size]byte, 0, profileMatchCacheSize),
	}
}

// profileMatchKey digests the inputs of match with length prefixes, so no two
// different inputs share a key.
func profileMatchKey(subject *profileSubject, source, connectorName string, scans []string, path profilePath, agent string) [sha256.Size]byte {
	h := sha256.New()
	var n [8]byte
	put := func(s string) {
		binary.LittleEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	put(source)
	put(connectorName)
	put(strconv.Itoa(len(scans)))
	for _, scan := range scans {
		put(scan)
	}
	// An uncertain profile is covered per request path (provenProfileCovers).
	put(strconv.Itoa(int(path)))
	put(agent)
	putSubject := func(subject *profileSubject) {
		put("subject")
		put(subject.UserID)
		put(subject.IDKind)
		put(subject.UserName)
		put(subject.Principal)
		put(subject.UPN)
		put(subject.Domain)
		put(subject.AccountDomain)
		// A local account and a directory account of one name select apart
		// (GAP-0305), as do a confirmed and an unconfirmed name.
		put(string(subject.Directory))
		if subject.localAccount {
			put("local-account")
		}
		if subject.nameUnconfirmed {
			put("name-unconfirmed")
		}
		if subject.LookupFailed {
			put("lookup-failed")
		} else {
			put("lookup-ok")
		}
		if subject.GroupsUnknown {
			put("groups-unknown")
		}
		binary.LittleEndian.PutUint64(n[:], uint64(len(subject.Groups)))
		h.Write(n[:])
		for _, g := range subject.Groups {
			put(g)
		}
		// The incarnation names the account the last proven profile is kept
		// for (provenProfileStore).
		put(subject.accountToken)
	}
	if subject == nil {
		put("\x00nil")
	} else {
		putSubject(subject)
	}
	var key [sha256.Size]byte
	h.Sum(key[:0])
	return key
}

func (c *profileMatchCache) get(key [sha256.Size]byte) (profileDecision, bool) {
	c.mu.Lock()
	e, ok := c.entries[key]
	c.mu.Unlock()
	return e.decision, ok
}

// put memoises d for key; userID is the uid or SID of the subject.
func (c *profileMatchCache) put(key [sha256.Size]byte, userID string, d profileDecision) {
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
	c.entries[key] = profileMatchEntry{decision: d, userID: userID}
}

// forgetUser drops every decision memoised for userID (a uid or SID), so the
// account's next request is decided afresh: `enterprise identity refresh`
// calls it for each account whose profile changed. The digest key already
// changes with the facts; this also covers inputs it does not hold. A ring
// slot of a dropped key stays and later evicts nothing, or a re-memoised
// copy of the same key early, which only costs a recomputation.
func (c *profileMatchCache) forgetUser(userID string) int {
	if c == nil || userID == "" {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	dropped := 0
	for key, entry := range c.entries {
		if entry.userID == userID {
			delete(c.entries, key)
			dropped++
		}
	}
	return dropped
}
