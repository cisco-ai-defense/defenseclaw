// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Standalone Windows matches group assignments on SIDs (GAP-0860).
//
// A Windows subject carries each group as its SID, and as DOMAIN\name only
// when the SID-to-name lookup answered in time. That lookup (LookupAccountSid)
// cannot be cancelled: a domain controller that stalled eight of them kept
// every later group a bare SID, so an assignment that names the group missed
// and the user got the default profile. Each group name an assignment writes
// is therefore resolved to its SID once per profile set, that is once per
// configuration generation (a reload builds a new set), and the decision
// compares the SIDs of the caller token only. A name that does not resolve
// selects nobody; explain, status and doctor name it, and requests retry it
// at most once a minute without waiting for the answer. A name that resolved
// is looked up again once a minute too: a local group deleted and recreated
// under the same name gets a new SID, and the set kept the deleted one, so
// the recreated group selected nobody until the gateway restarted
// (GAP-1144). The SID-to-name lookups stay, for display and telemetry only.

const (
	// profileGroupSIDWait bounds how long building a profile set waits for
	// the assignment group names to resolve.
	profileGroupSIDWait = 3 * time.Second
	// profileGroupSIDRetryInterval spaces the retries of a name that did not
	// resolve.
	profileGroupSIDRetryInterval = time.Minute
	// profileGroupSIDRecheckInterval spaces the lookups of a name that has
	// resolved, so a deleted or recreated group is followed.
	profileGroupSIDRecheckInterval = time.Minute
	// A hook waits briefly for a due retry, so a recovered directory can
	// select the assignment on that hook without waiting indefinitely on LSA.
	profileGroupSIDRetryWait = 200 * time.Millisecond
	// profileGroupSIDLookupsMax bounds the name lookups outstanding at once
	// across every profile set: the OS never abandons a stalled lookup, so
	// reloads must not pile them up.
	profileGroupSIDLookupsMax = 256
	// profileGroupSIDLocalLookupsMax bounds the lookups of this computer's
	// own groups (.\name, COMPUTER\name, BUILTIN\name, and a bare name
	// while it is looked up among them) apart from the rest. The LSA answers
	// those from the local account database, so lookups a stalled domain
	// controller holds cannot use up their slots, and a reload that assigns
	// a local group still resolves it (GAP-1261).
	profileGroupSIDLocalLookupsMax = 64
)

// profileGroupLocalDomain is this computer's name, the domain of its own
// accounts and groups ("" where unknown). It is set on Windows.
var profileGroupLocalDomain = func() string { return "" }

// profileGroupLocalName reports whether an assignment group name names a
// group of this computer.
func profileGroupLocalName(name string) bool {
	domain, _, qualified := strings.Cut(strings.TrimSpace(name), `\`)
	if !qualified {
		return false
	}
	if domain == "." || strings.EqualFold(domain, "BUILTIN") {
		return true
	}
	computer := strings.TrimSpace(profileGroupLocalDomain())
	return computer != "" && strings.EqualFold(domain, computer)
}

// profileGroupBareName reports whether an assignment group name has no
// domain part.
func profileGroupBareName(name string) bool {
	return !strings.ContainsAny(strings.TrimSpace(name), `\@`)
}

// errProfileGroupUnknown is the answer of profileGroupSIDLookup for a name
// that maps to no group.
var errProfileGroupUnknown = errors.New("no group of that name")

// errProfileGroupLookupsFull is the answer for a bare name that is no group
// of this computer while every directory lookup slot is in use; the name is
// tried again on the next request.
var errProfileGroupLookupsFull = errors.New("every directory lookup is in use")

// profileGroupSIDLookup resolves an assignment group name to its SID
// (LookupAccountName). It is set on Windows only.
var profileGroupSIDLookup func(name string) (string, error)

// profileGroupLocalSIDLookup resolves a bare group name among this
// computer's own groups only (BUILTIN, then its account database), which the
// LSA answers without a domain controller; errProfileGroupUnknown when none
// of them has the name. The LSA looks a bare name up in that order before
// it asks a domain, so a bare name is first looked up in the local lane and
// moves to the directory lane only when it is no group of this computer: a
// stalled domain controller kept a bare local group without a SID
// (GAP-1261). It is set on Windows only.
var profileGroupLocalSIDLookup func(name string) (string, error)

// profileGroupSIDLookupCall is one name lookup in flight. Profile sets that
// name the same group share it.
type profileGroupSIDLookupCall struct {
	done chan struct{}
	sid  string
	err  error
	// local is whether the call holds a slot of the local lane; it is read
	// and written under profileGroupSIDLookups.
	local bool
}

var profileGroupSIDLookups = struct {
	sync.Mutex
	calls map[string]*profileGroupSIDLookupCall
	// local counts the calls in flight for groups of this computer.
	local int
}{calls: map[string]*profileGroupSIDLookupCall{}}

// startProfileGroupSIDLookup returns the lookup in flight for name, starting
// one if none is (a bare name with localLookup first among this computer's
// groups); nil when the lane of name is full: profileGroupSIDLookupsMax
// lookups of directory names, or profileGroupSIDLocalLookupsMax of this
// computer's groups, are outstanding.
func startProfileGroupSIDLookup(lookup, localLookup func(string) (string, error), name string) *profileGroupSIDLookupCall {
	key := foldKey(name)
	localFirst := localLookup != nil && profileGroupBareName(name)
	local := localFirst || profileGroupLocalName(name)
	lookups := &profileGroupSIDLookups
	lookups.Lock()
	defer lookups.Unlock()
	if call, ok := lookups.calls[key]; ok {
		return call
	}
	if local && lookups.local >= profileGroupSIDLocalLookupsMax ||
		!local && len(lookups.calls)-lookups.local >= profileGroupSIDLookupsMax {
		return nil
	}
	call := &profileGroupSIDLookupCall{done: make(chan struct{}), local: local}
	lookups.calls[key] = call
	if local {
		lookups.local++
	}
	go func() {
		var sid string
		var err error
		if localFirst {
			sid, err = localLookup(name)
			if errors.Is(err, errProfileGroupUnknown) {
				// No group of this computer: the LSA asks the domain next,
				// so the name moves to the directory lane.
				sid, err = "", errProfileGroupLookupsFull
				lookups.Lock()
				moved := len(lookups.calls)-lookups.local < profileGroupSIDLookupsMax
				if moved {
					lookups.local--
					call.local = false
				}
				lookups.Unlock()
				if moved {
					sid, err = lookup(name)
				}
			}
		} else {
			sid, err = lookup(name)
		}
		call.sid, call.err = strings.ToUpper(strings.TrimSpace(sid)), err
		if call.err == nil && !strings.HasPrefix(call.sid, "S-1-") {
			call.sid, call.err = "", errProfileGroupUnknown
		}
		lookups.Lock()
		delete(lookups.calls, key)
		if call.local {
			lookups.local--
		}
		lookups.Unlock()
		close(call.done)
	}()
	return call
}

// profileGroupSIDs holds the SID of every group name the assignments of one
// profile set write.
type profileGroupSIDs struct {
	// lookup resolves any name, localLookup a bare name among this
	// computer's groups only (nil: bare names take the directory lane).
	lookup, localLookup func(string) (string, error)
	mu                  sync.Mutex
	// entries is keyed by the folded name.
	entries map[string]*profileGroupSIDEntry
	// unresolved counts the entries without a SID, so a request skips the
	// lock once every name has resolved; generation counts the SIDs learned
	// after the set was built, and keys the decisions memoised before them
	// apart from those after.
	unresolved atomic.Int64
	generation atomic.Uint64
	// nextCheck is when (UnixNano) the next re-check of resolved names is
	// due, so a request skips the lock until then.
	nextCheck atomic.Int64
	// inflight counts the entries with a lookup in flight. A re-check that
	// finishes after its hook stopped waiting is absorbed by the next
	// request, not a minute later at the next re-check (GAP-1509).
	inflight atomic.Int64
}

type profileGroupSIDEntry struct {
	name           string
	sid            string
	err            error
	call           *profileGroupSIDLookupCall
	nextTry        time.Time
	retryWaitUntil time.Time
	// checkAt is when a resolved name is looked up again; lostSID is the
	// SID a name had before the group was deleted.
	checkAt time.Time
	lostSID string
}

// buildProfileGroupSIDs resolves the group names of assignments, waiting at
// most wait for them. SIDs need no lookup; numeric names still require one.
func buildProfileGroupSIDs(assignments []config.ProfileAssignment, lookup, localLookup func(string) (string, error), wait time.Duration) *profileGroupSIDs {
	s := &profileGroupSIDs{lookup: lookup, localLookup: localLookup, entries: map[string]*profileGroupSIDEntry{}}
	now := time.Now()
	for _, assignment := range assignments {
		for _, group := range assignment.Match.Groups {
			name := norm.NFC.String(strings.TrimSpace(group))
			if !profileGroupNeedsSID(name) {
				continue
			}
			key := foldKey(name)
			if _, seen := s.entries[key]; seen {
				continue
			}
			entry := &profileGroupSIDEntry{name: name, nextTry: now.Add(profileGroupSIDRetryInterval)}
			if entry.call = startProfileGroupSIDLookup(lookup, localLookup, name); entry.call == nil {
				entry.nextTry = now
			}
			s.entries[key] = entry
		}
	}
	s.unresolved.Store(int64(len(s.entries)))
	s.nextCheck.Store(now.Add(profileGroupSIDRecheckInterval).UnixNano())
	s.countInflightLocked()
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for _, entry := range s.entries {
		if entry.call == nil {
			continue
		}
		select {
		case <-entry.call.done:
		case <-deadline.C:
			s.absorb(now)
			return s
		}
	}
	s.absorb(now)
	return s
}

// profileGroupNeedsSID reports whether an assignment group is a name to
// resolve rather than a SID.
func profileGroupNeedsSID(group string) bool {
	return group != "" && !strings.HasPrefix(strings.ToUpper(group), "S-1-")
}

// refresh absorbs completed lookups and starts retries that are due. Hooks
// share a short wait for an in-flight retry before matching and memoising a
// decision; a stalled LSA call never holds the request indefinitely.
func (s *profileGroupSIDs) refresh(now time.Time, wait bool) {
	if s == nil {
		return
	}
	recheck := now.UnixNano() >= s.nextCheck.Load()
	if s.unresolved.Load() == 0 && !recheck && s.inflight.Load() == 0 {
		return
	}
	s.mu.Lock()
	s.absorbLocked(now)
	if recheck {
		s.nextCheck.Store(now.Add(profileGroupSIDRecheckInterval).UnixNano())
	}
	var pending []*profileGroupSIDLookupCall
	var waitUntil time.Time
	for _, entry := range s.entries {
		if entry.sid == "" && entry.call == nil && !now.Before(entry.nextTry) {
			entry.call = startProfileGroupSIDLookup(s.lookup, s.localLookup, entry.name)
			entry.nextTry = now.Add(profileGroupSIDRetryInterval)
			if entry.call != nil {
				entry.retryWaitUntil = now.Add(profileGroupSIDRetryWait)
			}
		}
		if recheck && entry.sid != "" && entry.call == nil && !now.Before(entry.checkAt) {
			entry.call = startProfileGroupSIDLookup(s.lookup, s.localLookup, entry.name)
			entry.checkAt = now.Add(profileGroupSIDRecheckInterval)
			if entry.call != nil {
				entry.retryWaitUntil = now.Add(profileGroupSIDRetryWait)
			}
		}
		if entry.call != nil && now.Before(entry.retryWaitUntil) {
			pending = append(pending, entry.call)
			if entry.retryWaitUntil.After(waitUntil) {
				waitUntil = entry.retryWaitUntil
			}
		}
	}
	s.countInflightLocked()
	s.mu.Unlock()
	if !wait || len(pending) == 0 {
		return
	}
	remaining := time.Until(waitUntil)
	if remaining > 0 {
		deadline := time.NewTimer(remaining)
	waitForRetry:
		for _, call := range pending {
			select {
			case <-call.done:
			case <-deadline.C:
				break waitForRetry
			}
		}
		deadline.Stop()
	}
	s.absorb(time.Now())
}

func (s *profileGroupSIDs) absorb(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.absorbLocked(now)
}

func (s *profileGroupSIDs) absorbLocked(now time.Time) {
	for _, entry := range s.entries {
		if entry.call == nil {
			continue
		}
		select {
		case <-entry.call.done:
		default:
			continue
		}
		sid, err := entry.call.sid, entry.call.err
		entry.call, entry.retryWaitUntil = nil, time.Time{}
		if entry.sid != "" {
			// A re-check of a name that resolved: follow a recreated group's
			// new SID, and drop the SID of a deleted one. A failed lookup
			// keeps the SID.
			switch {
			case sid != "" && sid != entry.sid:
				entry.sid, entry.err = sid, nil
				s.generation.Add(1)
			case errors.Is(err, errProfileGroupUnknown):
				entry.lostSID, entry.sid, entry.err = entry.sid, "", err
				entry.nextTry = now.Add(profileGroupSIDRetryInterval)
				s.unresolved.Add(1)
				s.generation.Add(1)
			}
			continue
		}
		entry.sid, entry.err = sid, err
		switch {
		case entry.sid != "":
			entry.lostSID = ""
			entry.checkAt = now.Add(profileGroupSIDRecheckInterval)
			s.unresolved.Add(-1)
			s.generation.Add(1)
		case errors.Is(err, errProfileGroupLookupsFull):
			// As when no slot was free to start it: the next request tries.
			entry.nextTry = now
		default:
			entry.nextTry = now.Add(profileGroupSIDRetryInterval)
		}
	}
	s.countInflightLocked()
}

// countInflightLocked records how many entries have a lookup in flight.
func (s *profileGroupSIDs) countInflightLocked() {
	var n int64
	for _, entry := range s.entries {
		if entry.call != nil {
			n++
		}
	}
	s.inflight.Store(n)
}

// sid returns the SID of an assignment group name, or false while it has none
// or the set keeps no SIDs (nil: any set but a standalone Windows one).
func (s *profileGroupSIDs) sid(name string) (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight.Load() > 0 {
		s.absorbLocked(time.Now())
	}
	entry, ok := s.entries[foldKey(norm.NFC.String(strings.TrimSpace(name)))]
	if !ok || entry.sid == "" {
		return "", false
	}
	return entry.sid, true
}

// unresolvedAny reports whether a group name of entries that matches by its
// SID has none yet for a reason other than that no such group exists: its
// lookup is in flight or failed. Such a name may name one of the token's
// groups (GAP-0487). false for a set that keeps no SIDs.
func (s *profileGroupSIDs) unresolvedAny(entries []string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inflight.Load() > 0 {
		s.absorbLocked(time.Now())
	}
	for _, name := range entries {
		if !profileGroupNeedsSID(name) {
			continue
		}
		entry, ok := s.entries[foldKey(norm.NFC.String(strings.TrimSpace(name)))]
		if ok && entry.sid == "" && !errors.Is(entry.err, errProfileGroupUnknown) {
			return true
		}
	}
	return false
}

// matchKey keys a memoised decision by the SIDs known when it was made.
func (s *profileGroupSIDs) matchKey(key [sha256.Size]byte) [sha256.Size]byte {
	var generation [8]byte
	binary.LittleEndian.PutUint64(generation[:], s.generation.Load())
	return sha256.Sum256(append(key[:], generation[:]...))
}

// warnings names each assignment group that has no SID, other than a group
// the host does not know, which unknownGroupWarnings reports. Lookups that
// finished since the last request are taken in first: status and doctor
// kept naming a group as unresolved after its lookup had answered, until a
// hook call took the answer in (GAP-1142).
func (s *profileGroupSIDs) warnings(assignments []config.ProfileAssignment) []string {
	if s == nil || s.unresolved.Load() == 0 && s.inflight.Load() == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.absorbLocked(time.Now())
	if s.unresolved.Load() == 0 {
		return nil
	}
	var out []string
	for i, assignment := range assignments {
		for _, group := range assignment.Match.Groups {
			name := norm.NFC.String(strings.TrimSpace(group))
			entry, ok := s.entries[foldKey(name)]
			if ok && entry.sid == "" && entry.lostSID != "" && errors.Is(entry.err, errProfileGroupUnknown) {
				out = append(out, fmt.Sprintf("assignment %d: group %q no longer exists (its SID %s was deleted), so it selects nobody; "+
					"DefenseClaw looks the name up again every minute and follows a group recreated under it", i+1, strings.TrimSpace(group), entry.lostSID))
				continue
			}
			if !ok || entry.sid != "" || errors.Is(entry.err, errProfileGroupUnknown) {
				continue
			}
			reason := "the directory has not answered"
			if entry.err != nil {
				reason = entry.err.Error()
			}
			out = append(out, fmt.Sprintf("assignment %d: group %q has no SID yet (%s), so it selects nobody; "+
				"DefenseClaw retries it every minute, or name the group by its SID", i+1, strings.TrimSpace(group), reason))
		}
	}
	return out
}
