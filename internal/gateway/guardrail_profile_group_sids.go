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
// at most once a minute without waiting for the answer. The SID-to-name
// lookups stay, for display and telemetry only.

const (
	// profileGroupSIDWait bounds how long building a profile set waits for
	// the assignment group names to resolve.
	profileGroupSIDWait = 3 * time.Second
	// profileGroupSIDRetryInterval spaces the retries of a name that did not
	// resolve.
	profileGroupSIDRetryInterval = time.Minute
	// A hook waits briefly for a due retry, so a recovered directory can
	// select the assignment on that hook without waiting indefinitely on LSA.
	profileGroupSIDRetryWait = 200 * time.Millisecond
	// profileGroupSIDLookupsMax bounds the name lookups outstanding at once
	// across every profile set: the OS never abandons a stalled lookup, so
	// reloads must not pile them up.
	profileGroupSIDLookupsMax = 256
)

// errProfileGroupUnknown is the answer of profileGroupSIDLookup for a name
// that maps to no group.
var errProfileGroupUnknown = errors.New("no group of that name")

// profileGroupSIDLookup resolves an assignment group name to its SID
// (LookupAccountName). It is set on Windows only.
var profileGroupSIDLookup func(name string) (string, error)

// profileGroupSIDLookupCall is one name lookup in flight. Profile sets that
// name the same group share it.
type profileGroupSIDLookupCall struct {
	done chan struct{}
	sid  string
	err  error
}

var profileGroupSIDLookups = struct {
	sync.Mutex
	calls map[string]*profileGroupSIDLookupCall
}{calls: map[string]*profileGroupSIDLookupCall{}}

// startProfileGroupSIDLookup returns the lookup in flight for name, starting
// one if none is; nil when profileGroupSIDLookupsMax lookups are outstanding.
func startProfileGroupSIDLookup(lookup func(string) (string, error), name string) *profileGroupSIDLookupCall {
	key := foldKey(name)
	lookups := &profileGroupSIDLookups
	lookups.Lock()
	defer lookups.Unlock()
	if call, ok := lookups.calls[key]; ok {
		return call
	}
	if len(lookups.calls) >= profileGroupSIDLookupsMax {
		return nil
	}
	call := &profileGroupSIDLookupCall{done: make(chan struct{})}
	lookups.calls[key] = call
	go func() {
		sid, err := lookup(name)
		call.sid, call.err = strings.ToUpper(strings.TrimSpace(sid)), err
		if call.err == nil && !strings.HasPrefix(call.sid, "S-1-") {
			call.sid, call.err = "", errProfileGroupUnknown
		}
		lookups.Lock()
		delete(lookups.calls, key)
		lookups.Unlock()
		close(call.done)
	}()
	return call
}

// profileGroupSIDs holds the SID of every group name the assignments of one
// profile set write.
type profileGroupSIDs struct {
	lookup func(string) (string, error)
	mu     sync.Mutex
	// entries is keyed by the folded name.
	entries map[string]*profileGroupSIDEntry
	// unresolved counts the entries without a SID, so a request skips the
	// lock once every name has resolved; generation counts the SIDs learned
	// after the set was built, and keys the decisions memoised before them
	// apart from those after.
	unresolved atomic.Int64
	generation atomic.Uint64
}

type profileGroupSIDEntry struct {
	name           string
	sid            string
	err            error
	call           *profileGroupSIDLookupCall
	nextTry        time.Time
	retryWaitUntil time.Time
}

// newProfileGroupSIDs resolves the group names of assignments, waiting at most
// wait for them. SIDs need no lookup; numeric names are no Windows group.
func newProfileGroupSIDs(assignments []config.ProfileAssignment, lookup func(string) (string, error), wait time.Duration) *profileGroupSIDs {
	s := &profileGroupSIDs{lookup: lookup, entries: map[string]*profileGroupSIDEntry{}}
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
			if entry.call = startProfileGroupSIDLookup(lookup, name); entry.call == nil {
				entry.nextTry = now
			}
			s.entries[key] = entry
		}
	}
	s.unresolved.Store(int64(len(s.entries)))
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
	return group != "" && !strings.HasPrefix(strings.ToUpper(group), "S-1-") && strings.Trim(group, "0123456789") != ""
}

// refresh absorbs completed lookups and starts retries that are due. Hooks
// share a short wait for an in-flight retry before matching and memoising a
// decision; a stalled LSA call never holds the request indefinitely.
func (s *profileGroupSIDs) refresh(now time.Time, wait bool) {
	if s == nil || s.unresolved.Load() == 0 {
		return
	}
	s.mu.Lock()
	s.absorbLocked(now)
	var pending []*profileGroupSIDLookupCall
	var waitUntil time.Time
	for _, entry := range s.entries {
		if entry.sid == "" && entry.call == nil && !now.Before(entry.nextTry) {
			entry.call = startProfileGroupSIDLookup(s.lookup, entry.name)
			entry.nextTry = now.Add(profileGroupSIDRetryInterval)
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
		entry.sid, entry.err, entry.call = entry.call.sid, entry.call.err, nil
		entry.retryWaitUntil = time.Time{}
		if entry.sid != "" {
			s.unresolved.Add(-1)
			s.generation.Add(1)
		} else {
			entry.nextTry = now.Add(profileGroupSIDRetryInterval)
		}
	}
}

// sid returns the SID of an assignment group name, or false while it has none.
func (s *profileGroupSIDs) sid(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[foldKey(norm.NFC.String(strings.TrimSpace(name)))]
	if !ok || entry.sid == "" {
		return "", false
	}
	return entry.sid, true
}

// matchKey keys a memoised decision by the SIDs known when it was made.
func (s *profileGroupSIDs) matchKey(key [sha256.Size]byte) [sha256.Size]byte {
	var generation [8]byte
	binary.LittleEndian.PutUint64(generation[:], s.generation.Load())
	return sha256.Sum256(append(key[:], generation[:]...))
}

// warnings names each assignment group that has no SID, other than a group
// the host does not know, which unknownGroupWarnings reports.
func (s *profileGroupSIDs) warnings(assignments []config.ProfileAssignment) []string {
	if s == nil || s.unresolved.Load() == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for i, assignment := range assignments {
		for _, group := range assignment.Match.Groups {
			name := norm.NFC.String(strings.TrimSpace(group))
			entry, ok := s.entries[foldKey(name)]
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
