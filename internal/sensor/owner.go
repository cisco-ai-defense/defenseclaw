// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// How a finding was tied to an account (Finding.Attribution).
const (
	// AttributionProcessOwner is the owner the process probe read: the
	// process token, the Win32_Process owner, or the POSIX process owner.
	AttributionProcessOwner = "process_owner"
	// AttributionSession is the user signed in to the Windows session the
	// process runs in.
	AttributionSession = "session"
	// AttributionEnrolledProfile is the enrolled account whose profile holds
	// the configuration files the agent wrote.
	AttributionEnrolledProfile = "enrolled_profile"
	// AttributionUnattributed is a host-wide finding no lookup could tie to
	// an account. It is never filled in with another account's identity.
	AttributionUnattributed = "unattributed"
)

// Account is one enrolled account of the enrolled-user table.
type Account struct {
	// Name is DOMAIN\name, or COMPUTER\name for a local Windows account.
	Name string
	SID  string
	// Home is the account's profile folder.
	Home string
}

// OwnerLookups are the account sources consulted after the owner the
// process probe read itself. A nil lookup is skipped.
type OwnerLookups struct {
	// SessionUser names the account signed in to a Windows session, or
	// returns empty strings.
	SessionUser func(session uint32) (name, sid string)
	// Accounts returns the enrolled-user table.
	Accounts func() []Account
}

// owner is the account a finding is attributed to, or why it is not.
type owner struct {
	User, SID, Attribution, Reason string
}

// procRef is a finding's reference to one process instance and when the
// finding last saw it.
type procRef struct {
	PID int
	// Start is when the process was created, zero when unknown.
	Start time.Time
	// Name is the image name, empty when unknown.
	Name string
	// At is when the finding last saw the process.
	At time.Time
}

// processInstance is what the polls recorded about one process instance.
// Its owner is snapshotted while the process is alive and kept after it
// exits: looked up later by pid in the current process table, the owner
// would be that of whatever process holds the number by then (GAP-1372).
type processInstance struct {
	started                 time.Time
	name                    string
	user, sid               string
	sessionUser, sessionSID string
	lastSeen                time.Time
}

const (
	// instanceStartTolerance is how far apart two readings of one
	// process's start may be: an exec event's time and the kernel's
	// creation time agree to well under a second.
	instanceStartTolerance = 2 * time.Second
	// maxOwnerInstances bounds the book under process churn.
	maxOwnerInstances = 40000
	// minOwnerRetention keeps an exited process's owner at least as long
	// as the lineage tracker keeps its ancestry.
	minOwnerRetention = 30 * time.Minute
)

// ownerBook remembers the owner of every process instance the polls have
// seen, for as long as a finding can still refer to it. Instances are
// filed by pid and told apart by start time, so a process that reuses an
// exited process's pid has its own entry and never lends its owner to the
// exited process's findings.
type ownerBook struct {
	lookups OwnerLookups
	retain  time.Duration
	byPID   map[int][]*processInstance
	count   int
}

func newOwnerBook(lookups OwnerLookups, retain time.Duration) *ownerBook {
	return &ownerBook{lookups: lookups, retain: max(retain, minOwnerRetention), byPID: map[int][]*processInstance{}}
}

// observe records one poll's process table at now. The owner the probe
// read is taken the first time an instance shows one; the user signed in to
// the instance's Windows session is read while the instance is alive,
// because a session id is reused by the next sign-in too.
func (b *ownerBook) observe(processes []procprobe.Process, now time.Time) {
	sessions := map[uint32][2]string{}
	for _, process := range processes {
		if process.PID <= 0 {
			continue
		}
		instance := b.liveInstance(process)
		if instance == nil {
			instance = &processInstance{started: process.StartedAt, name: process.Name}
			b.byPID[process.PID] = append(b.byPID[process.PID], instance)
			b.count++
		}
		if instance.started.IsZero() {
			instance.started = process.StartedAt
		}
		instance.lastSeen = now
		if instance.sid != "" || instance.user != "" {
			continue
		}
		if process.UserSID != "" || process.User != "" {
			instance.user, instance.sid = process.User, process.UserSID
			continue
		}
		if instance.sessionSID != "" || process.SessionID == 0 || b.lookups.SessionUser == nil {
			continue
		}
		found, ok := sessions[process.SessionID]
		if !ok {
			name, sid := b.lookups.SessionUser(process.SessionID)
			found = [2]string{name, sid}
			sessions[process.SessionID] = found
		}
		instance.sessionUser, instance.sessionSID = found[0], found[1]
	}
	b.prune(now)
}

// liveInstance is the recorded instance a process-table row continues.
func (b *ownerBook) liveInstance(process procprobe.Process) *processInstance {
	var found *processInstance
	for _, instance := range b.byPID[process.PID] {
		same := sameImage(instance.name, process.Name)
		if !instance.started.IsZero() && !process.StartedAt.IsZero() {
			same = closeStarts(instance.started, process.StartedAt)
		}
		if same && (found == nil || instance.lastSeen.After(found.lastSeen)) {
			found = instance
		}
	}
	return found
}

func (b *ownerBook) prune(now time.Time) {
	cutoff := now.Add(-b.retain)
	var idle []*processInstance
	for pid, instances := range b.byPID {
		kept := instances[:0]
		for _, instance := range instances {
			if instance.lastSeen.Before(cutoff) {
				b.count--
				continue
			}
			kept = append(kept, instance)
			if b.count > maxOwnerInstances && instance.lastSeen.Before(now) {
				idle = append(idle, instance)
			}
		}
		if len(kept) == 0 {
			delete(b.byPID, pid)
		} else {
			b.byPID[pid] = kept
		}
	}
	if b.count <= maxOwnerInstances || len(idle) == 0 {
		return
	}
	// Over the bound: forget the exited instances seen longest ago.
	sort.Slice(idle, func(i, j int) bool { return idle[i].lastSeen.Before(idle[j].lastSeen) })
	drop := make(map[*processInstance]bool, b.count-maxOwnerInstances)
	for _, instance := range idle[:min(len(idle), b.count-maxOwnerInstances)] {
		drop[instance] = true
	}
	for pid, instances := range b.byPID {
		kept := instances[:0]
		for _, instance := range instances {
			if drop[instance] {
				b.count--
				continue
			}
			kept = append(kept, instance)
		}
		if len(kept) == 0 {
			delete(b.byPID, pid)
		} else {
			b.byPID[pid] = kept
		}
	}
}

// instance is the recorded process instance ref names. reused reports that
// the pid is on record only for other processes: the one the finding saw
// exited and its number was handed on.
//
// With both start times known the start decides. Otherwise the instance
// must carry the same image name and must not have started after the
// finding last saw its process; a pid that cannot be tied to the exact
// instance names nobody.
func (b *ownerBook) instance(ref procRef) (found *processInstance, reused bool) {
	candidates := b.byPID[ref.PID]
	for _, candidate := range candidates {
		if !refMatches(candidate, ref) {
			continue
		}
		if found == nil || candidate.started.After(found.started) ||
			(candidate.started.Equal(found.started) && candidate.lastSeen.After(found.lastSeen)) {
			found = candidate
		}
	}
	return found, found == nil && len(candidates) > 0
}

func refMatches(instance *processInstance, ref procRef) bool {
	if !ref.Start.IsZero() && !instance.started.IsZero() {
		return closeStarts(ref.Start, instance.started)
	}
	if !sameImage(ref.Name, instance.name) {
		return false
	}
	return instance.started.IsZero() || ref.At.IsZero() ||
		!instance.started.After(ref.At.Add(instanceStartTolerance))
}

func closeStarts(a, b time.Time) bool {
	delta := a.Sub(b)
	return delta <= instanceStartTolerance && delta >= -instanceStartTolerance
}

// sameImage compares executable names as the probes report them: Windows
// names without case or the .exe suffix, and a Linux comm cut at 15 bytes
// as a prefix of the full name. An empty name matches nothing.
func sameImage(a, b string) bool {
	a = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), ".exe")
	b = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(b)), ".exe")
	if a == "" || b == "" {
		return false
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	return a == b || (len(a) >= 15 && strings.HasPrefix(b, a))
}

// ownerResolver attributes the findings of one poll from the owner book.
// None of its lookups needs more than the gateway service already has: the
// managed Windows service account holds only SeChangeNotifyPrivilege, and
// nothing here widens an ACL to make a lookup succeed.
type ownerResolver struct {
	book     *ownerBook
	accounts []Account
}

func (b *ownerBook) resolver() *ownerResolver {
	resolver := &ownerResolver{book: b}
	if b.lookups.Accounts != nil {
		resolver.accounts = b.lookups.Accounts()
	}
	return resolver
}

// resolve attributes a finding whose process instances are processes (the
// finding's own process first, then the rest of its agent session) and
// whose agent wrote configPaths. In order: (a) the owner the probe read for
// one of the instances, (b) the user signed in to the Windows session one
// of them ran in, (c) the one enrolled account whose profile holds the
// agent's configuration files. A finding none of them names is
// unattributed and host-wide.
func (r *ownerResolver) resolve(processes []procRef, configPaths []string) owner {
	var matched []*processInstance
	reused := false
	for _, ref := range processes {
		instance, recycled := r.book.instance(ref)
		if instance != nil {
			matched = append(matched, instance)
		}
		reused = reused || recycled
	}
	for _, instance := range matched {
		if instance.sid != "" || instance.user != "" {
			return r.named(instance.user, instance.sid, AttributionProcessOwner)
		}
	}
	for _, instance := range matched {
		if instance.sessionSID != "" {
			return r.named(instance.sessionUser, instance.sessionSID, AttributionSession)
		}
	}
	if found, ok := r.profileOwner(configPaths); ok {
		return found
	}
	reason := "the process owner could not be read (process token, Win32_Process owner and session user) " +
		"and no enrolled profile holds the agent's configuration"
	switch {
	case len(matched) == 0 && reused:
		reason = "the finding's processes have exited and their pids now belong to other processes, " +
			"whose owners are not the finding's; no enrolled profile holds the agent's configuration"
	case len(matched) == 0:
		reason = "the finding's processes are no longer in the process table " +
			"and no enrolled profile holds the agent's configuration"
	}
	return owner{Attribution: AttributionUnattributed, Reason: reason}
}

// named qualifies an owner with the enrolled table's DOMAIN\name for its
// SID, which also names an owner whose SID the LSA could not translate.
func (r *ownerResolver) named(user, sid, attribution string) owner {
	for _, account := range r.accounts {
		if sid != "" && account.Name != "" && strings.EqualFold(account.SID, sid) {
			user = account.Name
			break
		}
	}
	return owner{User: user, SID: sid, Attribution: attribution}
}

// profileOwner is the enrolled account whose profile holds the agent's
// configuration files. Paths in more than one profile name no account, and
// paths outside every profile (a project's AGENTS.md) say nothing.
func (r *ownerResolver) profileOwner(paths []string) (owner, bool) {
	var found *Account
	for _, path := range paths {
		account := r.accountForPath(path)
		switch {
		case account == nil:
			continue
		case found != nil && !strings.EqualFold(found.SID, account.SID):
			return owner{}, false
		}
		found = account
	}
	if found == nil || found.SID == "" {
		return owner{}, false
	}
	return owner{User: found.Name, SID: found.SID, Attribution: AttributionEnrolledProfile}, true
}

// accountForPath returns the account whose profile folder holds path, the
// deepest one when profiles nest. Comparison ignores case and separator
// style, as Windows paths do.
func (r *ownerResolver) accountForPath(path string) *Account {
	path = normalizeOwnerPath(path)
	var best *Account
	bestLength := 0
	for index := range r.accounts {
		home := strings.TrimRight(normalizeOwnerPath(r.accounts[index].Home), "/")
		if home == "" || len(home) <= bestLength {
			continue
		}
		if path == home || strings.HasPrefix(path, home+"/") {
			best, bestLength = &r.accounts[index], len(home)
		}
	}
	return best
}

func normalizeOwnerPath(path string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path), `\`, "/"))
}
