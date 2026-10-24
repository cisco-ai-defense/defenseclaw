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
	"runtime"
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
	// Born is when the event that started the process was logged, and
	// Instance the lineage tracker's instance of it, each zero when unknown.
	// With Start unknown they are what ties the finding to one process
	// instance and not to a later one on the pid (GAP-1464).
	Born     time.Time
	Instance uint64
	// User and SID are the account the finding's own event named for the
	// process, empty when it named none.
	User, SID string
	// Descendant marks a process of an agent session other than its root.
	// It may run as another account (a setuid or runas child), so the owner
	// the probe read for it never names the session (GAP-1401).
	Descendant bool
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
	// session is the Windows session the instance runs in, zero when
	// unknown. A process never changes session.
	session uint32
	// firstSeen is the poll that recorded the instance, lastSeen the latest.
	firstSeen, lastSeen time.Time
	// replacedAt is the first exec or process creation the host plane saw
	// for the pid after the polls last saw this instance, and exitedAt the
	// first exit. From replacedAt on the pid may name another process, and
	// the start the lineage tracker reports for it may still be this
	// instance's: a Windows 4688 carries no creation time, so a pid whose
	// exit went unseen keeps its earlier holder's start (GAP-1403). Only a
	// poll that sees the instance again clears either.
	replacedAt, exitedAt time.Time
}

// pidEvent is a process creation (exec) or exit the host plane saw.
type pidEvent struct {
	At   time.Time
	Exit bool
	// Instance is the lineage tracker's instance the event concerned, zero
	// when the tracker had no record of the pid.
	Instance uint64
	// User and SID are the account a creation event named, empty when it
	// named none.
	User, SID string
}

// keepsOwner reports that a creation at the pid names, by name, the account
// recorded for instance, on a platform whose events and probes carry no SID
// (POSIX). A POSIX exec replaces the image of the same process, and even a
// new process on the pid would be that account's, so the recorded owner is
// still the one to report (GAP-1465). A creation that carries a SID (a
// Windows 4688), or names no account or another one, still hands the pid on.
func (event pidEvent) keepsOwner(instance *processInstance) bool {
	return !event.Exit && event.SID == "" && instance.sid == "" &&
		event.User != "" && instance.user != "" && strings.EqualFold(event.User, instance.user)
}

// pidEvents are the creations and exits the host plane saw since the owner
// book last took them. Overflow is when it stopped recording them under
// churn, zero when it did not, and Taken when the book took them.
type pidEvents struct {
	ByPID           map[int][]pidEvent
	Overflow, Taken time.Time
}

// timeSpan is a span in which the host plane recorded no creations or
// exits. A zero from is open towards the past and a zero to open towards
// the present.
type timeSpan struct {
	from, to time.Time
}

const (
	// instanceStartTolerance is how far apart two kernel start readings of
	// one process may be when they come from different sources (a process
	// probe and the lineage tracker's copy of an earlier poll).
	instanceStartTolerance = 2 * time.Second
	// sameReadingTolerance is how far apart two process-table readings of
	// one process's start may be once the pid was handed on: the probes
	// read the same kernel creation time each poll, while a process that
	// reused the pid within instanceStartTolerance has its own (GAP-1464).
	sameReadingTolerance = 10 * time.Millisecond
	// creationEventSkew is how far the logged time of a creation event may
	// lie from the kernel creation time of the process it reports: both are
	// read while the process is being created.
	creationEventSkew = 250 * time.Millisecond
	// maxOwnerInstances bounds the book under process churn, and
	// maxLifecycleHistory the creations and exits it keeps.
	maxOwnerInstances   = 40000
	maxLifecycleHistory = 4 * maxOwnerInstances
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
	// history is every creation and exit the host plane reported, by pid,
	// for as long as instances are kept, and lost the spans it reported
	// none: they tell whether a pid changed hands between a process's
	// creation and the first poll that saw a process on it (GAP-1464).
	history      map[int][]pidEvent
	historyCount int
	lost         []timeSpan
}

func newOwnerBook(lookups OwnerLookups, retain time.Duration) *ownerBook {
	return &ownerBook{
		lookups: lookups, retain: max(retain, minOwnerRetention),
		byPID: map[int][]*processInstance{}, history: map[int][]pidEvent{},
	}
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
		if instance != nil && instance.ownedByOther(process) {
			// Another account's process holds the pid now: it is a new
			// instance, and the recorded one names nothing after it.
			handedOn := now
			if process.StartedAt.After(instance.lastSeen) && process.StartedAt.Before(now) {
				handedOn = process.StartedAt
			}
			markFirst(&instance.replacedAt, handedOn)
			instance = nil
		}
		if instance == nil {
			instance = &processInstance{
				started: process.StartedAt, name: process.Name, session: process.SessionID, firstSeen: now,
			}
			b.byPID[process.PID] = append(b.byPID[process.PID], instance)
			b.count++
		}
		if instance.started.IsZero() {
			instance.started = process.StartedAt
		}
		if instance.session == 0 {
			instance.session = process.SessionID
		}
		instance.lastSeen = now
		instance.replacedAt, instance.exitedAt = time.Time{}, time.Time{}
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

// liveInstance is the recorded instance a process-table row continues. Once
// a creation or exit was seen for the pid only the start ties the row to the
// instance, and only as the same reading: the same image is no evidence after
// the pid was handed on, and a process that took the pid within
// instanceStartTolerance of the earlier holder's start is not it (GAP-1464).
func (b *ownerBook) liveInstance(process procprobe.Process) *processInstance {
	var found *processInstance
	for _, instance := range b.byPID[process.PID] {
		handedOn := !instance.replacedAt.IsZero() || !instance.exitedAt.IsZero()
		same := sameImage(instance.name, process.Name) && !handedOn
		if !instance.started.IsZero() && !process.StartedAt.IsZero() {
			tolerance := instanceStartTolerance
			if handedOn {
				tolerance = sameReadingTolerance
			}
			same = withinTolerance(instance.started, process.StartedAt, tolerance)
		}
		if same && (found == nil || instance.lastSeen.After(found.lastSeen)) {
			found = instance
		}
	}
	return found
}

// ownedByOther reports that a process-table row names another owner than the
// one recorded for the instance, or runs in another Windows session: the pid
// was handed on, whatever the start says (GAP-1464).
func (instance *processInstance) ownedByOther(process procprobe.Process) bool {
	if instance.session != 0 && process.SessionID != 0 && instance.session != process.SessionID {
		return true
	}
	if instance.sid != "" && process.UserSID != "" {
		return !strings.EqualFold(instance.sid, process.UserSID)
	}
	return instance.user != "" && process.User != "" && !strings.EqualFold(instance.user, process.User)
}

// markFirst keeps the earliest instant a pid was seen handed on or exited.
func markFirst(at *time.Time, when time.Time) {
	if at.IsZero() || when.Before(*at) {
		*at = when
	}
}

// heard files the host plane's creations and exits against the instances
// the polls last saw before them, so a pid handed on between two polls never
// lends the earlier holder's owner to what the new holder does. Past an
// overflow every instance the polls last saw before it counts as handed on.
// Every event is also kept in the history the instance lookup reads.
func (b *ownerBook) heard(events pidEvents) {
	for pid, seen := range events.ByPID {
		b.history[pid] = append(b.history[pid], seen...)
		b.historyCount += len(seen)
		for _, instance := range b.byPID[pid] {
			for _, event := range seen {
				switch {
				case !event.At.After(instance.lastSeen):
				case event.Exit:
					markFirst(&instance.exitedAt, event.At)
				case event.keepsOwner(instance):
				default:
					markFirst(&instance.replacedAt, event.At)
				}
			}
		}
	}
	if events.Overflow.IsZero() {
		return
	}
	b.lost = append(b.lost, timeSpan{from: events.Overflow, to: events.Taken})
	for _, instances := range b.byPID {
		for _, instance := range instances {
			if instance.lastSeen.Before(events.Overflow) {
				markFirst(&instance.replacedAt, events.Overflow)
			}
		}
	}
}

func (b *ownerBook) prune(now time.Time) {
	cutoff := now.Add(-b.retain)
	b.pruneHistory(cutoff)
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

// pruneHistory forgets the creations and exits before cutoff and, over the
// bound, the oldest ones; the span forgotten under the bound is recorded as
// lost, so no lookup reads its silence as proof.
func (b *ownerBook) pruneHistory(cutoff time.Time) {
	lost := b.lost[:0]
	for _, span := range b.lost {
		if span.to.IsZero() || !span.to.Before(cutoff) {
			lost = append(lost, span)
		}
	}
	b.lost = lost
	forget := func(before time.Time) {
		for pid, events := range b.history {
			kept := events[:0]
			for _, event := range events {
				if event.At.After(before) {
					kept = append(kept, event)
				}
			}
			b.historyCount -= len(events) - len(kept)
			if len(kept) == 0 {
				delete(b.history, pid)
			} else {
				b.history[pid] = kept
			}
		}
	}
	forget(cutoff.Add(-time.Nanosecond))
	if b.historyCount <= maxLifecycleHistory {
		return
	}
	times := make([]time.Time, 0, b.historyCount)
	for _, events := range b.history {
		for _, event := range events {
			times = append(times, event.At)
		}
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	newestForgotten := times[b.historyCount-maxLifecycleHistory-1]
	forget(newestForgotten)
	b.lost = append(b.lost, timeSpan{to: newestForgotten.Add(time.Nanosecond)})
}

// instance is the recorded process instance ref names. reused reports that
// the pid is on record only for other processes: the one the finding saw
// exited and its number was handed on.
//
// Nothing the finding saw once the pid was handed on is the instance. With
// both start times known the start decides. Otherwise the instance must not
// have exited before the finding saw its process, must carry the same image
// name, and must be proven to be the process: the finding read it from the
// poll that recorded the instance, or the instance started when the event
// that started the finding's process was logged and the pid did not change
// hands between that event and the poll that recorded the instance. A pid
// that cannot be tied to the exact instance names nobody (GAP-1464).
func (b *ownerBook) instance(ref procRef) (found *processInstance, reused bool) {
	candidates := b.byPID[ref.PID]
	for _, candidate := range candidates {
		if !b.refMatches(candidate, ref) {
			continue
		}
		if found == nil || closerInstance(candidate, found, ref) {
			found = candidate
		}
	}
	return found, found == nil && len(candidates) > 0
}

// closerInstance reports that candidate names ref better than found. With
// the starts known the nearer start wins, so a process that reused the pid
// within instanceStartTolerance never takes the earlier holder's findings
// (GAP-1464); otherwise the later start, then the later poll.
func closerInstance(candidate, found *processInstance, ref procRef) bool {
	reference := ref.Start
	if reference.IsZero() {
		reference = ref.Born
	}
	if !reference.IsZero() && !candidate.started.IsZero() && !found.started.IsZero() {
		if a, b := startDistance(candidate.started, reference), startDistance(found.started, reference); a != b {
			return a < b
		}
	}
	return candidate.started.After(found.started) ||
		(candidate.started.Equal(found.started) && candidate.lastSeen.After(found.lastSeen))
}

func (b *ownerBook) refMatches(instance *processInstance, ref procRef) bool {
	if !instance.replacedAt.IsZero() && (ref.At.IsZero() || !ref.At.Before(instance.replacedAt)) {
		return false
	}
	if !ref.Start.IsZero() && !instance.started.IsZero() {
		return closeStarts(ref.Start, instance.started)
	}
	if !instance.exitedAt.IsZero() && (ref.At.IsZero() || ref.At.After(instance.exitedAt)) {
		return false
	}
	if !sameImage(ref.Name, instance.name) {
		return false
	}
	if !ref.At.IsZero() && ref.At.Equal(instance.lastSeen) {
		// The finding read its process from the poll that recorded the
		// instance: it is that process-table row.
		return true
	}
	if ref.Born.IsZero() || instance.started.IsZero() ||
		!withinTolerance(instance.started, ref.Born, creationEventSkew) {
		return false
	}
	return !b.handedOnBetween(ref, instance.firstSeen)
}

// handedOnBetween reports that ref's pid may have changed hands after the
// event that started ref's process and by until: an exit, a creation of
// another instance, or a span the host plane recorded nothing in.
func (b *ownerBook) handedOnBetween(ref procRef, until time.Time) bool {
	for _, span := range b.lost {
		if !span.from.After(until) && (span.to.IsZero() || span.to.After(ref.Born)) {
			return true
		}
	}
	for _, event := range b.history[ref.PID] {
		if !event.At.After(ref.Born) || event.At.After(until) {
			continue
		}
		if event.Exit || ref.Instance == 0 || event.Instance != ref.Instance {
			return true
		}
	}
	return false
}

func closeStarts(a, b time.Time) bool {
	return withinTolerance(a, b, instanceStartTolerance)
}

func withinTolerance(a, b time.Time, tolerance time.Duration) bool {
	return startDistance(a, b) <= tolerance
}

func startDistance(a, b time.Time) time.Duration {
	if delta := a.Sub(b); delta >= 0 {
		return delta
	}
	return b.Sub(a)
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
// whose agent wrote configPaths. In order: (a) the account the finding's
// own events named for its processes, (b) the owner the probe read for one
// of the instances, (c) the user signed in to the Windows session one of
// them ran in, (d) the one enrolled account whose profile holds the agent's
// configuration files. A finding none of them names, or whose events name
// more than one account, is unattributed and host-wide.
func (r *ownerResolver) resolve(processes []procRef, configPaths []string) owner {
	if user, sid, mixed := eventOwner(processes); mixed {
		return owner{Attribution: AttributionUnattributed, Reason: "the finding's events name more than one account " +
			"for its processes (a pid was handed from one account's process to another's), so it names neither"}
	} else if sid != "" {
		return r.named(user, sid, AttributionProcessOwner)
	}
	var matched []*processInstance
	reused, descendants := false, false
	for _, ref := range processes {
		instance, recycled := r.book.instance(ref)
		switch {
		case instance == nil:
		case ref.Descendant:
			descendants = true
		default:
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
	reason := "the process owner could not be read (" + ownerSourcesFor(ownerGOOS) + ") " +
		"and no enrolled profile holds the agent's configuration"
	switch {
	case len(matched) == 0 && descendants:
		reason = "the agent's own process is no longer in the process table, the owner of a process it " +
			"started is not the session's, and no enrolled profile holds the agent's configuration"
	case len(matched) == 0 && reused:
		reason = "the finding's processes have exited and their pids now belong to other processes, " +
			"whose owners are not the finding's; no enrolled profile holds the agent's configuration"
	case len(matched) == 0:
		reason = "the finding's processes are no longer in the process table " +
			"and no enrolled profile holds the agent's configuration"
	}
	return owner{Attribution: AttributionUnattributed, Reason: reason}
}

// ownerGOOS is the system the owner sources are named for; tests replace it.
var ownerGOOS = runtime.GOOS

// ownerSourcesFor names the sources an unattributed finding's owner was
// looked up in on goos, so a Linux or macOS diagnostic does not name Windows
// mechanisms (GAP-0092).
func ownerSourcesFor(goos string) string {
	if goos == "windows" {
		return "process token, Win32_Process owner and session user"
	}
	return "the process's owning uid in the process table"
}

// eventOwner is the one account the events of processes named, and mixed
// reports that they named more than one. The account an event names is that
// of the process instance that produced it, so unlike an owner looked up by
// pid it is never a later holder's. Only the session's root says who owns
// it: a descendant's event can name the account a runas or setuid child
// runs as, so it is left out (GAP-1401).
func eventOwner(processes []procRef) (user, sid string, mixed bool) {
	for _, process := range processes {
		switch {
		case process.Descendant, process.SID == "":
		case sid == "":
			user, sid = process.User, process.SID
		case !strings.EqualFold(sid, process.SID):
			return "", "", true
		}
	}
	return user, sid, false
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
