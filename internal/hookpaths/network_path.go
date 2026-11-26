// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fixturefs"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// A Windows UNC path (\\server\share\..., //server/share/...) names a file
// on another machine: reading its attributes opens an SMB session to that
// server. A server that does not answer holds the read for the system's
// connect timeout (about 21 s), and the read cannot be cancelled. In a
// command such a path is often no path at all: the target scans read the
// URL in echo https://host/x or curl https://host/x -o x as the UNC path
// //host/x. Every hook call that named the host waited for the same attempt
// and passed its 3.5 s answer budget, so its hook denied an ordinary
// command as a gateway that did not answer (rel-1-0-6 GAP-0127).
//
// A share on another machine is never read at all (rel-1-0-10:GAP-1074): even
// a probe that the hook call does not wait for opens an SMB session to the
// server the operand text names, with the user's credentials, before any
// verdict and for a call the gateway then blocks. Such a share reads as
// unknown at once, as a share that did not answer: a write below it cannot be
// placed, a path below it is no proven protected file, and the protected
// target rules judge its text. A script body below it is a body the call could
// not read (ShareBodyUnread), judged by the policy tier as the unknown tier
// is, never as a body that writes nothing. Only a share of this machine
// (localhost, a loopback address, a name of this host:
// actionfacts.WindowsServerIsThisMachine) is asked, as below.
//
// The scans therefore read below a share of this machine only after the share
// has answered. The first read of a share asks it once, for every call that
// names it, and waits at most networkShareAnswerWait. A share that has not
// answered by then reads as unknown, as an unreadable path does: a write
// below it cannot be placed and a path below it is no proven protected
// file. A share that answers, however slowly, is read as before (a
// loopback share that names a local file among them). A share whose probe
// still had no answer after networkShareDeadAfter stays unknown for
// networkShareQuietFor without being asked again.
//
// The answer wait is bounded per hook call as well as per share: one hook
// call may name many shares, one after another, and each fresh share given
// its own wait with no bound on the sum would add up past the hook answer
// budget. A hook call (the hook client resolving its targets, the gateway
// answering one hook request: HookCall) waits for share answers
// networkShareCallShares full waits and one tail of half a wait in all. A
// share that does not answer costs the call its own wait and no other share
// its chance: each of the first shares a call asks is waited for at most
// networkShareAnswerWait, whatever the shares before it did, and a share
// that answers within it is read (rel-1-0-6:GAP-0482 review 3). The shares
// asked after those share the tail, each waited for half of what remains of
// it: the wait of a later share shrinks but never drops to nothing while the
// call has waited less than its budget, so a share that answers within it is
// read after any number of shares that did not (rel-1-0-6:GAP-0482 review
// 4). A fresh share asked once the wait is spent reads as unknown at once,
// as a share that did not answer within its wait reads, and is read once it
// has answered. The wait belongs to the call alone: no other call,
// before it or alongside it in the same process, spends it
// (rel-1-0-6:GAP-0482 review 2). The readers take no context, so a call is
// the goroutine that runs it, from HookCall to its end; a read outside a
// hook call waits for each share at most networkShareAnswerWait.
//
// The call budget never drops a script silently. A share read that the
// budget cut short (the share might have answered within its own wait) and
// that was to read the body of a script (an explicit source, make or awk -f:
// pathOpenRoot) is recorded on the call (ShareBodyUnread); the gateway then
// judges the call by its policy tier: as past its evaluation limit, as it
// judges a command it cannot read to the end, in the strict tier, and with
// an alert that does not block in the default and permissive tiers, since
// an unread body is neither a named nor a known protected target. A
// protected file or link the command names is blocked in every tier by the
// rules that name it. Whatever the number of shares the call asked before,
// a body the budget kept unread is never taken as a body that wrote nothing
// (rel-1-0-6:GAP-0482 reviews 7 and 8). A share that is merely slower than
// its own wait is the owner-accepted bound and is not recorded. A script
// whose path passes more links than the walk follows (networkLinkHopLimit)
// is recorded the same way: the walk could not show that no share on the
// way is left unasked, so the body was not read (rel-1-0-9:GAP-0621). So is a
// script whose path the system itself refuses to open for passing too many
// links (ELOOP), where the share walk is off (noteBodyLinkLimit,
// rel-1-0-9:GAP-0950).

// errNetworkShareUnanswered is the error of a read below a network share
// that has not answered. It is not fs.ErrNotExist: the path may exist.
var errNetworkShareUnanswered = errors.New("the network share did not answer in time")

var (
	// networkShareAnswerWait bounds how long a call waits for the first
	// answer of a share.
	networkShareAnswerWait = 750 * time.Millisecond
	// networkShareDeadAfter is how long a probe may take and still count as
	// the answer of a live (slow) share.
	networkShareDeadAfter = 5 * time.Second
	// networkShareQuietFor is how long a share whose probe did not answer
	// within networkShareDeadAfter stays unknown; networkShareAnsweredFor is
	// how long an answer is reused before the share is asked again.
	networkShareQuietFor    = 2 * time.Minute
	networkShareAnsweredFor = time.Minute
	// networkShareRootOf names the network share a path is on ("" for a
	// local path); probeNetworkShare asks the share once. Tests replace both.
	networkShareRootOf = networkShareRoot
	probeNetworkShare  = func(root string) { _, _ = os.Stat(root) }
	// networkShareOfThisMachine reports a share root whose server is this
	// machine, the only shares the gate asks (rel-1-0-10:GAP-1074).
	networkShareOfThisMachine = shareOfThisMachine
)

// networkShareCallShares is how many full answer waits one hook call may
// spend on shares that do not answer: two cost it 1.5 s. After them the
// call has a tail of half an answer wait (0.375 s) in all, so the call
// waits under 1.9 s whatever the number of shares, and the hook answer
// budget (3.5 s) keeps room for the rest of the call.
const networkShareCallShares = 2

// networkShareProbeLimit bounds the shares remembered at once.
const networkShareProbeLimit = 256

type networkShareProbe struct {
	started time.Time
	// done is closed when the probe returned; took is set before.
	done chan struct{}
	took time.Duration
}

var networkShares struct {
	mu     sync.Mutex
	probes map[string]*networkShareProbe
}

// hookCalls are the hook calls in progress, by the goroutine that runs
// each (hookCallKey); a call's wait is read and spent only by that goroutine.
var hookCalls struct {
	mu    sync.Mutex
	calls map[uint64]*hookCall
}

type hookCall struct {
	// key is the call's entry in hookCalls: hookCallKey of its goroutine
	// when the call began, or when it last took a thread back after a wait
	// (retakeHookCallThread).
	key uint64
	// waitLeft is how long the call may still wait for share answers
	// (networkShareCallShares answer waits and tail at its start); tail is
	// the part of it that the shares after the full waits share.
	waitLeft, tail time.Duration
	// bodyUnread is set when the budget cut short a read of a script body,
	// bodyLinks when the link bound stopped the walk to it
	// (ShareBodyUnread).
	bodyUnread, bodyLinks bool
	// linksUnproven is set when the budget cut short the ask of a share the
	// link walk of a skill folder check needed (SkillLinksUnproven).
	linksUnproven bool
	// stateUnanswered is set when a write target was not proved free of the
	// DefenseClaw state because a local read it needed did not answer in
	// time (StateCheckUnanswered). Atomic: the checks run on any goroutine of
	// the call.
	stateUnanswered atomic.Bool
	// budgetCuts counts the share waits of the call that its budget cut
	// short (askNetworkShare). Such a read is not the answer of the file
	// system: the share may answer a moment later in the same call. The
	// call's memory (stats, memo) keeps no answer made while it rose
	// (cutMark, keepsSince), so a later read asks the share again and reads
	// it once it has answered, as each evaluation did before it shared the
	// call's memory (rel-1-0-10:GAP-1606). Read by the memo under its own
	// lock from any goroutine, so it is atomic.
	budgetCuts atomic.Uint64
	// globCut holds the caps the pattern expansions of the private-key and
	// registration readers hit (globCutOf).
	globCut bounded.CapSet
	// memo holds what the call has read of the file system: the paths it
	// resolved and the protected set of each home (targets).
	memo *TargetMemo
	// stats are the answers of callStat, by path.
	stats map[string]statAnswer
	// scripts are the script bodies the call has read (readActionScriptWith),
	// scriptBytes their size in all.
	scripts     map[scriptReadKey]string
	scriptBytes int
	// keyReads are the answers of the private-key reader, by its reading
	// (ActionPrivateKeyReadBounded).
	keyReads map[keyReadKey]keyReadAnswer
}

type statAnswer struct {
	info os.FileInfo
	err  error
}

// callStat is pathStat remembered for the hook call: a reach scan compares
// the identity of the same resolved word with each protected file, for each
// statement, and each pathStat asks the share check first. The file it names
// is the same file for the whole decision (rel-1-0-10:GAP-0766). A caller
// that reads a path again to see whether it changed uses pathStat.
func callStat(name string) (os.FileInfo, error) {
	return memoHookCall().stat(name)
}

// stat is callStat for the hook call call (nil: none, pathStat). A loop that
// stats many paths finds its call once and stats through it: finding the call
// was a traceback of the goroutine's stack (goroutineID), half of a Windows
// hook decision for the registration names alone (rel-1-0-10:GAP-1293), until
// hookCallKey read the thread on Windows and goroutineKey the goroutine's g
// elsewhere (rel-1-0-10:GAP-2215).
func (call *hookCall) stat(name string) (os.FileInfo, error) {
	if call == nil {
		return pathStat(name)
	}
	if answer, ok := call.stats[name]; ok {
		return answer.info, answer.err
	}
	mark := call.cutMark()
	info, err := pathStat(name)
	if !call.keepsSince(mark) {
		// The budget cut a share wait of this stat short: unknown for now,
		// not the answer of the file system (rel-1-0-10:GAP-1606).
		return info, err
	}
	if call.stats == nil {
		call.stats = make(map[string]statAnswer)
	}
	call.stats[name] = statAnswer{info, err}
	return info, err
}

// targets is the file system memory of the call, made on first use. The call
// is run by one goroutine, so it needs no lock of its own.
func (call *hookCall) targets() *TargetMemo {
	if call.memo == nil {
		call.memo = newTargetMemo()
		call.memo.owner = call
	}
	return call.memo
}

// cutMark is how many share waits of the call its budget has cut short so
// far (0 for no call): taken before a read whose answer the call may keep.
func (call *hookCall) cutMark() uint64 {
	if call == nil {
		return 0
	}
	return call.budgetCuts.Load()
}

// keepsSince reports whether an answer read since mark (cutMark) may be kept
// in the call's memory: the budget cut no share wait of the call short
// meanwhile. An answer made while the budget cut a share off is unknown for
// that moment only, never the answer for the rest of the call
// (rel-1-0-10:GAP-1606). Without a call every answer is kept.
func (call *hookCall) keepsSince(mark uint64) bool {
	return call == nil || call.budgetCuts.Load() == mark
}

// shareWait is how long the call may wait for the next share: a full answer
// wait while the full waits last, then half of what remains of the tail.
func (call *hookCall) shareWait() time.Duration {
	return max(call.waitLeft-call.tail, call.waitLeft/2)
}

// HookCall begins a hook call on the calling goroutine and returns its end.
// The reads of the goroutine until then wait for share answers
// networkShareCallShares answer waits and a tail in all. Within a call it begins
// nothing more, so the gateway's request and the target resolution it runs are one call.
func HookCall() (end func()) {
	_, end = beginHookCall()
	return end
}

// beginHookCall is HookCall that also returns the call the goroutine runs
// from then on (nil: none), the one it began or the one already open, so a
// caller that uses the call does not read the goroutine's key a second time:
// globCutOf runs on every private-key and pattern reading of a decision
// (rel-1-0-10:GAP-1472).
func beginHookCall() (*hookCall, func()) {
	unlock := lockHookCallKey()
	id := hookCallKey()
	if id == 0 {
		unlock()
		return nil, func() {}
	}
	hookCalls.mu.Lock()
	defer hookCalls.mu.Unlock()
	if open := hookCalls.calls[id]; open != nil {
		unlock()
		return open, func() {}
	}
	if hookCalls.calls == nil {
		hookCalls.calls = make(map[uint64]*hookCall)
	}
	tail := networkShareAnswerWait / 2
	call := &hookCall{key: id, waitLeft: networkShareCallShares*networkShareAnswerWait + tail, tail: tail}
	hookCalls.calls[id] = call
	return call, func() {
		hookCalls.mu.Lock()
		delete(hookCalls.calls, call.key)
		hookCalls.mu.Unlock()
		unlock()
	}
}

// memoReads turns on the file system memory of a hook call (callStat,
// ResolveWriteTarget, newProtectedFiles). It pays where a read is dear: on
// Windows each stat asks the share check and the file system, 446,000 reads
// for 100 PowerShell lines, 27 s (rel-1-0-10:GAP-0766). On a POSIX host a
// stat costs about a microsecond, while finding the call cost a traceback of
// the calling goroutine's stack (goroutineID) on every read: the memory made a
// decision 1.3 to 4.4 times slower than none (rel-1-0-10:GAP-0844). The
// answers are the same with it or without it (the file system of one decision
// is the same file system). Tests set it to read the memory on every host.
var memoReads = runtime.GOOS == "windows"

// memoHookCall is the hook call whose file system memory a read uses: the
// call the goroutine runs where memoReads is on, nil elsewhere.
func memoHookCall() *hookCall {
	if !memoReads {
		return nil
	}
	return currentHookCall()
}

// currentHookCall is the hook call the calling goroutine runs (nil: none).
// The key and the map are read on one thread (lockHookCallKey): on Windows
// the key is the thread, and a goroutine moved off its thread between the two
// reads could find a call that has since locked that thread
// (rel-1-0-10:GAP-1476). The goroutine of a call is already locked to its
// thread; the lock nests, so its reads are unchanged.
func currentHookCall() *hookCall {
	if fixturefs.Unreadable() {
		// A decision that reads no file system keeps nothing in the call's
		// memory and reads none of it: its answers are not the host's.
		return nil
	}
	unlock := lockHookCallKey()
	defer unlock()
	id := hookCallKey()
	if id == 0 {
		return nil
	}
	hookCalls.mu.Lock()
	defer hookCalls.mu.Unlock()
	return hookCalls.calls[id]
}

// shareReadCut is why a read of a path that did not answer is not final.
type shareReadCut uint8

const (
	// shareReadFinal: the share itself did not answer within its own wait
	// (the owner-accepted bound), or the path answered.
	shareReadFinal shareReadCut = iota
	// shareReadBudgetCut: the call budget ended the wait for a share that
	// might have answered had the call had more budget.
	shareReadBudgetCut
	// shareReadLinkBound: the link bound stopped the walk before it could
	// tell whether a further link leads into a share.
	shareReadLinkBound
	// shareReadRemote: the share is on another machine, which the hook path
	// never reads (rel-1-0-10:GAP-1074); what is below it is unknown.
	shareReadRemote
)

// networkPathRead reports a path below a network share that has not
// answered in time (a local path is never reported and costs no probe), and
// whether the call budget, not the own wait of the share, ended the wait for
// a share that did not answer (it might have answered had the call had more
// budget), or the link bound stopped the walk to the path.
func networkPathRead(path string) (unanswered bool, cut shareReadCut) {
	return networkPathReadAs(path, true)
}

// networkPathReadAs is networkPathRead for a path that is on a share, or
// that a link on its way (and, with followLast, the last component) leads
// into one (networkPathGate).
func networkPathReadAs(path string, followLast bool) (unanswered bool, cut shareReadCut) {
	gate := networkPathGate(path, followLast)
	return gate.unanswered, gate.cut
}

// shareGate is the share decision for one read of a path and what the walk
// behind it read.
type shareGate struct {
	unanswered bool
	cut        shareReadCut
	// read is the path the read opens: the path the walk read when it
	// followed a link (shareWalk.resolved), else the name as given.
	read string
	// proved reports a walk that read every component of read as no link,
	// the last one too when the read follows it; last and lastErr are its
	// read of that last component (shareWalk).
	proved  bool
	last    os.FileInfo
	lastErr error
}

// networkPathGate decides whether a read of path may be made, and what it
// reads. Every share the read opens is asked, in the order the system
// opens them: a link inside an answered share may lead on to another share,
// and a name with a trailing separator opens its last link as well
// (os.Lstat follows it), so the walk goes on from each answered share until
// no link leads into a further share (rel-1-0-9:GAP-0621). A walk that the
// link bound stopped has not shown that no unasked share is left, so it is
// reported as unanswered, never as a completed check; a chain of links that
// comes back to a path it has asked is a loop, which the system fails, and
// every share on it has been asked.
//
// The decision and the read are about the same file (rel-1-0-10:GAP-1074
// review 1): the read opens the path the walk resolved, not the name again,
// so a link on the way that is pointed at a share after the walk is never
// opened, and a read that follows the last component holds it as the walk
// read it (readGated). A stat is the walk's own read of it (pathStat).
func networkPathGate(path string, followLast bool) (gate shareGate) {
	name := path
	gate.read = name
	if fixturefs.Unreadable() {
		// A decision that reads no file system asks no share (Unread).
		return gate
	}
	if path != "" && os.IsPathSeparator(path[len(path)-1]) {
		followLast = true
	}
	var seen map[string]bool
	for range networkLinkHopLimit + 1 {
		if root := networkShareRootOf(path); root != "" {
			if !networkShareOfThisMachine(root) {
				return shareGate{unanswered: true, cut: shareReadRemote, read: name}
			}
			if silent, budgetCut := askNetworkShare(root); silent {
				if budgetCut {
					return shareGate{unanswered: true, cut: shareReadBudgetCut, read: name}
				}
				return shareGate{unanswered: true, cut: shareReadFinal, read: name}
			}
		}
		walk := linkIntoShare(path, followLast)
		switch {
		case walk.exhausted:
			return shareGate{unanswered: true, cut: shareReadLinkBound, read: name}
		case walk.share == "":
			if walk.resolved != "" {
				gate.proved, gate.last, gate.lastErr = true, walk.last, walk.lastErr
				if walk.linked || path != name {
					gate.read = walk.resolved
				}
			}
			return gate
		case seen[walk.share]:
			return gate
		}
		if seen == nil {
			seen = make(map[string]bool)
		}
		seen[walk.share] = true
		path = walk.share
	}
	return shareGate{unanswered: true, cut: shareReadLinkBound, read: name}
}

// askNetworkShare asks the share root once for every call that names it and
// waits for its answer as the budget of the call allows.
func askNetworkShare(root string) (unanswered, budgetCut bool) {
	// One probe per share, whichever slashes the path spells it with.
	key := strings.ToLower(filepath.ToSlash(root))
	now := time.Now()
	networkShares.mu.Lock()
	probe := networkShares.probes[key]
	if probe != nil {
		select {
		case <-probe.done:
			finished := probe.started.Add(probe.took)
			dead := probe.took > networkShareDeadAfter
			switch {
			case dead && now.Sub(finished) < networkShareQuietFor:
				networkShares.mu.Unlock()
				return true, false
			case !dead && now.Sub(finished) < networkShareAnsweredFor:
				networkShares.mu.Unlock()
				return false, false
			}
			probe = nil
		default:
		}
	}
	if probe == nil {
		if networkShares.probes == nil {
			networkShares.probes = make(map[string]*networkShareProbe)
		}
		if len(networkShares.probes) >= networkShareProbeLimit && !evictNetworkShareProbesLocked() {
			// As many shares as the limit are being asked and none has
			// answered: hold no further thread on one more.
			networkShares.mu.Unlock()
			return true, false
		}
		probe = &networkShareProbe{started: now, done: make(chan struct{})}
		networkShares.probes[key] = probe
		// The probe function is read here, not by the probe goroutine,
		// which may start after a test has put the function back.
		ask := probeNetworkShare
		go func(probe *networkShareProbe) {
			ask(root + string(filepath.Separator))
			probe.took = time.Since(probe.started)
			close(probe.done)
		}(probe)
	}
	networkShares.mu.Unlock()
	now = time.Now()
	wait := networkShareAnswerWait - now.Sub(probe.started)
	call := currentHookCall()
	if call != nil {
		if left := call.shareWait(); left < wait {
			wait, budgetCut = left, true
		}
	}
	if wait <= 0 {
		select {
		case <-probe.done:
			return probe.took > networkShareDeadAfter, false
		default:
			call.noteBudgetCut(budgetCut)
			return true, budgetCut
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	if call != nil {
		defer func() { call.waitLeft -= time.Since(now) }()
	}
	select {
	case <-probe.done:
		return probe.took > networkShareDeadAfter, false
	case <-timer.C:
		call.noteBudgetCut(budgetCut)
		return true, budgetCut
	}
}

// noteBudgetCut counts a share wait the call's budget cut short (budgetCuts).
func (call *hookCall) noteBudgetCut(budgetCut bool) {
	if budgetCut && call != nil {
		call.budgetCuts.Add(1)
	}
}

// OverrideNetworkSharesForTest replaces which paths are network shares
// (rootOf names the share of a path, "" for none) and how a share is asked,
// and forgets the shares asked so far, for tests of the gateway on a host
// with no share. The shares rootOf names are taken as shares of this machine,
// the ones the gate asks, so that a test sees every share a reader would ask
// (OverrideRemoteSharesForTest keeps the real split). The restore puts all
// back.
func OverrideNetworkSharesForTest(rootOf func(path string) string, ask func(root string)) (restore func()) {
	return overrideNetworkShares(rootOf, ask, func(string) bool { return true })
}

// OverrideRemoteSharesForTest reads paths as Windows names network shares
// (every spelling of windowsShareRoot, on any host, with the link walk on),
// keeps which shares are this machine's as the product does, and calls ask
// for every share the gate asks: a test of the gateway counts the shares a
// call contacts (rel-1-0-10:GAP-1074). thisMachine, when not nil, replaces
// which shares are this machine's. The restore puts all back.
func OverrideRemoteSharesForTest(ask func(root string), thisMachine func(root string) bool) (restore func()) {
	if thisMachine == nil {
		thisMachine = shareOfThisMachine
	}
	return overrideNetworkShares(func(path string) string {
		root, _ := windowsShareRoot(path)
		return root
	}, ask, thisMachine)
}

func overrideNetworkShares(rootOf func(path string) string, ask func(root string), thisMachine func(root string) bool) (restore func()) {
	oldRoot, oldProbe, oldWalk, oldLocal := networkShareRootOf, probeNetworkShare, networkShareLinkWalk, networkShareOfThisMachine
	networkShares.mu.Lock()
	oldProbes := networkShares.probes
	networkShares.probes = nil
	networkShares.mu.Unlock()
	networkShareRootOf, probeNetworkShare, networkShareLinkWalk, networkShareOfThisMachine = rootOf, ask, true, thisMachine
	return func() {
		networkShareRootOf, probeNetworkShare, networkShareLinkWalk, networkShareOfThisMachine = oldRoot, oldProbe, oldWalk, oldLocal
		networkShares.mu.Lock()
		networkShares.probes = oldProbes
		networkShares.mu.Unlock()
	}
}

// ShareBodyUnread reports that the hook call on the calling goroutine
// could not read the body of a script on a network share because its share
// budget was spent or the share is on another machine (never read). The body might have written a protected file; the
// caller judges the call by the policy tier: the strict tier as it judges
// one it cannot evaluate, the others with an alert.
func ShareBodyUnread() bool {
	call := currentHookCall()
	return call != nil && (call.bodyUnread || call.bodyLinks)
}

// ShareBodyUnreadCauses tells why ShareBodyUnread is set: the call budget
// kept the share from being asked or the share is on another machine (budget), or the path to the script passes more
// links than the walk follows, so a share on it may not have been asked
// (rel-1-0-9:GAP-0621). Both can hold in one call.
func ShareBodyUnreadCauses() (budget, linkBound bool) {
	call := currentHookCall()
	if call == nil {
		return false, false
	}
	return call.bodyUnread, call.bodyLinks
}

// evictNetworkShareProbesLocked drops the finished probes and reports
// whether there is room for another.
func evictNetworkShareProbesLocked() bool {
	for key, probe := range networkShares.probes {
		select {
		case <-probe.done:
			delete(networkShares.probes, key)
		default:
		}
	}
	return len(networkShares.probes) < networkShareProbeLimit
}

func networkShareError(op, name string) error {
	return &fs.PathError{Op: op, Path: name, Err: errNetworkShareUnanswered}
}

// localReadUnanswered reports a read of path that did not answer
// (errNetworkShareUnanswered) while the gate places path on no network
// share: a local folder read past networkShareAnswerWait (stillPlain). What
// that read would have shown is unknown, not absent (rel-1-0-10:GAP-1804).
// A path on a share is not reported: a file there cannot be a hard link to
// a local file, so a slow share keeps its answer.
func localReadUnanswered(path string, err error) bool {
	return errors.Is(err, errNetworkShareUnanswered) && path != "" && networkShareRootOf(path) == ""
}

// The file system reads of the target scans and of the write-target walk.
// Each reads a local path as the os function does, and a path below a
// network share only once the share has answered (networkPathGate). Each
// reads the path the share decision was made for: the path the walk
// resolved, its last component held as the walk read it (readGated).

// readGated makes a read that follows the last component of name, once the
// share gate allows it, on the path the gate read (shareGate.read). When the
// walk read every component as no link, the last component is held as no
// link for the read (pathidentity.HoldUnlinked): one that has become a link
// since the walk, which may lead to a share on another machine, is refused
// before it is opened, and a read that it changed under is discarded. A
// refused read is unknown, as a share that did not answer
// (rel-1-0-10:GAP-1074 review 1).
func readGated[T any](op, name string, read func(path string) (T, error), discard func(T)) (T, shareReadCut, error) {
	var none T
	gate := networkPathGate(name, true)
	if gate.unanswered {
		return none, gate.cut, networkShareError(op, name)
	}
	path := fixturefs.Map(gate.read)
	if path == "" && name != "" {
		// Inside fixturefs.Unread nothing is read: the name does not exist
		// (filepath.EvalSymlinks of the empty name would answer itself).
		return none, shareReadFinal, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
	}
	if !gate.proved {
		value, err := read(path)
		return value, shareReadFinal, err
	}
	still, err := pathidentity.HoldUnlinked(path)
	switch {
	case errors.Is(err, pathidentity.ErrLinked), errors.Is(err, pathidentity.ErrUnpinned):
		// A link on the way, or a component the hold cannot pin: unknown,
		// never read unheld (rel-1-0-10:GAP-1263, GAP-1264).
		return none, shareReadRemote, networkShareError(op, name)
	case err != nil:
		return none, shareReadFinal, err
	}
	value, err := read(path)
	if !still() {
		if err == nil && discard != nil {
			discard(value)
		}
		return none, shareReadRemote, networkShareError(op, name)
	}
	return value, shareReadFinal, err
}

// pathStat is os.Stat of name. When the share walk read the whole path, the
// stat is the walk's own read of its last component: nothing reads the
// name again after the share decision.
func pathStat(name string) (os.FileInfo, error) {
	gate := networkPathGate(name, true)
	if gate.unanswered {
		return nil, networkShareError("stat", name)
	}
	if gate.proved && (gate.last != nil || gate.lastErr != nil) {
		return gate.last, gate.lastErr
	}
	info, _, err := readGated("stat", name, os.Stat, nil)
	return info, err
}

// pathStatPinned is pathStat with the file identity read at once, for a
// FileInfo that a later os.SameFile compares with the opened file. The
// walk's read of the last component is such a read.
func pathStatPinned(name string) (os.FileInfo, error) {
	gate := networkPathGate(name, true)
	if gate.unanswered {
		return nil, networkShareError("stat", name)
	}
	if gate.proved && (gate.last != nil || gate.lastErr != nil) {
		return gate.last, gate.lastErr
	}
	info, _, err := readGated("stat", name, pathidentity.StatPinned, nil)
	return info, err
}

// pathLstat is os.Lstat of name: the last component is not followed, and the
// folders above it are read as the walk resolved them.
func pathLstat(name string) (os.FileInfo, error) {
	gate := networkPathGate(name, false)
	if gate.unanswered {
		return nil, networkShareError("lstat", name)
	}
	return os.Lstat(fixturefs.Map(gate.read))
}

func closeFile(file *os.File) { _ = file.Close() }

func pathOpen(name string) (*os.File, error) {
	file, _, err := readGated("open", name, os.Open, closeFile)
	return file, err
}

// pathOpenRoot is os.OpenRoot with the root read as pathOpen reads it.
// A read through the root stays below the root, so on the same share.
func pathOpenRoot(name string) (*os.Root, error) {
	root, cut, err := readGated("openroot", name, os.OpenRoot, func(root *os.Root) { _ = root.Close() })
	if errors.Is(err, errNetworkShareUnanswered) {
		noteBodyCut(cut)
		return nil, err
	}
	noteBodyLinkLimit(err)
	return root, err
}

// noteBodyCut records on the hook call why the read of a script body did not
// finish when a cause other than the share itself ended it (ShareBodyUnread).
func noteBodyCut(cut shareReadCut) {
	call := currentHookCall()
	if call == nil {
		return
	}
	switch cut {
	case shareReadBudgetCut, shareReadRemote:
		call.bodyUnread = true
	case shareReadLinkBound:
		call.bodyLinks = true
	}
}

// noteGlobCut records on the hook call the caps a pattern expansion of the
// private-key or a registration reader hit (globCutOf).
func noteGlobCut(truncated bounded.CapSet) {
	if !truncated.Any() {
		return
	}
	if call := currentHookCall(); call != nil {
		call.globCut = call.globCut.Union(truncated)
	}
}

// pathBodyUnanswered is networkPathRead for the script a relative name reaches
// below a folder already walked: a name that spells folder links of its own
// is walked on from that folder, and a path past the links the system opens
// is an unread body whatever way the name is spelled, as when the folder is
// the one behind the links (rel-1-0-9:GAP-0982). A Windows read below an
// open folder does not report the bound, so the walk does.
func pathBodyUnanswered(cwd, relative string) bool {
	if !networkShareLinkWalk || !strings.ContainsAny(relative, `/\`) {
		return false
	}
	unanswered, cut := networkPathRead(joinPathElement(cwd, relative))
	if unanswered {
		noteBodyCut(cut)
	}
	return unanswered
}

// noteBodyLinkLimit records on the hook call that a read of a script body
// failed because the system would not follow so many links on its path
// (ELOOP). That is the link bound on a host where the share walk is off
// (Linux, macOS): the body is neither read nor known to write nothing, so
// the call is judged by its tier like a body past the walk bound
// (ShareBodyUnread, rel-1-0-9:GAP-0950). A directly named or known protected
// target is blocked by the rules that name it and is not affected. Windows
// reports the bound through the share walk, which stops at the same limit.
func noteBodyLinkLimit(err error) {
	if err == nil || !errors.Is(err, syscall.ELOOP) {
		return
	}
	if call := currentHookCall(); call != nil {
		call.bodyLinks = true
	}
}

func pathReadDir(name string) ([]os.DirEntry, error) {
	entries, _, err := readGated("readdir", name, os.ReadDir, nil)
	return entries, err
}

// pathReadDirChunk is how many entries pathReadDirLimit reads at a time past
// its first n.
const pathReadDirChunk = 1024

// pathReadDirLimit is pathReadDir for a walk that examines at most n-1
// entries of a directory in name order: it returns the n entries of the
// whole directory that sort first by name, which is how the sorted read of
// pathReadDir begins (a directory of fewer names reads as pathReadDir reads
// it). A directory of more names is still read to its end, as pathReadDir
// read it, keeping at most 2n entries at a time, so the walk examines the
// entries rel examined whatever order the file system lists them in: the
// first n in directory order made a key link that sorts early drop out of a
// directory past the cap (rel-1-0-10:GAP-1468).
func pathReadDirLimit(name string, n int) ([]os.DirEntry, error) {
	// The directory is opened as pathOpen opens it, on the path the share
	// gate read under its hold; every entry below is read through that
	// handle. Asking the gate and then opening the name looked the name up
	// again after the share decision (rel-1-0-10:GAP-1264).
	dir, err := pathOpen(name)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(n)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	byName := func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) }
	slices.SortFunc(entries, byName)
	if err != nil || n <= 0 || len(entries) < n {
		return entries, err
	}
	for {
		more, err := dir.ReadDir(pathReadDirChunk)
		done := errors.Is(err, io.EOF) || len(more) == 0
		if err != nil && !done {
			return nil, err
		}
		// entries[:n] is sorted: a name past entries[n-1] is not among the
		// first n (the names of a directory are distinct).
		bound := entries[n-1].Name()
		for _, entry := range more {
			if entry.Name() < bound {
				entries = append(entries, entry)
			}
		}
		if done || len(entries) >= 2*n {
			slices.SortFunc(entries, byName)
			entries = entries[:n]
		}
		if done {
			return entries, nil
		}
	}
}

func pathReadlink(name string) (string, error) {
	gate := networkPathGate(name, false)
	if gate.unanswered {
		return "", networkShareError("readlink", name)
	}
	target, err := os.Readlink(fixturefs.Map(gate.read))
	return fixturefs.Unmap(target), err
}

func pathEvalSymlinks(name string) (string, error) {
	resolved, _, err := readGated("evalsymlinks", name, winpath.EvalLinks, nil)
	return fixturefs.Unmap(resolved), err
}

// pathFinalPath is pathEvalSymlinks with the real final path always
// (winpath.FinalPath): no subst or mapped drive letter kept.
func pathFinalPath(name string) (string, error) {
	resolved, _, err := readGated("evalsymlinks", name, winpath.FinalPath, nil)
	return fixturefs.Unmap(resolved), err
}

// pathWalkDir is filepath.WalkDir with its root read as pathLstat reads
// it: a root below a share that has not answered is passed to fn with the
// share's error, as WalkDir passes a root it cannot read. The walk reads
// the root the share walk resolved and hands fn the paths below the root as
// the caller named it.
func pathWalkDir(root string, fn fs.WalkDirFunc) error {
	gate := networkPathGate(root, false)
	if gate.unanswered {
		err := fn(root, nil, networkShareError("lstat", root))
		if err == filepath.SkipDir || err == filepath.SkipAll {
			return nil
		}
		return err
	}
	return filepath.WalkDir(fixturefs.Map(gate.read), func(path string, d fs.DirEntry, err error) error {
		path = fixturefs.Unmap(path)
		if gate.read != root {
			if below, ok := strings.CutPrefix(path, gate.read); ok && (below == "" || os.IsPathSeparator(below[0])) {
				path = root + below
			}
		}
		return fn(path, d, err)
	})
}

// Every read of a path that a hook call names, in this package and in the
// gateway's command-target proofs, goes through these readers, so a share
// that does not answer costs at most networkShareAnswerWait and never the
// connect timeout (rel-1-0-6:GAP-0482). TestHookPathReadsAreShareBounded
// keeps it so.

// Lstat is os.Lstat for a path a hook call names, read as pathLstat reads it.
func Lstat(name string) (os.FileInfo, error) { return pathLstat(name) }

// Stat is os.Stat for a path a hook call names, read as pathStat reads it.
func Stat(name string) (os.FileInfo, error) { return pathStat(name) }

// EvalSymlinks is winpath.EvalLinks bounded like the other readers: the
// gateway reads a link chain of a path a hook call names through it. On
// Windows it follows a junction as it follows a symbolic link, which
// filepath.EvalSymlinks does not (rel-1-0-9:GAP-0621, rel-1-0-10:GAP-2182).
func EvalSymlinks(name string) (string, error) { return pathEvalSymlinks(name) }

// ReadDir is os.ReadDir for a directory a hook call names, read as pathReadDir reads it.
func ReadDir(name string) ([]os.DirEntry, error) { return pathReadDir(name) }

// Readlink is os.Readlink for a path a hook call names, read as pathReadlink reads it.
func Readlink(name string) (string, error) { return pathReadlink(name) }

// Open is os.Open for a path a hook call names, read as pathOpen reads it.
func Open(name string) (*os.File, error) { return pathOpen(name) }

// ReadFile is os.ReadFile for a path a hook call names, read as pathOpen reads it.
func ReadFile(name string) ([]byte, error) {
	body, _, err := readGated("open", name, os.ReadFile, nil)
	return body, err
}

// ReadRegularFileBounded is safefile.ReadRegularFileBounded for a path a
// hook call names, read as pathOpen reads it: a share on another machine is
// never contacted, and the file read is the file the share decision was
// made for (rel-1-0-10:GAP-1074). safefile reads the path the gate read,
// under its hold, never the name again: opening the name would follow a
// link on the way as it is now, which may lead to a share since the walk
// (rel-1-0-10:GAP-1264). A name the walk read through a link that safefile
// refuses for the name is refused here before anything opens it
// (readNameAsSafefile), so the answer stays the one safefile gives the name.
func ReadRegularFileBounded(name string, maxBytes int64) ([]byte, error) {
	body, _, err := readGated("open", name, func(path string) ([]byte, error) {
		if err := readNameAsSafefile("open", name, path); err != nil {
			return nil, err
		}
		return safefile.ReadRegularFileBounded(path, maxBytes)
	}, nil)
	return body, err
}

// readNameAsSafefile refuses (errNameReadThroughLink) a name that the walk
// read through a link where safefile refuses one: on Windows any link on the
// way (rejectReparseChain); elsewhere a link as the last component or as the
// folder that holds it, which are looked at with the walk's own reads
// (pathLstat). A link further up is read through, as safefile does.
func readNameAsSafefile(op, name, path string) error {
	if path == fixturefs.Map(name) {
		return nil
	}
	if runtime.GOOS == "windows" {
		return &fs.PathError{Op: op, Path: name, Err: errNameReadThroughLink}
	}
	for _, component := range []string{name, filepath.Dir(name)} {
		info, err := pathLstat(component)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return &fs.PathError{Op: op, Path: name, Err: errNameReadThroughLink}
		}
	}
	return nil
}

// errNameReadThroughLink is the refusal of a reader that reads the name it
// is given as a name (safefile, GetLongPathName) when the share walk read
// that name through a link: the gate's path is the link's target, and the
// name would be looked up again through the link as it is now.
var errNameReadThroughLink = errors.New("hookpaths: the name passes a link the share gate resolved")

// readNameAsGated is the rule of a reader that must read a name as spelled
// (it refuses links, or it spells the name back): it reads only when the
// path the gate read (path, mapped) is the name itself, so the read is the
// gate's read under its hold. Otherwise it refuses (errNameReadThroughLink).
func readNameAsGated(op, name, path string) error {
	if path != fixturefs.Map(name) {
		return &fs.PathError{Op: op, Path: name, Err: errNameReadThroughLink}
	}
	return nil
}

// LstatPinned is pathidentity.LstatPinned for a path a hook call names,
// read as pathLstat reads it.
func LstatPinned(name string) (os.FileInfo, error) {
	gate := networkPathGate(name, false)
	if gate.unanswered {
		return nil, networkShareError("lstat", name)
	}
	return pathidentity.LstatPinned(fixturefs.Map(gate.read))
}

// ObserveRemoteShareReadsForTest calls note with every name a hook-path read
// hands the file system (fixturefs.Map) that is below a share on another
// machine, in any spelling Windows opens one by (windowsShareRoot), on any
// host: a test counts every contact a call makes with such a share, the
// reads past the gate as well as the share asks (rel-1-0-10:GAP-1074).
func ObserveRemoteShareReadsForTest(note func(name string)) (restore func()) {
	return fixturefs.ObserveForTest(func(name string) {
		if root, _ := windowsShareRoot(name); root != "" && !shareOfThisMachine(root) {
			note(name)
		}
	})
}

// NotExist reports a read error that a proof which tells a missing path
// from an unreadable one takes as missing: an os not-exist error, or a
// share that did not answer in time. A read that waits for such a share
// fails at the end of the connect timeout with ERROR_BAD_NETPATH, which
// os.IsNotExist reports, so the proof reaches the verdict it reached
// before, without the wait its hook cannot afford.
func NotExist(err error) bool {
	return os.IsNotExist(err) || errors.Is(err, errNetworkShareUnanswered)
}

// CallState is what the hook call of the goroutine has spent of its budgets
// and set of its causes so far: the share answer wait, the script bytes, the
// bodies left unread, the pattern caps hit. Its caches (stats, the target
// memo, the bodies read) are left out: they answer a repeat as the first
// read. A dispatch that leaves it as it found it spent nothing a repeat of
// the same request would find spent (the gateway's dispatch memo,
// rel-1-0-10:GAP-1472). A share wait the budget cut short changes it too
// (budgetCuts), even one that spent no wait: the answer made then is not kept
// (rel-1-0-10:GAP-1606). The zero value: no call open.
type CallState struct {
	open                                 bool
	waitLeft, tail                       time.Duration
	bodyUnread, bodyLinks, linksUnproven bool
	globCut                              bounded.CapSet
	scriptBytes, scripts                 int
	budgetCuts                           uint64
}

// noteStateUnanswered marks the goroutine's hook call (none: nothing): a
// write target was refused as not proved free of the state because a local
// read it needed did not answer in time (rel-1-0-10:GAP-1805).
func noteStateUnanswered() {
	if call := currentHookCall(); call != nil {
		call.stateUnanswered.Store(true)
	}
}

// StateCheckUnanswered reports that the goroutine's hook call refused a
// write target only as not proved free of the DefenseClaw state: a local read
// the check needed did not answer in time. The caller names that cause, so
// the user retries instead of reading a state-write reason for an ordinary
// file (rel-1-0-10:GAP-1805).
func StateCheckUnanswered() bool {
	call := currentHookCall()
	return call != nil && call.stateUnanswered.Load()
}

// HookCallState is the CallState of the hook call the goroutine runs.
func HookCallState() CallState {
	call := currentHookCall()
	if call == nil {
		return CallState{}
	}
	return call.state()
}

// state is the CallState of call (not nil).
func (call *hookCall) state() CallState {
	return CallState{
		open: true, waitLeft: call.waitLeft, tail: call.tail,
		bodyUnread: call.bodyUnread, bodyLinks: call.bodyLinks, linksUnproven: call.linksUnproven,
		globCut: call.globCut, scriptBytes: call.scriptBytes, scripts: len(call.scripts),
		budgetCuts: call.budgetCuts.Load(),
	}
}
