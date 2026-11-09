// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
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
// The scans therefore read below a network share only after the share has
// answered. The first read of a share asks it once, for every call that
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
// way is left unasked, so the body was not read (rel-1-0-9:GAP-0621).

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
// each; a call's wait is read and spent only by that goroutine.
var hookCalls struct {
	mu    sync.Mutex
	calls map[uint64]*hookCall
}

type hookCall struct {
	// waitLeft is how long the call may still wait for share answers
	// (networkShareCallShares answer waits and tail at its start); tail is
	// the part of it that the shares after the full waits share.
	waitLeft, tail time.Duration
	// bodyUnread is set when the budget cut short a read of a script body,
	// bodyLinks when the link bound stopped the walk to it
	// (ShareBodyUnread).
	bodyUnread, bodyLinks bool
	// cleared are the local paths the share walk has read in this call and
	// found to lead into no share (clearedRead). The goroutines of a call
	// may read it together.
	clearedMu sync.Mutex
	cleared   map[clearedRead]struct{}
	// stats are the answers of pathStat and pathLstat in this call, for a
	// name that exists or does not (statAnswer).
	stats map[clearedRead]statAnswer
}

// statAnswer is what a stat of a name returned.
type statAnswer struct {
	info os.FileInfo
	err  error
}

// statOfCall is the answer this call has had to a stat of name (followLast:
// stat, not lstat). The scans of one call stat the same operand again and
// again, and within one evaluation every reader assumes the files stay as
// they are (TargetMemo), so the name is stat-ed once. Only an operand that
// exists or is missing is kept: any other error (a share that did not
// answer, a refused read) is read again.
func (call *hookCall) statOfCall(name string, followLast bool) (statAnswer, bool) {
	call.clearedMu.Lock()
	defer call.clearedMu.Unlock()
	answer, ok := call.stats[clearedKey(name, followLast)]
	return answer, ok
}

// noteStat keeps the answer to a stat of name.
func (call *hookCall) noteStat(name string, followLast bool, info os.FileInfo, err error) {
	if err != nil && !os.IsNotExist(err) {
		return
	}
	call.clearedMu.Lock()
	defer call.clearedMu.Unlock()
	if len(call.stats) >= clearedPathsLimit {
		return
	}
	if call.stats == nil {
		call.stats = make(map[clearedRead]statAnswer)
	}
	call.stats[clearedKey(name, followLast)] = statAnswer{info, err}
}

// clearedRead is a path read by the share walk, with whether the read opens
// a link at the end of the path.
type clearedRead struct {
	path       string
	followLast bool
}

// clearedPathsLimit bounds the paths one call remembers; past it a path is
// read again each time, as outside a call.
const clearedPathsLimit = 1 << 16

// clearedKey is the key of a path in cleared. Windows names the same file
// by spellings that differ in the case of a letter, and the scans of one
// call spell an operand both ways, so the ASCII letters are folded there
// (the system folds exactly those, so two spellings with one key are one
// name). Any other letter keeps its case: two names the system tells apart
// are never one key.
func clearedKey(path string, followLast bool) clearedRead {
	if runtime.GOOS == "windows" {
		folded := []byte(path)
		for i, c := range folded {
			if c >= 0x41 && c <= 0x5a { // A to Z
				folded[i] = c + 0x20
			}
		}
		path = string(folded)
	}
	return clearedRead{path, followLast}
}

// isCleared reports a path this call has read and found to lead into no
// share. A read that opens the link at the end of the path also covers the
// read that does not.
func (call *hookCall) isCleared(path string, followLast bool) bool {
	call.clearedMu.Lock()
	defer call.clearedMu.Unlock()
	key := clearedKey(path, followLast)
	if _, ok := call.cleared[clearedKey(path, true)]; ok {
		return true
	}
	_, ok := call.cleared[key]
	return ok
}

// clear remembers a path found to lead into no share.
func (call *hookCall) clear(path string, followLast bool) {
	call.clearedMu.Lock()
	defer call.clearedMu.Unlock()
	if len(call.cleared) >= clearedPathsLimit {
		return
	}
	if call.cleared == nil {
		call.cleared = make(map[clearedRead]struct{})
	}
	call.cleared[clearedKey(path, followLast)] = struct{}{}
}

// soleHookCall is the hook call in progress when exactly one is (nil: none,
// or several). The goroutine of a call is told by a stack walk that costs
// more than the read it would save, so the walk is remembered for the one
// call that nothing can be confused with; with several calls in progress
// every read is walked as before.
func soleHookCall() *hookCall {
	hookCalls.mu.Lock()
	defer hookCalls.mu.Unlock()
	if len(hookCalls.calls) != 1 {
		return nil
	}
	for _, call := range hookCalls.calls {
		return call
	}
	return nil
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
	id := goroutineID()
	if id == 0 {
		return func() {}
	}
	hookCalls.mu.Lock()
	defer hookCalls.mu.Unlock()
	if _, open := hookCalls.calls[id]; open {
		return func() {}
	}
	if hookCalls.calls == nil {
		hookCalls.calls = make(map[uint64]*hookCall)
	}
	tail := networkShareAnswerWait / 2
	hookCalls.calls[id] = &hookCall{waitLeft: networkShareCallShares*networkShareAnswerWait + tail, tail: tail}
	return func() {
		hookCalls.mu.Lock()
		delete(hookCalls.calls, id)
		hookCalls.mu.Unlock()
	}
}

// currentHookCall is the hook call the calling goroutine runs (nil: none).
func currentHookCall() *hookCall {
	id := goroutineID()
	if id == 0 {
		return nil
	}
	hookCalls.mu.Lock()
	defer hookCalls.mu.Unlock()
	return hookCalls.calls[id]
}

// goroutineID is the runtime's number of the calling goroutine (0: not
// read), from the first line of its stack: "goroutine N [...". Numbers are
// not reused while the process runs.
func goroutineID() uint64 {
	var buf [64]byte
	line, ok := bytes.CutPrefix(buf[:runtime.Stack(buf[:], false)], []byte("goroutine "))
	if !ok {
		return 0
	}
	digits, _, _ := bytes.Cut(line, []byte(" "))
	id, err := strconv.ParseUint(string(digits), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// networkPathUnanswered reports a path below a network share that has not
// answered in time. A local path is never reported and costs no probe.
func networkPathUnanswered(path string) bool {
	unanswered, _ := networkPathRead(path)
	return unanswered
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
)

// linkUnanswered is networkPathUnanswered for a read that opens no link at
// the end of the path (lstat, readlink, a directory walk).
func linkUnanswered(path string) bool {
	unanswered, _ := networkPathReadAs(path, false)
	return unanswered
}

// networkPathRead is networkPathUnanswered that also reports whether the
// call budget, not the own wait of the share, ended the wait for a share
// that did not answer (it might have answered had the call had more
// budget), or the link bound stopped the walk to the path.
func networkPathRead(path string) (unanswered bool, cut shareReadCut) {
	return networkPathReadAs(path, true)
}

// networkPathReadAs is networkPathRead for a path that is on a share, or
// that a link on its way (and, with followLast, the last component) leads
// into one. Every share the read opens is asked, in the order the system
// opens them: a link inside an answered share may lead on to another share,
// and a name with a trailing separator opens its last link as well
// (os.Lstat follows it), so the walk goes on from each answered share until
// no link leads into a further share (rel-1-0-9:GAP-0621). A walk that the
// link bound stopped has not shown that no unasked share is left, so it is
// reported as unanswered, never as a completed check; a chain of links that
// comes back to a path it has asked is a loop, which the system fails, and
// every share on it has been asked.
func networkPathReadAs(path string, followLast bool) (unanswered bool, cut shareReadCut) {
	if path != "" && os.IsPathSeparator(path[len(path)-1]) {
		followLast = true
	}
	// The scans of one hook call read the same operand again and again (a
	// stat, an lstat and a link resolution each), and each read costs the
	// proof of its folders: a path the call has read and found to lead into
	// no share is not walked again in that call (rel-1-0-9:GAP-0943, about
	// 1 ms an operand on Windows). Only a local path is remembered, and
	// only until the call ends.
	var call *hookCall
	if networkShareLinkWalk {
		if call = soleHookCall(); call != nil && call.isCleared(path, followLast) {
			return false, shareReadFinal
		}
		// A read that opens the link at the end of a path the call has read
		// without opening it needs only the last name: the folders on the
		// way are proven.
		if call != nil && followLast && !os.IsPathSeparator(path[len(path)-1]) &&
			filepath.Clean(path) == path && call.isCleared(path, false) {
			if info, err := walkLstat(path); err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
				call.clear(path, true)
				return false, shareReadFinal
			}
		}
	}
	local, origin := true, path
	var seen map[string]bool
	for range networkLinkHopLimit + 1 {
		if root := networkShareRootOf(path); root != "" {
			local = false
			if silent, budgetCut := askNetworkShare(root); silent {
				if budgetCut {
					return true, shareReadBudgetCut
				}
				return true, shareReadFinal
			}
		}
		next, exhausted := linkIntoShare(path, followLast)
		switch {
		case exhausted:
			return true, shareReadLinkBound
		case next == "":
			if local && seen == nil && call != nil {
				call.clear(origin, followLast)
			}
			return false, shareReadFinal
		case seen[next]:
			return false, shareReadFinal
		}
		if seen == nil {
			seen = make(map[string]bool)
		}
		seen[next] = true
		path = next
	}
	return true, shareReadLinkBound
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
		return true, budgetCut
	}
}

// OverrideNetworkSharesForTest replaces which paths are network shares
// (rootOf names the share of a path, "" for none) and how a share is asked,
// and forgets the shares asked so far, for tests of the gateway on a host
// with no share. The restore puts all back.
func OverrideNetworkSharesForTest(rootOf func(path string) string, ask func(root string)) (restore func()) {
	oldRoot, oldProbe, oldWalk := networkShareRootOf, probeNetworkShare, networkShareLinkWalk
	networkShares.mu.Lock()
	oldProbes := networkShares.probes
	networkShares.probes = nil
	networkShares.mu.Unlock()
	networkShareRootOf, probeNetworkShare, networkShareLinkWalk = rootOf, ask, true
	return func() {
		networkShareRootOf, probeNetworkShare, networkShareLinkWalk = oldRoot, oldProbe, oldWalk
		networkShares.mu.Lock()
		networkShares.probes = oldProbes
		networkShares.mu.Unlock()
	}
}

// ShareBodyUnread reports that the hook call on the calling goroutine
// could not read the body of a script on a network share because its share
// budget was spent. The body might have written a protected file; the
// caller judges the call by the policy tier: the strict tier as it judges
// one it cannot evaluate, the others with an alert.
func ShareBodyUnread() bool {
	call := currentHookCall()
	return call != nil && (call.bodyUnread || call.bodyLinks)
}

// ShareBodyUnreadCauses tells why ShareBodyUnread is set: the call budget
// kept the share from being asked, or the path to the script passes more
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

// The file system reads of the target scans and of the write-target walk.
// Each reads a local path as the os function does, and a path below a
// network share only once the share has answered (networkPathUnanswered).

func pathStat(name string) (os.FileInfo, error) {
	var call *hookCall
	if networkShareLinkWalk {
		if call = soleHookCall(); call != nil {
			if answer, ok := call.statOfCall(name, true); ok {
				return answer.info, answer.err
			}
		}
	}
	if networkPathUnanswered(name) {
		return nil, networkShareError("stat", name)
	}
	info, err := os.Stat(name)
	if call != nil {
		call.noteStat(name, true, info, err)
	}
	return info, err
}

// pathStatPinned is pathStat with the file identity read at once, for a
// FileInfo that a later os.SameFile compares with the opened file.
func pathStatPinned(name string) (os.FileInfo, error) {
	if networkPathUnanswered(name) {
		return nil, networkShareError("stat", name)
	}
	return pathidentity.StatPinned(name)
}

func pathLstat(name string) (os.FileInfo, error) {
	var call *hookCall
	if networkShareLinkWalk {
		if call = soleHookCall(); call != nil {
			if answer, ok := call.statOfCall(name, false); ok {
				return answer.info, answer.err
			}
		}
	}
	if linkUnanswered(name) {
		return nil, networkShareError("lstat", name)
	}
	info, err := os.Lstat(name)
	if call != nil {
		call.noteStat(name, false, info, err)
	}
	return info, err
}

func pathOpen(name string) (*os.File, error) {
	if networkPathUnanswered(name) {
		return nil, networkShareError("open", name)
	}
	return os.Open(name)
}

// pathOpenRoot is os.OpenRoot with the root read as pathOpen reads it.
// A read through the root stays below the root, so on the same share.
func pathOpenRoot(name string) (*os.Root, error) {
	if unanswered, cut := networkPathRead(name); unanswered {
		if call := currentHookCall(); call != nil {
			switch cut {
			case shareReadBudgetCut:
				call.bodyUnread = true
			case shareReadLinkBound:
				call.bodyLinks = true
			}
		}
		return nil, networkShareError("openroot", name)
	}
	return os.OpenRoot(name)
}

func pathReadDir(name string) ([]os.DirEntry, error) {
	if networkPathUnanswered(name) {
		return nil, networkShareError("readdir", name)
	}
	return os.ReadDir(name)
}

func pathReadlink(name string) (string, error) {
	if linkUnanswered(name) {
		return "", networkShareError("readlink", name)
	}
	return os.Readlink(name)
}

func pathEvalSymlinks(name string) (string, error) {
	if networkPathUnanswered(name) {
		return "", networkShareError("evalsymlinks", name)
	}
	return filepath.EvalSymlinks(name)
}

// pathWalkDir is filepath.WalkDir with its root read as pathLstat reads
// it: a root below a share that has not answered is passed to fn with the
// share's error, as WalkDir passes a root it cannot read.
func pathWalkDir(root string, fn fs.WalkDirFunc) error {
	if linkUnanswered(root) {
		err := fn(root, nil, networkShareError("lstat", root))
		if err == filepath.SkipDir || err == filepath.SkipAll {
			return nil
		}
		return err
	}
	return filepath.WalkDir(root, fn)
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

// NotExist reports a read error that a proof which tells a missing path
// from an unreadable one takes as missing: an os not-exist error, or a
// share that did not answer in time. A read that waits for such a share
// fails at the end of the connect timeout with ERROR_BAD_NETPATH, which
// os.IsNotExist reports, so the proof reaches the verdict it reached
// before, without the wait its hook cannot afford.
func NotExist(err error) bool {
	return os.IsNotExist(err) || errors.Is(err, errNetworkShareUnanswered)
}
