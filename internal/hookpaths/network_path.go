// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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

// errNetworkShareUnanswered is the error of a read below a network share
// that has not answered. It is not fs.ErrNotExist: the path may exist.
var errNetworkShareUnanswered = errors.New("the network share did not answer in time")

var (
	// networkShareAnswerWait bounds how long a call waits for the first
	// answer of a share.
	networkShareAnswerWait = 680 * time.Millisecond
	// Identity reads get the remainder of this first-contact budget while
	// the root is pending. The ordinary root probe still has the shorter
	// answer wait above, so dead shares return within the hook's one-second
	// requirement while a reached file can answer after that probe.
	networkShareIdentityAnswerWait = 900 * time.Millisecond
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

// networkPathUnanswered reports a path below a network share that has not
// answered in time. A local path is never reported and costs no probe.
func networkPathUnanswered(path string) bool {
	root := networkShareRootOf(path)
	if root == "" {
		return false
	}
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
				return true
			case !dead && now.Sub(finished) < networkShareAnsweredFor:
				networkShares.mu.Unlock()
				return false
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
			return true
		}
		probe = &networkShareProbe{started: now, done: make(chan struct{})}
		networkShares.probes[key] = probe
		go func(probe *networkShareProbe) {
			probeNetworkShare(root + string(filepath.Separator))
			probe.took = time.Since(probe.started)
			close(probe.done)
		}(probe)
	}
	networkShares.mu.Unlock()
	wait := networkShareAnswerWait - time.Since(probe.started)
	if wait <= 0 {
		select {
		case <-probe.done:
			return probe.took > networkShareDeadAfter
		default:
			return true
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-probe.done:
		return probe.took > networkShareDeadAfter
	case <-timer.C:
		return true
	}
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

// Every file operation below a share uses one deadline measured from first
// contact. A completed read is not cached: a later call must see current file
// identity. The slot limit bounds outstanding operating-system reads.
type pathReadKind uint8

const (
	readStat pathReadKind = iota
	readLstat
	readStatPinned
	readOpen
	readDir
	readLink
	readEvalSymlinks
)

type pathReadResult struct {
	info    os.FileInfo
	file    *os.File
	entries []os.DirEntry
	link    string
	err     error
}

var networkReadSlots = make(chan struct{}, networkShareProbeLimit)

// A file read that has exhausted the answer budget may still be held in the
// operating system. Path scans use the same unknown answer until it returns.
// Identity reads get one brief chance to resolve another reachable file.
var pendingNetworkReads struct {
	mu    sync.Mutex
	roots map[string]*pendingNetworkRead
}

type pendingNetworkRead struct {
	done       chan struct{}
	started    time.Time
	lastAccess time.Time
	quietFor   time.Duration
}

func networkReadPending(root string) (bool, time.Time) {
	pendingNetworkReads.mu.Lock()
	defer pendingNetworkReads.mu.Unlock()
	state := pendingNetworkReads.roots[root]
	if state == nil {
		return false, time.Time{}
	}
	select {
	case <-state.done:
		// Consecutive reads in one decision share the unknown answer. A
		// later read after a quiet interval retries the current identity.
		if time.Since(state.lastAccess) >= state.quietFor {
			delete(pendingNetworkReads.roots, root)
			return false, time.Time{}
		}
	default:
	}
	state.lastAccess = time.Now()
	return true, state.started
}

func rememberPendingNetworkRead(root string, done chan struct{}, started time.Time) {
	pendingNetworkReads.mu.Lock()
	if pendingNetworkReads.roots == nil {
		pendingNetworkReads.roots = make(map[string]*pendingNetworkRead)
	}
	if prior := pendingNetworkReads.roots[root]; prior != nil && prior.started.Before(started) {
		started = prior.started
	}
	state := &pendingNetworkRead{
		done: done, started: started, lastAccess: time.Now(), quietFor: max(networkShareAnswerWait/3, time.Millisecond),
	}
	pendingNetworkReads.roots[root] = state
	pendingNetworkReads.mu.Unlock()
	go func() {
		<-done
		pendingNetworkReads.mu.Lock()
		if pendingNetworkReads.roots[root] == state {
			state.lastAccess = time.Now()
		}
		pendingNetworkReads.mu.Unlock()
		for {
			time.Sleep(state.quietFor)
			pendingNetworkReads.mu.Lock()
			if pendingNetworkReads.roots[root] != state {
				pendingNetworkReads.mu.Unlock()
				return
			}
			if time.Since(state.lastAccess) >= state.quietFor {
				delete(pendingNetworkReads.roots, root)
				pendingNetworkReads.mu.Unlock()
				return
			}
			pendingNetworkReads.mu.Unlock()
		}
	}()
}

var readPath = func(name string, kind pathReadKind) (result pathReadResult) {
	switch kind {
	case readStat:
		result.info, result.err = os.Stat(name)
	case readLstat:
		result.info, result.err = os.Lstat(name)
	case readStatPinned:
		result.info, result.err = pathidentity.StatPinned(name)
	case readOpen:
		result.file, result.err = os.Open(name)
	case readDir:
		result.entries, result.err = os.ReadDir(name)
	case readLink:
		result.link, result.err = os.Readlink(name)
	case readEvalSymlinks:
		result.link, result.err = filepath.EvalSymlinks(name)
	}
	return result
}

// identityRead lets the gateway accept a file identity that answers while its
// share root probe is pending. An error still waits for the root answer, so a
// missing path on an unanswered share is not mistaken for a missing file.
func boundedPathRead(name string, kind pathReadKind, identityRead bool) pathReadResult {
	root := networkShareRootOf(name)
	if root == "" {
		return readPath(name, kind)
	}
	root = strings.ToLower(filepath.ToSlash(root))
	pending, pendingStarted := networkReadPending(root)
	if pending && !identityRead {
		return pathReadResult{err: networkShareError("read", name)}
	}
	started := time.Now()
	var rootReady <-chan bool
	if identityRead {
		ready := make(chan bool, 1)
		rootReady = ready
		go func() { ready <- networkPathUnanswered(name) }()
	} else if networkPathUnanswered(name) {
		return pathReadResult{err: networkShareError("read", name)}
	}
	wait := networkShareAnswerWait - time.Since(started)
	if identityRead {
		// The identity window extends the root probe by at most one third.
		// Keep that relationship when a caller supplies a shorter probe
		// bound, so one slow file read does not consume a separate budget.
		identityWait := min(networkShareIdentityAnswerWait, networkShareAnswerWait*4/3)
		wait = identityWait - time.Since(started)
		rootAnswered := false
		networkShares.mu.Lock()
		probe := networkShares.probes[root]
		if probe != nil {
			select {
			case <-probe.done:
				rootAnswered = true
			default:
				remaining := identityWait - time.Since(probe.started)
				if remaining < wait {
					wait = remaining
				}
			}
		}
		networkShares.mu.Unlock()
		if pending {
			if rootAnswered {
				// One stalled file does not hide another reached identity on
				// a share whose root has already answered.
				wait = min(wait, 150*time.Millisecond)
			} else {
				wait = min(wait, identityWait-time.Since(pendingStarted))
			}
		}
	}
	if wait <= 0 {
		return pathReadResult{err: networkShareError("read", name)}
	}
	select {
	case networkReadSlots <- struct{}{}:
	default:
		return pathReadResult{err: networkShareError("read", name)}
	}
	readReady := make(chan pathReadResult, 1)
	readFinished := make(chan struct{})
	reader := readPath
	go func() {
		readReady <- reader(name, kind)
		close(readFinished)
		<-networkReadSlots
	}()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	var result pathReadResult
	readDone, rootDone, rootUnanswered := false, !identityRead, false
	for {
		if readDone && (result.err == nil || rootDone) {
			if result.err != nil && rootUnanswered {
				return pathReadResult{err: networkShareError("read", name)}
			}
			return result
		}
		select {
		case result = <-readReady:
			readDone = true
			readReady = nil
		case rootUnanswered = <-rootReady:
			rootDone = true
			rootReady = nil
		case <-timer.C:
			// A completed read wins a race with the timer. An Open that
			// finishes after the deadline has no caller to own its handle.
			if !readDone {
				select {
				case result = <-readReady:
					readDone = true
				default:
				}
			}
			if readDone && result.err == nil {
				return result
			}
			if !readDone && kind == readOpen {
				go func() {
					if late := <-readReady; late.file != nil {
						_ = late.file.Close()
					}
				}()
			}
			if !readDone {
				rememberPendingNetworkRead(root, readFinished, started)
			}
			return pathReadResult{err: networkShareError("read", name)}
		}
	}
}

// ShareUnanswered distinguishes an unknown network path from a missing one.
func ShareUnanswered(err error) bool { return errors.Is(err, errNetworkShareUnanswered) }

// SharePath reports a network-share spelling without reading the share.
func SharePath(name string) bool { return networkShareRootOf(name) != "" }

// The file system reads of the target scans and of the write-target walk.
// Each reads a local path as the os function does, and a path below a
// network share only once the share has answered (networkPathUnanswered).

func pathStat(name string) (os.FileInfo, error) {
	result := boundedPathRead(name, readStat, false)
	return result.info, result.err
}

// pathStatPinned is pathStat with the file identity read at once, for a
// FileInfo that a later os.SameFile compares with the opened file.
func pathStatPinned(name string) (os.FileInfo, error) {
	result := boundedPathRead(name, readStatPinned, false)
	return result.info, result.err
}

func pathLstat(name string) (os.FileInfo, error) {
	result := boundedPathRead(name, readLstat, false)
	return result.info, result.err
}

func pathOpen(name string) (*os.File, error) {
	result := boundedPathRead(name, readOpen, false)
	return result.file, result.err
}

func pathReadDir(name string) ([]os.DirEntry, error) {
	result := boundedPathRead(name, readDir, false)
	return result.entries, result.err
}

func pathReadlink(name string) (string, error) {
	result := boundedPathRead(name, readLink, false)
	return result.link, result.err
}

func pathEvalSymlinks(name string) (string, error) {
	result := boundedPathRead(name, readEvalSymlinks, false)
	return result.link, result.err
}

// PathStat and PathLstat share the hook path reader and its network bound.
func PathStat(name string) (os.FileInfo, error) {
	result := boundedPathRead(name, readStat, true)
	return result.info, result.err
}
func PathLstat(name string) (os.FileInfo, error) {
	result := boundedPathRead(name, readLstat, true)
	return result.info, result.err
}

// PathReadlink reads a known link entry within the shared share budget.
func PathReadlink(name string) (string, error) {
	result := boundedPathRead(name, readLink, true)
	return result.link, result.err
}
