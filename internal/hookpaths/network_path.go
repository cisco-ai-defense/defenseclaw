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

// The gateway needs file identity, not only a root-share answer. A share
// root can answer slowly while an already reachable file answers at once.
// Read that file with the same answer bound and cache a timeout per share.
// The slot bound limits blocked operating-system calls if many shares stop
// answering at once. A completed root probe permits a later retry.
var shareInfoReads = struct {
	mu       sync.Mutex
	timeouts map[string]shareInfoTimeout
	slots    chan struct{}
}{slots: make(chan struct{}, networkShareProbeLimit)}

type shareInfoTimeout struct {
	since      time.Time
	retryAfter time.Time
}

var readShareInfo = func(name string, follow bool) (os.FileInfo, error) {
	if follow {
		return os.Stat(name)
	}
	return os.Lstat(name)
}

func shareBoundedInfo(name string, follow bool) (os.FileInfo, error) {
	root := networkShareRootOf(name)
	if root == "" {
		return readShareInfo(name, follow)
	}
	if networkPathUnanswered(name) {
		return nil, networkShareError("stat", name)
	}
	key := strings.ToLower(filepath.ToSlash(root))
	now := time.Now()
	shareInfoReads.mu.Lock()
	if timed, present := shareInfoReads.timeouts[key]; present {
		if now.Before(timed.retryAfter) && !shareProbeRecoveredSince(key, timed.since) {
			shareInfoReads.mu.Unlock()
			return nil, networkShareError("stat", name)
		}
		delete(shareInfoReads.timeouts, key)
	}
	shareInfoReads.mu.Unlock()
	select {
	case shareInfoReads.slots <- struct{}{}:
	default:
		return nil, networkShareError("stat", name)
	}
	type result struct {
		info os.FileInfo
		err  error
	}
	ready := make(chan result, 1)
	go func() {
		info, err := readShareInfo(name, follow)
		ready <- result{info, err}
		<-shareInfoReads.slots
	}()
	wait := networkShareAnswerWait
	if wait < 0 {
		wait = 0
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case got := <-ready:
		return got.info, got.err
	case <-timer.C:
		// Prefer an answer that raced the deadline.
		select {
		case got := <-ready:
			return got.info, got.err
		default:
		}
		// A root answer before this read timed out does not prove that
		// this file answered.
		timedOutAt := time.Now()
		shareInfoReads.mu.Lock()
		if shareInfoReads.timeouts == nil {
			shareInfoReads.timeouts = make(map[string]shareInfoTimeout)
		}
		if _, known := shareInfoReads.timeouts[key]; !known && len(shareInfoReads.timeouts) >= networkShareProbeLimit {
			oldestKey := ""
			var oldest time.Time
			for previous, timed := range shareInfoReads.timeouts {
				if oldestKey == "" || timed.retryAfter.Before(oldest) {
					oldestKey, oldest = previous, timed.retryAfter
				}
			}
			delete(shareInfoReads.timeouts, oldestKey)
		}
		shareInfoReads.timeouts[key] = shareInfoTimeout{since: timedOutAt, retryAfter: timedOutAt.Add(networkShareQuietFor)}
		shareInfoReads.mu.Unlock()
		go networkPathUnanswered(name)
		return nil, networkShareError("stat", name)
	}
}

func shareProbeRecoveredSince(key string, since time.Time) bool {
	networkShares.mu.Lock()
	defer networkShares.mu.Unlock()
	probe := networkShares.probes[key]
	if probe == nil {
		return false
	}
	select {
	case <-probe.done:
		return probe.took <= networkShareDeadAfter && probe.started.Add(probe.took).After(since)
	default:
		return false
	}
}

// ShareUnanswered distinguishes an unknown network path from a missing one.
func ShareUnanswered(err error) bool { return errors.Is(err, errNetworkShareUnanswered) }

// SharePath reports a network-share spelling without reading the share.
func SharePath(name string) bool { return networkShareRootOf(name) != "" }

// The file system reads of the target scans and of the write-target walk.
// Each reads a local path as the os function does, and a path below a
// network share only once the share has answered (networkPathUnanswered).

func pathStat(name string) (os.FileInfo, error) { return shareBoundedInfo(name, true) }

// pathStatPinned is pathStat with the file identity read at once, for a
// FileInfo that a later os.SameFile compares with the opened file.
func pathStatPinned(name string) (os.FileInfo, error) {
	if networkPathUnanswered(name) {
		return nil, networkShareError("stat", name)
	}
	return pathidentity.StatPinned(name)
}

func pathLstat(name string) (os.FileInfo, error) { return shareBoundedInfo(name, false) }

func pathOpen(name string) (*os.File, error) {
	if networkPathUnanswered(name) {
		return nil, networkShareError("open", name)
	}
	return os.Open(name)
}

func pathReadDir(name string) ([]os.DirEntry, error) {
	if networkPathUnanswered(name) {
		return nil, networkShareError("readdir", name)
	}
	return os.ReadDir(name)
}

func pathReadlink(name string) (string, error) {
	if networkPathUnanswered(name) {
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

// PathStat and PathLstat share the hook path reader and its network bound.
func PathStat(name string) (os.FileInfo, error)  { return pathStat(name) }
func PathLstat(name string) (os.FileInfo, error) { return pathLstat(name) }
