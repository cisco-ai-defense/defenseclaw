// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/fixturefs"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// A local spelling can reach a network share through a link on its way: a
// project folder that is a junction or symbolic link to \\server\share. The
// read of the spelling opens the link, and the share, in the operating
// system, so the share must be asked before the read, as for a path that
// names the share itself (rel-1-0-6:GAP-0482, rel-1-0-9:GAP-0621). The
// walk below reads each component of a local path with an lstat, which
// opens no link, follows each link it meets one hop at a time, and reports
// the first share a hop lands on.

// networkShareLinkWalk is whether a local path may reach a share through a
// link: on Windows only (NFS and SMB mounts read like any mounted volume
// elsewhere). Tests that fake a share turn it on.
var networkShareLinkWalk = runtime.GOOS == "windows"

// walkLstat reads one component of a path for the walk below; tests count it.
// It reads the identity of the component with its attributes, through one
// handle that shares the folder with every other opener (pathidentity): the
// identity that os.Lstat leaves to the first comparison is a second open of
// the path on Windows, which fails on a folder held open, and runs outside
// the wait that bounds the read.
var walkLstat = pathidentity.LstatPinned

// networkLinkHopLimit bounds the links one walk follows: the links the system
// opens in one path (SystemLinkLimit: 63 on Windows, 40 on Linux, 32 on macOS).
// A path past it is one no read can go through, an unread body. A walk that
// reaches the bound has not proven the path free of an unasked share, so it
// reports the path as unanswered, as a share that did not answer, and never
// as a completed check.
var networkLinkHopLimit = SystemLinkLimit()

// ShareWalkLinkLimit is the links the share walk follows before it reports a
// path unanswered (networkLinkHopLimit), for tests of the callers.
func ShareWalkLinkLimit() int { return networkLinkHopLimit }

// trimPathSeparators drops the leading separators of path.
func trimPathSeparators(path string) string {
	for path != "" && os.IsPathSeparator(path[0]) {
		path = path[1:]
	}
	return path
}

// cutPathElement splits the first component off path.
func cutPathElement(path string) (elem, rest string) {
	for i := 0; i < len(path); i++ {
		if os.IsPathSeparator(path[i]) {
			return path[:i], trimPathSeparators(path[i:])
		}
	}
	return path, ""
}

// joinPathElement is dir and elem joined by one separator.
func joinPathElement(dir, elem string) string {
	switch {
	case dir == "":
		return elem
	case os.IsPathSeparator(dir[len(dir)-1]):
		return dir + elem
	}
	return dir + string(filepath.Separator) + elem
}

// linkIntoShare is the path as a link on the local path resolves it, when
// the link leads into a network share and the resolved path names that
// share ("" for no such link). A link as the last component is followed
// only with followLast: lstat, readlink and a directory walk open no final
// link. The caller asks the share and then walks the resolved path on, so
// a link inside the share that leads into another share is met too.
// exhausted reports a walk that followed networkLinkHopLimit links and was
// stopped before it could tell whether a further link leads into a share.
func linkIntoShare(path string, followLast bool) (resolved string, exhausted bool) {
	if !networkShareLinkWalk || path == "" {
		return "", false
	}
	// A hook call resolves the paths of thousands of operands, nearly all
	// below the same folders. A folder found to be no link is not read
	// again, but the deepest known folder of a path is read once and must
	// still be the folder that was found; a folder that changed (a link
	// now, or another folder) drops what was known and the path is walked
	// from its root (rel-1-0-9:GAP-0943, about 1 ms per operand on Windows).
	resolved, exhausted, stale := walkShareLinks(path, followLast, true)
	if stale {
		forgetPlainFolders()
		resolved, exhausted, _ = walkShareLinks(path, followLast, false)
	}
	return resolved, exhausted
}

// walkShareLinks is linkIntoShare. With trust it skips the folders known to
// be no link, and reports stale when a known folder has changed.
func walkShareLinks(path string, followLast bool, trust bool) (resolved string, exhausted, stale bool) {
	sep := string(filepath.Separator)
	vol := filepath.VolumeName(path)
	cur, rest := vol, path[len(vol):]
	if rest != "" && os.IsPathSeparator(rest[0]) {
		cur += sep
		rest = trimPathSeparators(rest)
	}
	if trust {
		// The folder that holds the last name is nearly always a known one;
		// it is read once, and the folders above it need no walk.
		if folder, last, known, ok := knownParent(path); ok {
			switch same, answered := stillPlain(folder, known); {
			case !answered:
				return "", true, false
			case !same:
				return "", false, true
			}
			cur, rest = folder, last
		}
	}
	hops := 0
	for rest != "" {
		var elem string
		elem, rest = cutPathElement(rest)
		switch elem {
		case "", ".":
			continue
		case "..":
			if parent := filepath.Dir(cur); cur != "" && parent != "." {
				cur = parent
			}
			continue
		}
		if rest == "" && !followLast {
			return "", false, false
		}
		next := joinPathElement(cur, elem)
		if known, ok := knownPlain(next); ok && trust && rest != "" {
			if !knownBelow(next, rest) {
				switch same, answered := stillPlain(next, known); {
				case !answered:
					return "", true, false
				case !same:
					return "", false, true
				}
			}
			cur = next
			continue
		}
		info, err := walkLstat(next)
		if err != nil {
			return "", false, false
		}
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			if rest != "" {
				notePlain(next, info)
			}
			cur = next
			continue
		}
		target, err := os.Readlink(fixturefs.Map(next))
		target = fixturefs.Unmap(target)
		if err != nil {
			cur = next
			continue
		}
		if networkShareRootOf(target) != "" {
			return joinPathElement(target, rest), false, false
		}
		if hops++; hops > networkLinkHopLimit {
			return "", true, false
		}
		targetVol := filepath.VolumeName(target)
		tail := target[len(targetVol):]
		if targetVol == "" && (tail == "" || !os.IsPathSeparator(tail[0])) {
			// A relative target is read from the folder that holds the link.
			if rest != "" {
				tail += sep + rest
			}
			rest = tail
			continue
		}
		if targetVol == "" {
			targetVol = filepath.VolumeName(cur)
		}
		cur = targetVol
		if tail != "" && os.IsPathSeparator(tail[0]) {
			cur += sep
			tail = trimPathSeparators(tail)
		}
		if rest != "" && tail != "" {
			tail += sep + rest
		} else if tail == "" {
			tail = rest
		}
		rest = tail
	}
	return "", false, false
}

// plainFolders are the local folders the share walk found to be no link, with
// what it read of each (its identity among it), so that the many paths of a
// hook call that run through the same folders are not read component by
// component again. A folder is skipped only on the proof of stillPlain, never
// on its age, so the memory outlives no call that matters and is shared by
// the goroutines that walk.
var plainFolders struct {
	mu sync.Mutex
	m  map[string]os.FileInfo
}

// plainFoldersLimit bounds plainFolders; at the limit the memory starts anew.
const plainFoldersLimit = 4096

// knownPlain is what the walk read of a folder it found to be no link.
func knownPlain(path string) (os.FileInfo, bool) {
	plainFolders.mu.Lock()
	defer plainFolders.mu.Unlock()
	info, known := plainFolders.m[path]
	return info, known
}

// notePlain records a folder the walk has found to be no link. info comes
// from walkLstat, which reads the identity of the folder with its other
// attributes, so it names the folder that was found whenever it is compared.
func notePlain(path string, info os.FileInfo) {
	plainFolders.mu.Lock()
	defer plainFolders.mu.Unlock()
	if plainFolders.m == nil || len(plainFolders.m) >= plainFoldersLimit {
		plainFolders.m = make(map[string]os.FileInfo)
	}
	plainFolders.m[path] = info
}

// forgetPlainFolders drops every folder noted.
func forgetPlainFolders() {
	plainFolders.mu.Lock()
	defer plainFolders.mu.Unlock()
	clear(plainFolders.m)
}

// knownBelow reports that the next folder of rest below folder is known
// too, so that folder is proven by the read of the deeper one.
func knownBelow(folder, rest string) bool {
	elem, after := cutPathElement(rest)
	if elem == "" || elem == "." || elem == ".." || after == "" {
		return false
	}
	_, known := knownPlain(joinPathElement(folder, elem))
	return known
}

// knownParent splits path into the folder that holds its last name and that
// name, when the folder is spelled as it was noted (so no ".." or repeated
// separator lies in it) and is known.
func knownParent(path string) (folder, last string, known os.FileInfo, ok bool) {
	i := len(path) - 1
	for i >= 0 && !os.IsPathSeparator(path[i]) {
		i--
	}
	if i <= 0 || i == len(path)-1 {
		return "", "", nil, false
	}
	folder, last = path[:i], path[i+1:]
	if last == "." || last == ".." {
		return "", "", nil, false
	}
	known, ok = knownPlain(folder)
	return folder, last, known, ok
}

// knownFolderReadGrace is how long stillPlain waits for the read of a known
// folder before it looks up the hook call and its remaining share wait. The
// read of a local folder returns in microseconds, and the call lookup (the
// goroutine number) costs more than that read, so it is made only for a read
// that is slow. A call with less share wait left than this waits at most this
// long for a read that is not back.
const knownFolderReadGrace = 2 * time.Millisecond

// stillPlain reads a known folder again and reports whether it is still the
// folder that was found, as a folder and no link. The read is the first to
// pass through the folders above it unasked, and a folder above it may have
// become a link to a share that does not answer, so it is bounded as a share
// is: by the answer wait and by what the hook call has left of its share
// wait. answered is false when it did not return within that wait (the wait
// is charged to the hook call, the memory is dropped, and the path is
// reported unanswered).
func stillPlain(path string, known os.FileInfo) (same, answered bool) {
	start := time.Now()
	done := make(chan bool, 1)
	// The read function is taken here, not by the goroutine, which may
	// outlive the call (and a test that has put the function back). The
	// comparison is made in the goroutine too: nothing of the folder is
	// read after the wait.
	lstat := walkLstat
	go func() {
		info, err := lstat(path)
		done <- err == nil && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 && os.SameFile(known, info)
	}()
	timer := time.NewTimer(min(networkShareAnswerWait, knownFolderReadGrace))
	defer timer.Stop()
	select {
	case same := <-done:
		return same, true
	case <-timer.C:
	}
	call := currentHookCall()
	wait := networkShareAnswerWait
	if call != nil {
		wait = min(wait, call.shareWait())
	}
	if wait -= time.Since(start); wait > 0 {
		timer.Reset(wait)
		select {
		case same := <-done:
			return same, true
		case <-timer.C:
		}
	}
	if call != nil {
		call.waitLeft -= time.Since(start)
	}
	forgetPlainFolders()
	return false, false
}
