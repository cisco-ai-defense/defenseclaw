// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
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
	sep := string(filepath.Separator)
	vol := filepath.VolumeName(path)
	cur, rest := vol, path[len(vol):]
	if rest != "" && os.IsPathSeparator(rest[0]) {
		cur += sep
		rest = trimPathSeparators(rest)
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
			return "", false
		}
		next := joinPathElement(cur, elem)
		info, err := os.Lstat(next)
		if err != nil {
			return "", false
		}
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			cur = next
			continue
		}
		target, err := os.Readlink(next)
		if err != nil {
			cur = next
			continue
		}
		if networkShareRootOf(target) != "" {
			return joinPathElement(target, rest), false
		}
		if hops++; hops > networkLinkHopLimit {
			return "", true
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
	return "", false
}
