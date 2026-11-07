// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// lateReachEntries bounds the entries the late-call scan looks at when it
// decides whether a file is one of the protected ones by identity. A bound
// that is hit is not an answer: the file is then not ordinary.
var lateReachEntries = 20000

// lateHomeEntries bounds the entries of the home the scan lists to find the
// protected folders in it.
const lateHomeEntries = 20000

// lateReach is the protected-reach state of one call's scan, built only when
// a path needs it: the protected authorized-keys files, the folders in the
// home that carry a protected name (followed to the place they really are),
// and the identity of every entry below them.
type lateReach struct {
	keys      protectedFiles
	haveKeys  bool
	roots     []os.FileInfo
	rootPaths []string
	rootsOK   bool
	haveRoots bool
	ids       map[string]bool
	idsOK     bool
	haveIDs   bool
}

// follow resolves the link at path hop by hop, as the kernel does. Every link
// text and every place a hop passes through is told by its protected names
// (a link to a protected link is not ordinary even when the file at the very
// end carries no such name), a missing target is not ordinary, and the place
// it ends in must be reachable (not the root, the home or a parent of it).
func (s *lateScan) follow(path string) (string, bool) {
	current, hops := string(filepath.Separator), 0
	pending := strings.Split(path, "/")
	for steps := 0; len(pending) > 0; steps++ {
		name := pending[0]
		pending = pending[1:]
		if steps > 4096 {
			return "", false
		}
		switch name {
		case "", ".":
			continue
		case "..":
			current = filepath.Dir(current)
			continue
		}
		next := filepath.Join(current, name)
		if lateNamesProtected(next) {
			return "", false
		}
		info, err := pathLstat(next)
		if err != nil {
			return "", false
		}
		if info.Mode()&os.ModeSymlink == 0 {
			current = next
			continue
		}
		hops++
		text, err := os.Readlink(next)
		if hops > 40 || err != nil || strings.IndexByte(text, 0) >= 0 || lateNamesProtected(text) {
			return "", false
		}
		if filepath.IsAbs(text) {
			current = string(filepath.Separator)
		}
		pending = append(strings.Split(text, "/"), pending...)
	}
	return current, s.placeOrdinary(current)
}

// reachesProtected reports whether the entry at real (info is its Lstat),
// which the scan reached through a link or which has a second hard link, is
// one of the protected ones or may be: an authorized-keys file by identity, a
// protected folder or anything below it, and, for a regular file with a
// second hard link, any file below such a folder. What cannot be told (an
// unreadable home, a state tree over the bound) is protected, because the
// scan only ever moves a call from closed to the outage-mode outcome.
func (s *lateScan) reachesProtected(real string, info os.FileInfo) bool {
	if !s.reach.haveKeys {
		s.reach.keys, s.reach.haveKeys = newProtectedFiles(s.home), true
	}
	for _, key := range s.reach.keys {
		if key.unknown || key.info != nil && os.SameFile(info, key.info) {
			return true
		}
	}
	if !s.reach.haveRoots {
		s.listRoots()
	}
	if !s.reach.rootsOK {
		return true
	}
	for dir := real; ; dir = filepath.Dir(dir) {
		dirInfo, err := pathLstat(dir)
		if err != nil {
			return true
		}
		for _, root := range s.reach.roots {
			if os.SameFile(dirInfo, root) {
				return true
			}
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	if info.Mode().IsRegular() && linkCount(real, info) > 1 {
		return s.hardLinkedToProtected(real, info)
	}
	return false
}

// listRoots finds the folders of the home that carry a protected name.
func (s *lateScan) listRoots() {
	s.reach.haveRoots = true
	entries, err := os.ReadDir(s.home)
	if err != nil || len(entries) > lateHomeEntries {
		return
	}
	for _, entry := range entries {
		if !lateNamesProtected(entry.Name()) {
			continue
		}
		real, err := filepath.EvalSymlinks(filepath.Join(s.home, entry.Name()))
		if err != nil {
			continue
		}
		info, err := pathLstat(real)
		if err != nil {
			return
		}
		s.reach.roots = append(s.reach.roots, info)
		s.reach.rootPaths = append(s.reach.rootPaths, real)
	}
	s.reach.rootsOK = true
}

// hardLinkedToProtected reports whether a regular file with a second hard
// link is the same file as any entry below a protected folder (or what a link
// there leads to).
func (s *lateScan) hardLinkedToProtected(real string, info os.FileInfo) bool {
	if !s.reach.haveIDs {
		s.indexRoots()
	}
	identity := fileIdentityForPath(real, info)
	return !s.reach.idsOK || identity == "" || s.reach.ids[identity]
}

// indexRoots records the identity of every entry below the protected folders,
// and of what each link there leads to, within lateReachEntries entries.
func (s *lateScan) indexRoots() {
	s.reach.haveIDs = true
	s.reach.ids = map[string]bool{}
	visited := 0
	add := func(path string, info os.FileInfo) {
		if identity := fileIdentityForPath(path, info); identity != "" {
			s.reach.ids[identity] = true
		}
	}
	for _, root := range s.reach.rootPaths {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if visited++; visited > lateReachEntries {
				return fs.SkipAll
			}
			if walkErr != nil {
				return nil
			}
			if info, err := entry.Info(); err == nil {
				add(path, info)
				if info.Mode()&os.ModeSymlink != 0 {
					if target, err := pathStat(path); err == nil {
						add(path, target)
					}
				}
			}
			return nil
		})
		if err != nil {
			return
		}
	}
	s.reach.idsOK = visited <= lateReachEntries
}
