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
// decides whether a file is one of the protected ones by identity. The scan
// identifies a protected file positively: a file is protected only when its
// identity is found among the protected ones. A bound that is hit, an
// unreadable folder and a link to a folder are not found, so the file they
// might have held is not proven protected (the call is then ordinary in the
// open tier, with the late-gateway warning; the strict tier never reaches the
// scan).
var lateReachEntries = 20000

// lateHomeEntries bounds the entries of the home the scan lists to find the
// protected folders in it; the entries past it are not listed.
var lateHomeEntries = 20000

// lateReach is the protected-reach state of one call's scan, built only when
// a path needs it: the protected authorized-keys files, the folders in the
// home that carry a protected name (followed to the place they really are),
// and the identity of every entry below them.
type lateReach struct {
	keys      protectedFiles
	haveKeys  bool
	roots     []os.FileInfo
	rootPaths []string
	haveRoots bool
	ids       map[string]bool
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
		text, err := pathReadlink(next)
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
// second hard link, any file below such a folder. Only a proven identity is
// protected: what the scan could not list or index (an unreadable folder, a
// tree over the bound, an authorized-keys file it could not read) is not
// proven, and a not-proven ordinary alias must not be denied for the budget
// the scan ran out of or for a protected file it could not read.
func (s *lateScan) reachesProtected(real string, info os.FileInfo) bool {
	if !s.reach.haveKeys {
		for _, home := range s.indexHomes {
			s.reach.keys = append(s.reach.keys, newProtectedFiles(home)...)
		}
		s.reach.haveKeys = true
	}
	for _, key := range s.reach.keys {
		if key.info != nil && os.SameFile(info, key.info) {
			return true
		}
	}
	if !s.reach.haveRoots {
		s.listRoots()
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

// listRoots finds the folders of the homes that carry a protected name, among
// the first lateHomeEntries entries of each it can read.
func (s *lateScan) listRoots() {
	s.reach.haveRoots = true
	for _, home := range s.indexHomes {
		entries, _ := pathReadDir(home)
		if len(entries) > lateHomeEntries {
			entries = entries[:lateHomeEntries]
		}
		for _, entry := range entries {
			if !lateNamesProtected(entry.Name()) {
				continue
			}
			real, err := pathEvalSymlinks(filepath.Join(home, entry.Name()))
			if err != nil {
				continue
			}
			info, err := pathLstat(real)
			if err != nil {
				continue
			}
			s.reach.roots = append(s.reach.roots, info)
			s.reach.rootPaths = append(s.reach.rootPaths, real)
		}
	}
}

// hardLinkedToProtected reports whether a regular file with a second hard
// link is the same file as an entry the index found below a protected folder
// (or what a link there leads to). A file the index did not reach is not
// proven protected.
func (s *lateScan) hardLinkedToProtected(real string, info os.FileInfo) bool {
	if !s.reach.haveIDs {
		s.indexRoots()
	}
	identity := fileIdentityForPath(real, info)
	return identity != "" && s.reach.ids[identity]
}

// indexRoots records the identity of the entries below the protected folders,
// and of what each link there leads to, within lateReachEntries entries. A
// folder it cannot read and a link to a folder it does not enter are left
// out.
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
		_ = pathWalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
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
	}
}
