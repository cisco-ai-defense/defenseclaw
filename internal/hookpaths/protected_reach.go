// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
)

// Grade is the strength of one path finding. Readers combine grades with Max:
// a possible name never clears a named protected destination.
type Grade uint8

const (
	GradeNone Grade = iota
	GradePossible
	GradeNamed
)

func (g Grade) Max(other Grade) Grade {
	if other > g {
		return other
	}
	return g
}

func (g Grade) String() string {
	switch g {
	case GradePossible:
		return "possible-target"
	case GradeNamed:
		return "protected-target"
	default:
		return ""
	}
}

type reachNames struct {
	files       []string
	directories []string
	trees       []string
}

func (s *reachNames) addFile(path string) {
	path = filepath.Clean(path)
	if !slices.Contains(s.files, path) {
		s.files = append(s.files, path)
	}
}
func (s *reachNames) addDirectory(path string) {
	path = filepath.Clean(path)
	if !slices.Contains(s.directories, path) {
		s.directories = append(s.directories, path)
	}
}
func (s *reachNames) addTree(path string) {
	path = filepath.Clean(path)
	if !slices.Contains(s.trees, path) {
		s.trees = append(s.trees, path)
	}
}
func (s *reachNames) has(path string) bool {
	path = filepath.Clean(path)
	for _, dir := range s.directories {
		if samePathName(path, dir) {
			return true
		}
	}
	return s.hasCandidate(path)
}

// An exact protected directory is a protected destination, but passing
// through it does not make every unlisted child a protected file.
func (s *reachNames) hasCandidate(path string) bool {
	path = filepath.Clean(path)
	for _, file := range s.files {
		if samePathName(path, file) {
			return true
		}
	}
	for _, tree := range s.trees {
		if pathAtOrUnder(path, tree) {
			return true
		}
	}
	return false
}

// protectedReachNames resolves the protected side once per evaluation. A
// lexical name remains protected even when its physical path cannot be read.
func (m *TargetMemo) protectedReachNames(home string, sshOnly bool) reachNames {
	key := home
	if sshOnly {
		key = "ssh:" + home
	}
	if m != nil {
		m.mu.Lock()
		names, ok := m.reachNames[key]
		m.mu.Unlock()
		if ok {
			return names
		}
	}
	names := reachNames{}
	ssh := filepath.Join(home, ".ssh")
	names.addDirectory(ssh)
	addResolved := func(path string, add func(string)) {
		add(path)
		// A share's lexical protected names remain valid while its root is
		// pending. Resolve its physical side through the identity reads below,
		// in parallel with the target, so one slow root does not consume the
		// target's entire answer window.
		if SharePath(path) {
			return
		}
		if resolved, ok := m.resolveWriteTarget(path); ok {
			add(resolved)
		}
	}
	for _, name := range AuthorizedKeysFiles {
		addResolved(filepath.Join(ssh, name), names.addFile)
	}
	for _, name := range SSHControlFiles {
		addResolved(filepath.Join(ssh, name), names.addFile)
	}
	if !sshOnly {
		state := filepath.Join(home, ".defenseclaw")
		for _, name := range activeStateFiles {
			addResolved(filepath.Join(state, name), names.addFile)
		}
		for _, name := range activeStateTrees {
			addResolved(filepath.Join(state, name), names.addTree)
		}
	}
	if !SharePath(ssh) {
		if resolved, ok := m.resolveWriteTarget(ssh); ok {
			names.addDirectory(resolved)
		}
	}
	if m != nil {
		m.mu.Lock()
		if m.reachNames == nil {
			m.reachNames = make(map[string]reachNames)
		}
		if prior, ok := m.reachNames[key]; ok {
			names = prior
		} else {
			m.reachNames[key] = names
		}
		m.mu.Unlock()
	}
	return names
}

// ProtectedReach grades a write target against both spellings and file
// identities of protected files. It uses the hook's bounded path readers; an
// unanswered share remains Possible, while a reached link name is Named.
func ProtectedReach(target, home string, memo *TargetMemo) Grade {
	return memo.ProtectedReach(target, home)
}

func (m *TargetMemo) ProtectedReach(target, home string) Grade {
	return m.protectedReach(target, home, false)
}

// ProtectedSSHReach applies the same two-sided resolver to the SSH rule's
// protected set. State files belong to their own rule.
func ProtectedSSHReach(target, home string, memo *TargetMemo) Grade {
	return memo.protectedReach(target, home, true)
}

func (m *TargetMemo) protectedReach(target, home string, sshOnly bool) Grade {
	if !filepath.IsAbs(target) || !filepath.IsAbs(home) {
		return GradePossible
	}
	names := m.protectedReachNames(home, sshOnly)
	target = filepath.Clean(target)
	if names.has(target) {
		return GradeNamed
	}

	type answer struct {
		info os.FileInfo
		err  error
	}
	// On a share the two sides of an identity comparison must read within
	// the same first-contact window. Starting the protected reads only after
	// the target returns would misgrade a reachable link as unanswered.
	type protectedRead struct {
		done chan struct{}
		answer
	}
	protectedReady := make(map[string]*protectedRead)
	if SharePath(target) || SharePath(home) {
		start := func(path string) {
			if _, started := protectedReady[path]; started {
				return
			}
			read := &protectedRead{done: make(chan struct{})}
			protectedReady[path] = read
			go func() {
				read.info, read.err = PathStat(path)
				close(read.done)
			}()
		}
		for _, path := range names.files {
			start(path)
			start(filepath.Dir(path))
		}
		for _, path := range names.trees {
			start(path)
		}
	}
	readProtected := func(path string) (os.FileInfo, error) {
		if read := protectedReady[path]; read != nil {
			<-read.done
			return read.info, read.err
		}
		return PathStat(path)
	}
	fileReady, parentReady, entryReady := make(chan answer, 1), make(chan answer, 1), make(chan answer, 1)
	parent := filepath.Dir(target)
	go func() { info, err := PathStat(target); fileReady <- answer{info, err} }()
	go func() { info, err := PathStat(parent); parentReady <- answer{info, err} }()
	go func() { info, err := PathLstat(target); entryReady <- answer{info, err} }()
	file, directory, entry := <-fileReady, <-parentReady, <-entryReady

	// A reached file can be a hard link; a reached parent can be a linked
	// directory whose final child has not been created yet.
	var wg sync.WaitGroup
	type identityMatch struct{ matched, unknown, file bool }
	matches := make(chan identityMatch, len(names.files)*2+len(names.directories)+len(names.trees))
	unknownFiles, unknownParents := false, false
	if file.err == nil {
		for _, path := range names.files {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				info, err := readProtected(path)
				matches <- identityMatch{matched: err == nil && os.SameFile(file.info, info), unknown: ShareUnanswered(err), file: true}
			}(path)
		}
	}
	if directory.err == nil {
		for _, path := range names.files {
			if !samePathName(filepath.Base(target), filepath.Base(path)) {
				continue
			}
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				info, err := readProtected(filepath.Dir(path))
				matches <- identityMatch{matched: err == nil && os.SameFile(directory.info, info), unknown: ShareUnanswered(err)}
			}(path)
		}
		for _, path := range names.trees {
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				info, err := readProtected(path)
				matches <- identityMatch{matched: err == nil && os.SameFile(directory.info, info), unknown: ShareUnanswered(err)}
			}(path)
		}
	}
	wg.Wait()
	close(matches)
	for match := range matches {
		if match.matched {
			return GradeNamed
		}
		if match.file {
			unknownFiles = unknownFiles || match.unknown
		} else {
			unknownParents = unknownParents || match.unknown
		}
	}

	// Resolve the complete target before accepting an ordinary file or parent.
	// A successful Stat can otherwise hide a protected directory reached by a
	// link, and an ordinary missing child can hide a protected link hop.
	reached := false
	unread := false
	lstat := func(path string) (os.FileInfo, error) {
		if names.hasCandidate(path) {
			reached = true
		}
		info, err := PathLstat(path)
		if ShareUnanswered(err) {
			unread = true
		}
		return info, err
	}
	readlink := func(path string) (string, error) {
		link, err := PathReadlink(path)
		if ShareUnanswered(err) {
			unread = true
		}
		return link, err
	}
	resolved, _, _, ok := walkWritePathMemoWithReaders("", target, 0, false, false, nil, lstat, readlink)
	if reached || ok && names.has(resolved) {
		return GradeNamed
	}
	// A missing local component or a regular file used as a directory
	// cannot lead this write to another path. The walk above has already
	// checked every reached link and protected name.
	if !SharePath(target) && !unread && (os.IsNotExist(file.err) || errors.Is(file.err, syscall.ENOTDIR)) {
		return GradeNone
	}

	// The ordinary parent of a missing local file is a complete answer even
	// when another, unrelated share is pending.
	if os.IsNotExist(entry.err) && directory.err == nil {
		if resolved, ok := m.resolveWriteTarget(parent); ok && !names.has(filepath.Join(resolved, filepath.Base(target))) {
			return GradeNone
		}
	}
	if file.err == nil {
		if unknownFiles {
			return GradePossible
		}
		return GradeNone
	}
	if ShareUnanswered(entry.err) && directory.err == nil && !unknownParents {
		// The final entry gave no answer. Its reached ordinary parent
		// cannot make that unread identity a named protected file.
		return GradePossible
	}

	if unread || unknownParents || ShareUnanswered(file.err) || ShareUnanswered(entry.err) || ShareUnanswered(directory.err) || !ok {
		return GradePossible
	}
	return GradeNone
}
