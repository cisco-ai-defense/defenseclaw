// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"sync"
)

// TargetMemo keeps the file system answers of one hook evaluation: the
// write-target walks and the Windows target-word checks
// (actionWindowsWordNamesTarget). Every word of a long command is placed
// in the same working directory and home, and the gateway reads each
// statement of it again on its own (one simple-command pass per statement),
// so without the memo the same directories were walked once per word, per
// reading and per pass. On Windows a walk is one GetFileAttributesEx per
// path component, about 30 microseconds on the test hosts: a benign
// 100-assignment command paid about 70,000 of them in the gateway and
// missed the hook answer window (rel-1-0-2:GAP-0568). With the memo each
// distinct path prefix is read once per evaluation.
//
// A memo holds for one evaluation only, and never outlives the call that
// made it: the file system changes between hook calls (one call can create
// the link the next call writes through). Within one evaluation every
// reader already assumes the files stay as they are; the memo makes all of
// them see the same answer. A nil memo reads the file system every time.
type TargetMemo struct {
	mu sync.Mutex
	// startup is the agent's shell startup for this evaluation, from the
	// hook client's header (nil: the process's own).
	startup *ShellStartup
	// prefixes is the write-target walk state after each absolute path
	// prefix (walkWritePathMemo).
	prefixes map[string]walkState
	// words are the answers of actionWindowsWordNamesTarget's candidate
	// check, which depend only on the key and the file system.
	words map[memoWordKey]bool
	// homes resolves each home once (actionProtectedStatePath).
	homes map[string]*actionStateHome
	// keys lists each home's protected key files once
	// (ProtectedAuthorizedKeysPaths), and files their identities
	// (newProtectedFiles).
	keys  map[string][]string
	files map[string]protectedFiles
	// resolved are the answers of resolveWriteTarget by the exact path: the
	// scans of one call ask for the same operands again (GAP-0483).
	resolved map[string]resolvedTarget
	// The shared reach reader keeps complete names and per-parent answers.
	reachNames   map[string]reachNames
	reachParents map[reachParentKey]reachParentAnswer
	// work counts the path components the memo walked on the file system
	// and the candidate checks it computed (Work); candidates counts the
	// Windows candidate checks among them (WorkParts).
	work       int
	candidates int
}

// maxTargetMemoEntries bounds a memo: past it, answers are computed and not
// kept. A call under the hook payload cap has fewer distinct words.
const maxTargetMemoEntries = 1 << 16

// NewTargetMemo returns an empty memo for one evaluation.
func NewTargetMemo() *TargetMemo {
	return &TargetMemo{
		prefixes: make(map[string]walkState),
		words:    make(map[memoWordKey]bool),
		homes:    make(map[string]*actionStateHome),
		keys:     make(map[string][]string),
		files:    make(map[string]protectedFiles),
		resolved: make(map[string]resolvedTarget),
	}
}

type resolvedTarget struct {
	path string
	ok   bool
}

// protectedFiles is newProtectedFiles of home, once per memo.
func (m *TargetMemo) protectedFiles(home string) protectedFiles {
	if m == nil {
		return newProtectedFiles(home)
	}
	m.mu.Lock()
	files, ok := m.files[home]
	m.mu.Unlock()
	if !ok {
		files = newProtectedFilesWith(home, m)
		m.mu.Lock()
		m.files[home] = files
		m.mu.Unlock()
	}
	return slices.Clone(files)
}

// ProtectedAuthorizedKeysPaths is the package function of that name, with
// the file system answers of the evaluation m (nil: none).
func (m *TargetMemo) ProtectedAuthorizedKeysPaths(home string) []string {
	if m == nil {
		return ProtectedAuthorizedKeysPaths(home)
	}
	m.mu.Lock()
	paths, ok := m.keys[home]
	m.mu.Unlock()
	if !ok {
		paths = protectedAuthorizedKeysPaths(home, m)
		m.mu.Lock()
		m.keys[home] = paths
		m.mu.Unlock()
	}
	return slices.Clone(paths)
}

// Work reports the path components this memo walked on the file system and
// the Windows candidate checks it computed, a deterministic measure of an
// evaluation's file system work for the hook budget tests (GAP-0568).
func (m *TargetMemo) Work() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.work
}

// WorkParts splits Work into the path components walked and the Windows
// candidate checks computed. Each is linear in the statements; a Windows
// gateway also reads every word as a Windows candidate, which a POSIX host
// never does, so the two are bounded apart (rel-1-0-2:GAP-0568 on the
// Windows x64 CI suite).
func (m *TargetMemo) WorkParts() (walked, candidates int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.work - m.candidates, m.candidates
}

func (m *TargetMemo) noteWork() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.work++
	m.mu.Unlock()
}

func (m *TargetMemo) noteCandidateWork() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.work++
	m.candidates++
	m.mu.Unlock()
}

// walkState is the write-target walk after a path prefix: the physical
// directory reached, the missing-component stack ("..", walkWritePath) and
// the link hops spent. failed marks a prefix the walk cannot cross.
type walkState struct {
	current   string
	crossed   []bool
	linkDepth int
	failed    bool
}

type memoWordKey struct {
	candidate, cwd, home    string
	stateOnly, sshDirectory bool
}

func (m *TargetMemo) prefix(key string) (walkState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.prefixes[key]
	return state, ok
}

func (m *TargetMemo) storePrefix(key string, state walkState) {
	state.crossed = append([]bool(nil), state.crossed...)
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.prefixes) < maxTargetMemoEntries {
		m.prefixes[key] = state
	}
}

func (m *TargetMemo) word(key memoWordKey) (answer, ok bool) {
	if m == nil {
		return false, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	answer, ok = m.words[key]
	return answer, ok
}

func (m *TargetMemo) storeWord(key memoWordKey, answer bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.words) < maxTargetMemoEntries {
		m.words[key] = answer
	}
}

// stateHome is the one actionStateHome of home in this memo, already
// resolved; without a memo, a fresh one.
func (m *TargetMemo) stateHome(home string) *actionStateHome {
	if m == nil {
		return &actionStateHome{home: home}
	}
	m.mu.Lock()
	state, ok := m.homes[home]
	m.mu.Unlock()
	if ok {
		return state
	}
	state = &actionStateHome{home: home, memo: m, done: true}
	state.resolved, state.ok = m.resolveWriteTarget(home)
	m.mu.Lock()
	defer m.mu.Unlock()
	if earlier, ok := m.homes[home]; ok {
		return earlier
	}
	m.homes[home] = state
	return state
}

// ResolveWriteTarget is the package function of that name, with the file
// system answers of the evaluation m (nil: none).
func (m *TargetMemo) ResolveWriteTarget(path string) (string, bool) {
	return m.resolveWriteTarget(path)
}

// resolveWriteTarget is ResolveWriteTarget through the memo.
func (m *TargetMemo) resolveWriteTarget(path string) (string, bool) {
	if m == nil {
		return ResolveWriteTarget(path)
	}
	writeTargetWalks.Add(1)
	m.mu.Lock()
	known, found := m.resolved[path]
	m.mu.Unlock()
	if found {
		return known.path, known.ok
	}
	resolved, _, _, ok := walkWritePathMemo("", path, 0, false, false, m)
	m.mu.Lock()
	if len(m.resolved) < maxTargetMemoEntries {
		m.resolved[path] = resolvedTarget{path: resolved, ok: ok}
	}
	m.mu.Unlock()
	return resolved, ok
}

// WithShellStartup sets the agent's shell startup the evaluation's safe
// proofs judge against and returns the memo.
func (m *TargetMemo) WithShellStartup(startup *ShellStartup) *TargetMemo {
	if m != nil {
		m.startup = startup
	}
	return m
}

// ShellStartup is the startup set by WithShellStartup (nil: none).
func (m *TargetMemo) ShellStartup() *ShellStartup {
	if m == nil {
		return nil
	}
	return m.startup
}

// shellStartup is the agent's startup the evaluation was given, or this
// process's own.
func (m *TargetMemo) shellStartup() ShellStartup {
	if m != nil && m.startup != nil {
		return *m.startup
	}
	return CurrentShellStartup()
}
