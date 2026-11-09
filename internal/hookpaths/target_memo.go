// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
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
// A memo holds for one scan only, and never outlives it: the file system
// changes between hook calls (one call can create the link the next call
// writes through) and between the scans of one call (a link can be
// retargeted, a hard link made or removed, a keys file replaced). Each entry
// point of an evaluation starts a scan (beginScan) that drops every answer of
// the earlier ones, so a scan judges the names as they are when it runs.
// Within one scan every reader already assumes the files stay as they are;
// the memo makes all of them see the same answer. A nil memo reads the file
// system every time.
type TargetMemo struct {
	mu sync.Mutex
	// prefixes is the write-target walk state after each absolute path
	// prefix (walkWritePathMemo).
	prefixes map[string]walkState
	// words are the answers of actionWindowsWordNamesTarget's candidate
	// check, which depend only on the key and the file system.
	words map[memoWordKey]bool
	// homes resolves each home once (actionProtectedStatePath).
	homes map[string]*actionStateHome
	// keys lists the protected key files of each home once
	// (ProtectedAuthorizedKeysPaths), and files their identities
	// (newProtectedFiles). A keys file path can be a link that was retargeted
	// and a keys file can be created or replaced between two scans, so these
	// hold for one scan like every other answer.
	keys  map[string][]string
	files map[string]protectedFiles
	// resolved are the answers of resolveWriteTarget by the exact path: the
	// readers of one scan ask for the same operands again (GAP-0483).
	resolved map[string]resolvedTarget
	// lstats and stats are the answers of the evaluation's lstat and stat of
	// a name that exists or is missing (reads): the scans of one call read
	// each operand again and again, and on Windows each read first walks the
	// folders of the name for a link into a network share (rel-1-0-9:GAP-0943).
	// They hold for one scan: each entry point of the evaluation starts a new
	// one (beginScan), so a name that changed between two scans (a file that
	// became or stopped being a hard link to a protected file) is read again.
	lstats, stats map[string]memoRead
	// folders are the folders the scan has read below and found no link into a
	// network share.
	folders folderProofs
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
		lstats:   make(map[string]memoRead),
		stats:    make(map[string]memoRead),
	}
}

// memoRead is what a stat or lstat of a name returned.
type memoRead struct {
	info os.FileInfo
	err  error
}

// beginScan starts a scan of the evaluation and drops every answer the
// earlier scans gave: the reads of names, the identities of the protected
// files, the write-target walks and resolved targets, the key file paths, the
// resolved homes and the Windows word checks. All of them are answers of the
// file system, and the file system can change between two scans (a link
// retargeted, a hard link made or removed, a keys file replaced), so the next
// read of any of them is a read of the file system. Only the work counters
// stay (Work).
func (m *TargetMemo) beginScan() {
	if m == nil {
		return
	}
	m.mu.Lock()
	clear(m.prefixes)
	clear(m.words)
	clear(m.homes)
	clear(m.keys)
	clear(m.files)
	clear(m.resolved)
	clear(m.lstats)
	clear(m.stats)
	m.folders.clear()
	m.mu.Unlock()
}

// lstat is pathLstat through the memo. Only a name that exists or is missing
// is kept: any other error (a share that did not answer, a refused read) is
// read again, so a read the share walk reports unanswered is never taken for
// an answer. Each read that is not answered from the memo is still a
// pathLstat, walked for a link into a share as any other read.
func (m *TargetMemo) lstat(name string) (os.FileInfo, error) {
	if m == nil {
		return pathLstat(name)
	}
	m.mu.Lock()
	known, ok := m.lstats[name]
	m.mu.Unlock()
	if ok {
		return known.info, known.err
	}
	info, err := m.folders.lstat(name)
	m.keep(m.lstats, name, info, err)
	return info, err
}

// stat is pathStat through the memo. A name the evaluation has read with
// lstat answers stat as well when that read decides it: a missing name is
// missing, and a name that is no link is the same file.
func (m *TargetMemo) stat(name string) (os.FileInfo, error) {
	if m == nil {
		return pathStat(name)
	}
	m.mu.Lock()
	known, ok := m.stats[name]
	if !ok {
		if link, seen := m.lstats[name]; seen && (os.IsNotExist(link.err) ||
			link.err == nil && link.info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0) {
			known, ok = link, true
		}
	}
	m.mu.Unlock()
	if ok {
		return known.info, known.err
	}
	info, err := m.folders.stat(name)
	m.keep(m.stats, name, info, err)
	return info, err
}

func (m *TargetMemo) keep(into map[string]memoRead, name string, info os.FileInfo, err error) {
	if err != nil && !os.IsNotExist(err) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(into) < maxTargetMemoEntries {
		into[name] = memoRead{info, err}
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
