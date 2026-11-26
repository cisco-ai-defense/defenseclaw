// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"sync"
	"sync/atomic"

	"mvdan.cc/sh/v3/syntax"
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
	// excuseNonWrites makes the mention scan leave a protected name alone when
	// the statement that holds it only reads (ActionMentionsNoWriteRole).
	excuseNonWrites bool
	// excuseUnknownRoles widens that scan to the unknown tier
	// (ActionMentionsNoKnownWrite): see unknownRolesExcused.
	excuseUnknownRoles bool
	// startup is the agent's shell startup for this evaluation, from the
	// hook client's header (nil: the process's own).
	startup *ShellStartup
	// callDots is set when the words of the whole call this evaluation
	// judges may turn dotglob on (WithCallWords).
	callDots atomic.Bool
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
	// entries are the answers of stateEntryMayDiffer by the exact path.
	entries map[string]stateEntry
	// The shared reach reader keeps complete names and per-parent answers.
	reachNames   map[string]reachNames
	reachParents map[reachParentKey]reachParentAnswer
	// work counts the path components the memo walked on the file system
	// and the candidate checks it computed (Work); candidates counts the
	// Windows candidate checks among them (WorkParts).
	work       int
	candidates int
	// call is the memory of the hook call the memo was made in, when the call
	// keeps one (memoHookCall): the memo resolves its write targets there.
	call *TargetMemo
	// owner is the hook call whose memory this memo is (hookCall.targets,
	// nil for the memo of one evaluation). It outlives each evaluation, so
	// it keeps no answer read while the call's budget cut a share wait
	// short (hookCall.keepsSince): the share may answer later in the call,
	// and an evaluation after that reads it (rel-1-0-10:GAP-1606).
	owner *hookCall
	// unread is the memo of this evaluation's decisions that read no file
	// system (UnreadCommandDecision), and unreadDecisions their answers by
	// input. Nothing they read is the host's, so they keep apart from this
	// memo's own answers.
	unread          *TargetMemo
	unreadDecisions map[unreadDecisionKey]string
	// parsed are the trees parsedShell handed out, by command.
	parsed map[string]memoParse
}

// memoParse is one parseShell answer kept by a memo.
type memoParse struct {
	file *syntax.File
	ok   bool
}

// maxMemoParses and maxMemoParseBytes bound the trees a memo keeps: a few
// commands of the hook payload's size.
const (
	maxMemoParses     = 8
	maxMemoParseBytes = 64 << 10
)

// parsedShell is parseShell of command for a reader that only reads the
// tree: the memo parses each command once and hands every such reader the
// same tree. One decision read the same 8 KB command with the parser four
// times for the sed backup reader (both readings), the make proof and the
// POSIX mention scan, most of a copy-mode by-name decision (FIX-F3PERF).
// Only readers that never change a tree may use it:
// literalWriteOperandsWithParsedKnown renames the shadowed builtins of its
// tree in place (knownShadow), so it and the readers that hand it their
// tree parse their own.
func (m *TargetMemo) parsedShell(command string) (*syntax.File, bool) {
	if m == nil || len(command) > maxMemoParseBytes {
		return parseShell(command)
	}
	m.mu.Lock()
	kept, found := m.parsed[command]
	m.mu.Unlock()
	if found {
		return kept.file, kept.ok
	}
	file, ok := parseShell(command)
	m.mu.Lock()
	if m.parsed == nil {
		m.parsed = make(map[string]memoParse)
	}
	if len(m.parsed) < maxMemoParses {
		m.parsed[command] = memoParse{file: file, ok: ok}
	}
	m.mu.Unlock()
	return file, ok
}

// maxTargetMemoEntries bounds a memo: past it, answers are computed and not
// kept. A call under the hook payload cap has fewer distinct words.
const maxTargetMemoEntries = 1 << 16

// NewTargetMemo returns an empty memo for one evaluation. Made in a hook call
// that keeps a memory of the file system (memoHookCall), it resolves its write
// targets and state entries in the call's memory: the gateway and the scans
// make a memo for each evaluation of the call, and each walked the same paths
// again. A Codex call on Windows whose command named a script behind the
// system's link bound walked the 63 links once per memo, 7,000 lstat calls
// and 0.7 s of its answer (rel-1-0-10:GAP-0447). The answers depend only on
// the path and the file system, which is the same for the whole decision.
func NewTargetMemo() *TargetMemo {
	memo := newTargetMemo()
	if call := memoHookCall(); call != nil {
		memo.call = call.targets()
	}
	return memo
}

// newTargetMemo is an empty memo that keeps its own answers.
func newTargetMemo() *TargetMemo {
	return &TargetMemo{
		prefixes: make(map[string]walkState),
		words:    make(map[memoWordKey]bool),
		homes:    make(map[string]*actionStateHome),
		keys:     make(map[string][]string),
		files:    make(map[string]protectedFiles),
		resolved: make(map[string]resolvedTarget),
		entries:  make(map[string]stateEntry),
	}
}

type resolvedTarget struct {
	path string
	ok   bool
	// unanswered: the walk failed on a local read that did not answer
	// (walkWritePathWhy).
	unanswered bool
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
		mark := m.cutMark()
		files = newProtectedFilesWith(home, m)
		if m.keepsSince(mark) {
			m.mu.Lock()
			m.files[home] = files
			m.mu.Unlock()
		}
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
		mark := m.cutMark()
		paths = protectedAuthorizedKeysPaths(home, m)
		if m.keepsSince(mark) {
			m.mu.Lock()
			m.keys[home] = paths
			m.mu.Unlock()
		}
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
	// unanswered: failed on a local read that did not answer
	// (walkWritePathWhy).
	unanswered bool
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

// storePrefix keeps the walk state after the prefix key, unless the budget
// cut a share wait of the call short since the walk began (mark: cutMark).
func (m *TargetMemo) storePrefix(key string, state walkState, mark uint64) {
	if !m.keepsSince(mark) {
		return
	}
	state.crossed = append([]bool(nil), state.crossed...)
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.prefixes) < maxTargetMemoEntries {
		m.prefixes[key] = state
	}
}

// cutCall is the hook call whose budget cuts decide what m keeps: the call
// whose memory m is, or the call an evaluation memo was made in (nil: none,
// m keeps every answer for its one evaluation, as off Windows).
func (m *TargetMemo) cutCall() *hookCall {
	switch {
	case m == nil:
		return nil
	case m.owner != nil:
		return m.owner
	case m.call != nil:
		return m.call.owner
	}
	return nil
}

// cutMark is hookCall.cutMark of cutCall.
func (m *TargetMemo) cutMark() uint64 { return m.cutCall().cutMark() }

// keepsSince reports whether m keeps an answer read since mark: only when
// the budget of its call cut no share wait short meanwhile
// (hookCall.keepsSince).
func (m *TargetMemo) keepsSince(mark uint64) bool { return m.cutCall().keepsSince(mark) }

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
	mark := m.cutMark()
	state = &actionStateHome{home: home, memo: m, done: true}
	state.resolved, state.ok = m.resolveWriteTarget(home)
	if !m.keepsSince(mark) {
		return state
	}
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
	resolved, ok, _ := m.resolveWriteTargetWhy(path)
	return resolved, ok
}

// resolveWriteTargetWhy is resolveWriteTargetWhy through the memo.
func (m *TargetMemo) resolveWriteTargetWhy(path string) (resolved string, ok, unanswered bool) {
	if m == nil {
		return resolveWriteTargetWhy(path)
	}
	if m.call != nil {
		return m.call.resolveWriteTargetWhy(path)
	}
	writeTargetWalks.Add(1)
	m.mu.Lock()
	known, found := m.resolved[path]
	m.mu.Unlock()
	if found {
		return known.path, known.ok, known.unanswered
	}
	mark := m.cutMark()
	resolved, _, _, ok = walkWritePathWhy("", path, 0, false, false, m, &unanswered)
	if !m.keepsSince(mark) {
		// A share on the way did not answer only because the call's
		// budget cut its wait short: the next ask may read it
		// (rel-1-0-10:GAP-1606).
		return resolved, ok, unanswered
	}
	m.mu.Lock()
	if len(m.resolved) < maxTargetMemoEntries {
		m.resolved[path] = resolvedTarget{path: resolved, ok: ok, unanswered: unanswered}
	}
	m.mu.Unlock()
	return resolved, ok, unanswered
}

// stateEntry is one answer of actionStateEntryMayDiffer.
type stateEntry struct{ differ, missing bool }

// stateEntryMayDiffer is actionStateEntryMayDiffer through the memo. The
// state scans ask for the entry of the same word in every statement and
// every reading of the call, and on Windows the Lstat of a name behind folder
// links first walks each link of it for the share check: a word behind the
// system's link bound cost a Codex call 77 walks of 63 links, 0.8 s
// (rel-1-0-10:GAP-0447).
func (m *TargetMemo) stateEntryMayDiffer(value string) (differ, missing bool) {
	if m == nil {
		return actionStateEntryMayDiffer(value)
	}
	if m.call != nil {
		return m.call.stateEntryMayDiffer(value)
	}
	m.mu.Lock()
	known, found := m.entries[value]
	m.mu.Unlock()
	if found {
		return known.differ, known.missing
	}
	mark := m.cutMark()
	differ, missing = actionStateEntryMayDiffer(value)
	if !m.keepsSince(mark) {
		return differ, missing
	}
	m.mu.Lock()
	if len(m.entries) < maxTargetMemoEntries {
		m.entries[value] = stateEntry{differ: differ, missing: missing}
	}
	m.mu.Unlock()
	return differ, missing
}

// nonWritesExcused is set for the scan ActionMentionsNoWriteRole runs; a nil memo
// (a scan that carries none) never excuses.
func (m *TargetMemo) nonWritesExcused() bool { return m != nil && m.excuseNonWrites }

// unknownRolesExcused is set for the scan ActionMentionsNoKnownWrite runs: a
// reader statement keeps its excuse beside a program the scan has no model
// of (a dynamic program word, an echo of an expansion), in a pipeline and with
// its output redirected to a file the call names (rel-1-0-10:GAP-0843).
func (m *TargetMemo) unknownRolesExcused() bool { return m != nil && m.excuseUnknownRoles }

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

// WithCallWords records the whole call the evaluation judges and returns
// the memo. When its words may turn dotglob or globdots on
// (CommandMayDotglob), every statement read in this evaluation is read with
// * and ? matching a leading dot, as the call's own reading is: the gateway
// judges each statement of an eval body on its own, and the statement
// rm -rf * of eval 'cd ~; shopt -s dotglob; rm -rf *' does not spell the
// option its body turned on (rel-1-0-10:GAP-2267). It only turns the
// reading on.
func (m *TargetMemo) WithCallWords(command string) *TargetMemo {
	if m != nil && !m.callDots.Load() && CommandMayDotglob(command) {
		m.callDots.Store(true)
	}
	return m
}

// callMayDotglob reports a call whose words may turn dotglob on
// (WithCallWords).
func (m *TargetMemo) callMayDotglob() bool { return m != nil && m.callDots.Load() }

// withCallDotglobOf gives m the call reading of from and returns m.
func (m *TargetMemo) withCallDotglobOf(from *TargetMemo) *TargetMemo {
	if m != nil && from.callMayDotglob() {
		m.callDots.Store(true)
	}
	return m
}
