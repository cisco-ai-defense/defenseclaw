// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
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

type reachParentKey struct{ path, home string }
type reachParentAnswer struct {
	resolved string
	grade    Grade
}

// parentProtectedReach keeps the complete link reading of a shared parent.
// A final ordinary directory does not clear a protected intermediate hop.
func (m *TargetMemo) parentProtectedReach(parent, home string, names reachNames) reachParentAnswer {
	key := reachParentKey{parent, home}
	if m != nil {
		m.mu.Lock()
		answer, ok := m.reachParents[key]
		m.mu.Unlock()
		if ok {
			return answer
		}
	}
	reached, linkedInProtectedDir, unread := false, false, false
	lstat := func(path string) (os.FileInfo, error) {
		if names.hasCandidate(path) {
			reached = true
		}
		info, err := PathLstat(path)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			for _, dir := range names.directories {
				if pathAtOrUnder(path, dir) {
					linkedInProtectedDir = true
				}
			}
		}
		unread = unread || ShareUnanswered(err)
		return info, err
	}
	var procLinks procLinkGuard
	readlink := func(path string) (string, error) {
		link, err := procLinks.readlink(path)
		unread = unread || ShareUnanswered(err)
		return link, err
	}
	resolved, _, _, ok := walkWritePathMemoWithReaders("", parent, 0, false, false, nil, lstat, readlink, procLinks.unproved, true)
	answer := reachParentAnswer{resolved: resolved}
	switch {
	case reached || ok && names.hasCandidate(resolved):
		answer.grade = GradeNamed
	case linkedInProtectedDir:
		answer.grade = GradePossible
	case unread || !ok:
		answer.grade = GradePossible
	}
	if m != nil {
		m.mu.Lock()
		if m.reachParents == nil {
			m.reachParents = make(map[reachParentKey]reachParentAnswer)
		}
		if len(m.reachParents) < maxTargetMemoEntries {
			m.reachParents[key] = answer
		}
		m.mu.Unlock()
	}
	return answer
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
	for _, name := range actionPrivateKeyNames {
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
	raw := target
	target = filepath.Clean(raw)
	if hasDotDotStep(raw) {
		// The cleaned spelling names a path the kernel may never open, so
		// it is not graded before the link walk.
		return m.dotDotReach(raw, target, home, sshOnly)
	}
	if unprovedProcessLink(target, false) {
		// The kernel resolves this hop for the process that opens it, or the
		// hook cannot show that its own reading reaches the same file.
		return GradePossible
	}
	if names.has(target) {
		return GradeNamed
	}
	parent := filepath.Dir(target)
	share := SharePath(target) || SharePath(home)
	// A missing leaf cannot be a hard link. Resolve its parent through the
	// evaluation memo. A regular local file with one link cannot alias a
	// protected file either; its parent reading is shared by every operand.
	// Share reads start together below to preserve their answer window.
	var entryInfo os.FileInfo
	var entryErr error
	if !share {
		entryInfo, entryErr = PathLstat(target)
		if os.IsNotExist(entryErr) || entryErr == nil &&
			(entryInfo.IsDir() || entryInfo.Mode().IsRegular() && linkCount(target, entryInfo) == 1) {
			answer := m.parentProtectedReach(parent, home, names)
			if names.has(filepath.Join(answer.resolved, filepath.Base(target))) {
				return GradeNamed
			}
			return answer.grade
		}
	}

	type answer struct {
		info os.FileInfo
		err  error
	}
	// Read both sides of a share identity in the same first-contact window.
	type protectedRead struct {
		done chan struct{}
		answer
	}
	protectedReady := make(map[string]*protectedRead)
	if share {
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
	fileReady, parentReady := make(chan answer, 1), make(chan answer, 1)
	var entryReady chan answer
	if share {
		entryReady = make(chan answer, 1)
		go func() { info, err := PathLstat(target); entryReady <- answer{info, err} }()
	}
	go func() { info, err := PathStat(target); fileReady <- answer{info, err} }()
	go func() { info, err := PathStat(parent); parentReady <- answer{info, err} }()
	file, directory, entry := <-fileReady, <-parentReady, answer{entryInfo, entryErr}
	if share {
		entry = <-entryReady
	}

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
	var procLinks procLinkGuard
	readlink := func(path string) (string, error) {
		link, err := procLinks.readlink(path)
		if ShareUnanswered(err) {
			unread = true
		}
		return link, err
	}
	resolved, _, _, ok := walkWritePathMemoWithReaders("", target, 0, false, false, nil, lstat, readlink, procLinks.unproved, false)
	if reached || ok && names.has(resolved) {
		return GradeNamed
	}

	// The ordinary parent of a missing local file is a complete answer even
	// when another, unrelated share is pending.
	if os.IsNotExist(entry.err) && directory.err == nil {
		if resolved, ok := m.resolveWriteTarget(parent); ok && !names.has(filepath.Join(resolved, filepath.Base(target))) {
			return GradeNone
		}
	}
	if file.err == nil {
		if !sshOnly && entry.info != nil && entry.info.Mode().IsRegular() &&
			linkCount(target, entry.info) > 1 {
			if grade := stateTreeHardlinkReach(target, home); grade != GradeNone {
				return grade
			}
		}
		if unknownFiles || !ok {
			// An unresolved walk leaves the opened identity unproved.
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

// dotDotReach grades a spelling with a dot-dot step. The kernel follows a
// directory link before it applies the step, so the lexical form proves only
// the clean spelling; the path the kernel opens is the one read link by link.
// A step after a process-relative link is that process's own directory, so it
// stays unproved. A walk that cannot cross a step stays unproved too.
func (m *TargetMemo) dotDotReach(raw, clean, home string, sshOnly bool) Grade {
	steps := strings.Split(filepath.ToSlash(raw), "/")
	for i, step := range steps {
		if step == ".." && unprovedProcessLink(strings.Join(steps[:i], "/"), true) {
			return GradePossible
		}
	}
	// A link read on the way may lead through a process-relative hop (the
	// hook reads its own directory there); the steps after it belong to the
	// process that opens the path, so the walk proves nothing past it.
	processRelative := false
	var procLinks procLinkGuard
	unproved := func(path string, below bool) bool {
		if procLinks.unproved(path, below) {
			processRelative = true
		}
		return processRelative
	}
	physical, _, _, ok := walkWritePathMemoWithReaders("", raw, 0, false, false, nil, PathLstat, procLinks.readlink, unproved, false)
	if processRelative {
		return GradePossible
	}
	if !ok {
		// A step the walk could not cross leaves the opened path unproved:
		// the clean spelling is the strongest lexical reading.
		return m.protectedReach(clean, home, sshOnly).Max(GradePossible)
	}
	// Every component was read, so the physical path is the one the kernel
	// opens. A protected link that only the cleaned spelling names is a
	// different entry that the kernel never reads.
	grade := m.protectedReach(physical, home, sshOnly)
	if dotDotReadsLexically {
		// A Windows name has two readings. Win32 removes the step from the
		// text before it opens the name, so a program that is not a shell
		// opens the cleaned spelling; Git Bash and this walk follow the link
		// first. The name is ordinary only when both readings are.
		grade = grade.Max(m.protectedReach(clean, home, sshOnly))
	}
	return grade
}

// dotDotReadsLexically is true where a dot-dot step after a link also has the
// reading in which it is removed from the text (Windows). It is a variable so
// that the tests of the rule run on every host.
var dotDotReadsLexically = runtime.GOOS == "windows"

// stateTreeHardlinkReach compares a multiply linked file with the active
// state by file identity (ResolveActiveStateIdentity, which reads the whole
// state, not the bounded mention index). A complete reading gives an ordinary
// alias a definite answer; a state that could not be read to the end leaves
// it unproved.
func stateTreeHardlinkReach(target, home string) Grade {
	_, same, complete := ResolveActiveStateIdentity(target, home)
	switch {
	case same:
		return GradeNamed
	case !complete:
		return GradePossible
	}
	return GradeNone
}

// processRelativeLink reports a path whose link the kernel reads for the
// process that opens it: a /proc/self or /proc/thread-self entry (also under
// task/<tid>) for its cwd, root, exe, descriptors or mapped files, and the
// /dev descriptor aliases. A numeric process id names one process whichever
// process opens the path; fixedPIDLink handles that form.
func processRelativeLink(path string) bool {
	path = filepath.ToSlash(path)
	for _, alias := range []string{"/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr"} {
		if path == alias || strings.HasPrefix(path, alias+"/") {
			return true
		}
	}
	rest, found := strings.CutPrefix(path, "/proc/")
	if !found {
		return false
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[0] != "self" && parts[0] != "thread-self" {
		return false
	}
	entry := 1
	if parts[1] == "task" {
		if len(parts) < 4 || !allDigits(parts[2]) {
			return false
		}
		entry = 3
	}
	switch parts[entry] {
	case "cwd", "root", "exe", "fd", "map_files":
		return true
	}
	return false
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// fixedPIDLink returns the process link a /proc/<pid> path starts with: the
// cwd, root or exe link, one descriptor or one mapped file, also under
// task/<tid>. The same process answers whichever process opens the link.
func fixedPIDLink(path string) (string, bool) {
	path = filepath.ToSlash(path)
	rest, found := strings.CutPrefix(path, "/proc/")
	if !found {
		return "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || !allDigits(parts[0]) {
		return "", false
	}
	entry := 1
	if parts[1] == "task" {
		if len(parts) < 4 || !allDigits(parts[2]) {
			return "", false
		}
		entry = 3
	}
	end := entry + 1
	switch parts[entry] {
	case "cwd", "root", "exe":
	case "fd", "map_files":
		if len(parts) <= entry+1 || parts[entry+1] == "" {
			return "", false
		}
		end = entry + 2
	default:
		return "", false
	}
	return "/proc/" + strings.Join(parts[:end], "/"), true
}

// procMountView is what the hook reads of the mount tree of a process or task
// directory: the identity of its mount namespace and its mount table, which
// lists only the mounts below the root of that process.
type procMountView struct {
	namespace os.FileInfo
	table     string
}

const maxProcMountTable = 4 << 20

// readProcMountView is a variable so a test can present a mount tree the hook
// does not share.
var readProcMountView = func(dir string) (procMountView, error) {
	ns, err := PathStat(dir + "/ns/mnt")
	if err != nil {
		return procMountView{}, err
	}
	f, err := pathOpen(dir + "/mountinfo")
	if err != nil {
		return procMountView{}, err
	}
	defer f.Close()
	table, err := io.ReadAll(io.LimitReader(f, maxProcMountTable+1))
	if err != nil {
		return procMountView{}, err
	}
	if len(table) > maxProcMountTable {
		return procMountView{}, errProcMountTableTooLarge
	}
	return procMountView{namespace: ns, table: string(table)}, nil
}

var errProcMountTableTooLarge = errors.New("mount table too large to compare")

// fixedPIDProcDir returns the process (or task) directory the link that
// fixedPIDLink returned lives in.
func fixedPIDProcDir(link string) string {
	parts := strings.Split(strings.TrimPrefix(link, "/proc/"), "/")
	n := 1
	if len(parts) > 1 && parts[1] == "task" {
		n = 3
	}
	if len(parts) <= n {
		return ""
	}
	return "/proc/" + strings.Join(parts[:n], "/")
}

// sharesMountTree reports that the process directory sees the mount tree the
// hook sees: the same mount namespace and the same mount table. A matching
// root directory identity is not enough, because a private mount below an
// unchanged directory, or a root that omits a submount, changes what a path
// below the link names. An unreadable or oversized view is not shared.
func sharesMountTree(dir string) bool {
	theirs, err := readProcMountView(dir)
	if err != nil {
		return false
	}
	ours, err := readProcMountView("/proc/thread-self")
	return err == nil && os.SameFile(ours.namespace, theirs.namespace) && ours.table == theirs.table
}

// fixedPIDLeafProved reports that the link of an explicit process id leads to
// the file the hook reads for it, as a path that ends at the link. The kernel
// resolves the link itself the same way for the hook and for the process that
// opens the path, so the proof is a reading that reaches one file identity
// through both the link and its target text. An unreadable link, a text that
// is not a path, or two identities that differ stay unproved.
func fixedPIDLeafProved(link string) bool {
	target, err := PathReadlink(link)
	if err != nil || !filepath.IsAbs(target) {
		return false
	}
	via, err := PathStat(link)
	if err != nil {
		return false
	}
	named, err := PathStat(target)
	return err == nil && os.SameFile(via, named)
}

// fixedPIDLinkProved is the proof for a path that goes on below the link. That
// part is resolved in the mount tree of the process the link names, so the
// proof needs that tree to be the hook tree besides the leaf proof.
func fixedPIDLinkProved(link string) bool {
	dir := fixedPIDProcDir(link)
	return dir != "" && sharesMountTree(dir) && fixedPIDLeafProved(link)
}

// procLinkGuard follows the links one reading crosses. The aliases
// /proc/self and /proc/thread-self read as the hook's own process id, so a
// path that goes on through that id names the hook process, not the one that
// opens the path; the guard remembers each such id.
type procLinkGuard struct{ aliased map[string]bool }

func (g *procLinkGuard) readlink(path string) (string, error) {
	link, err := PathReadlink(path)
	if err == nil && (path == "/proc/self" || path == "/proc/thread-self") {
		pid, _, _ := strings.Cut(filepath.ToSlash(link), "/")
		if g.aliased == nil {
			g.aliased = make(map[string]bool)
		}
		g.aliased[pid] = true
	}
	return link, err
}

// unproved reports a path that starts with a per-process link the hook cannot
// read for the process that opens it: an opener-relative alias, a process id
// the hook reached through such an alias, or an explicit process id whose
// link the hook does not prove. A path that ends at the link needs only the
// leaf proof; below tells that the path goes on below it.
func (g *procLinkGuard) unproved(path string, below bool) bool {
	if processRelativeLink(path) {
		return true
	}
	link, ok := fixedPIDLink(path)
	if !ok {
		return false
	}
	pid, _, _ := strings.Cut(strings.TrimPrefix(link, "/proc/"), "/")
	if g.aliased[pid] {
		return true
	}
	if below || filepath.ToSlash(path) != link {
		return !fixedPIDLinkProved(link)
	}
	return !fixedPIDLeafProved(link)
}

func unprovedProcessLink(path string, below bool) bool {
	var g procLinkGuard
	return g.unproved(path, below)
}
