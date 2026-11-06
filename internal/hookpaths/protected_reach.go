// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io"
	"io/fs"
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
	hasAlias    bool
}

type reachDirNames struct {
	names    map[string]struct{}
	complete bool
}

type reachParentKey struct {
	parent, home string
	sshOnly      bool
}

type reachParentProof struct {
	tree  bool
	files map[string]struct{}
	dirs  map[string]struct{}
	trees map[string]struct{}
}

// A missing leaf can still be placed through a bind-mounted protected
// directory. Compare the parent identity with protected tree roots and file
// parents once per evaluation before treating that leaf as ordinary.
func (m *TargetMemo) protectedReachMissingParent(parent, home string, sshOnly bool, names reachNames) (reachParentProof, bool) {
	key := reachParentKey{parent, home, sshOnly}
	if m != nil {
		m.mu.Lock()
		proof, ok := m.reachParentIdentity[key]
		m.mu.Unlock()
		if ok {
			return proof, true
		}
	}
	parentInfo, err := PathStat(parent)
	if err != nil {
		return reachParentProof{}, false
	}
	proof := reachParentProof{files: make(map[string]struct{}), dirs: make(map[string]struct{}), trees: make(map[string]struct{})}
	resolvedParent, resolved := m.resolveWriteTarget(parent)
	if !resolved {
		return reachParentProof{}, false
	}
	type statAnswer struct {
		info os.FileInfo
		err  error
	}
	answers := make(map[string]statAnswer)
	read := func(path string) (os.FileInfo, error) {
		if answer, ok := answers[path]; ok {
			return answer.info, answer.err
		}
		info, err := PathStat(path)
		answers[path] = statAnswer{info, err}
		return info, err
	}
	for _, tree := range names.trees {
		info, err := read(tree)
		if err != nil && !os.IsNotExist(err) {
			return reachParentProof{}, false
		}
		proof.tree = proof.tree || pathAtOrUnder(parent, tree) || pathAtOrUnder(resolvedParent, tree) ||
			err == nil && os.SameFile(parentInfo, info)
		if info, err := read(filepath.Dir(tree)); err == nil && os.SameFile(parentInfo, info) {
			proof.trees[filepath.Base(tree)] = struct{}{}
		} else if err != nil && !os.IsNotExist(err) {
			return reachParentProof{}, false
		}
	}
	for _, dir := range names.directories {
		info, err := read(filepath.Dir(dir))
		if err != nil && !os.IsNotExist(err) {
			return reachParentProof{}, false
		}
		if err == nil && os.SameFile(parentInfo, info) {
			proof.dirs[filepath.Base(dir)] = struct{}{}
		}
	}
	for _, file := range names.files {
		info, err := read(filepath.Dir(file))
		if err != nil && !os.IsNotExist(err) {
			return reachParentProof{}, false
		}
		if err == nil && os.SameFile(parentInfo, info) {
			proof.files[filepath.Base(file)] = struct{}{}
		}
	}
	if m != nil {
		m.mu.Lock()
		if m.reachParentIdentity == nil {
			m.reachParentIdentity = make(map[reachParentKey]reachParentProof)
		}
		if len(m.reachParentIdentity) < 512 {
			m.reachParentIdentity[key] = proof
		}
		m.mu.Unlock()
	}
	return proof, true
}

// A complete parent listing and its protected identity proof can dismiss a
// missing candidate before the general two-sided path comparison. A present
// entry, named leaf, or unanswered parent always takes that comparison.
func (m *TargetMemo) protectedReachOrdinaryMissing(target, home string) bool {
	if m == nil || !filepath.IsAbs(target) || !filepath.IsAbs(home) || SharePath(target) || SharePath(home) {
		return false
	}
	parent, leaf := filepath.Dir(target), filepath.Base(target)
	if !m.protectedReachDirMiss(parent, leaf) {
		return false
	}
	proof, complete := m.protectedReachMissingParent(parent, home, false, m.protectedReachNames(home, false))
	if !complete || proof.tree {
		return false
	}
	if _, named := proof.files[leaf]; named {
		return false
	}
	if _, named := proof.dirs[leaf]; named {
		return false
	}
	_, named := proof.trees[leaf]
	return !named
}

// A complete local directory listing proves that an unlisted leaf has no
// file identity. Read it only when several candidates share the parent;
// large or unanswered directories continue through the usual path reader.
func (m *TargetMemo) protectedReachDirMiss(parent, leaf string) bool {
	if m == nil || runtime.GOOS != "linux" || SharePath(parent) {
		return false
	}
	m.mu.Lock()
	listing, cached := m.reachDirs[parent]
	if !cached {
		if len(m.reachDirs) >= 512 {
			m.mu.Unlock()
			return false
		}
		if m.reachDirHits == nil {
			m.reachDirHits = make(map[string]uint8)
		}
		if len(m.reachDirHits) >= 512 && m.reachDirHits[parent] == 0 {
			m.mu.Unlock()
			return false
		}
		if m.reachDirHits[parent] < 64 {
			m.reachDirHits[parent]++
		}
		if m.reachDirHits[parent] < 64 {
			m.mu.Unlock()
			return false
		}
	}
	m.mu.Unlock()
	if !cached {
		listing = reachDirNames{}
		if physical, ok := m.resolveWriteTarget(parent); ok && !SharePath(physical) {
			if entry, err := PathLstat(physical); err == nil && entry.IsDir() {
				if directory, err := os.Open(physical); err == nil {
					var names []string
					complete := false
					for len(names) <= 4096 {
						part, readErr := directory.Readdirnames(4097 - len(names))
						names = append(names, part...)
						if readErr == io.EOF {
							complete = true
							break
						}
						if readErr != nil || len(part) == 0 {
							break
						}
					}
					_ = directory.Close()
					if complete && len(names) <= 4096 {
						listing.names = make(map[string]struct{}, len(names))
						for _, name := range names {
							listing.names[name] = struct{}{}
						}
						listing.complete = true
					}
				}
			}
		}
		m.mu.Lock()
		if m.reachDirs == nil {
			m.reachDirs = make(map[string]reachDirNames)
		}
		if len(m.reachDirs) < 512 {
			m.reachDirs[parent] = listing
		}
		m.mu.Unlock()
	}
	_, exists := listing.names[leaf]
	return listing.complete && !exists
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
	physicalHome, homeKnown := "", false
	if !SharePath(home) {
		physicalHome, homeKnown = m.resolveWriteTarget(home)
	}
	// Resolve each root once. Its children share that physical parent; only
	// an entry that is itself a link needs another path walk.
	resolvedRoot := func(root string) string {
		if SharePath(root) {
			return ""
		}
		if homeKnown {
			if entry, err := PathLstat(root); err == nil && entry.Mode()&os.ModeSymlink == 0 || os.IsNotExist(err) {
				resolved := filepath.Join(physicalHome, filepath.Base(root))
				if !samePathName(root, resolved) {
					names.hasAlias = true
				}
				return resolved
			}
		}
		resolved, ok := m.resolveWriteTarget(root)
		if !ok {
			names.hasAlias = true
			return ""
		}
		if !samePathName(root, resolved) {
			names.hasAlias = true
		}
		return resolved
	}
	readEntries := func(root string) map[string]bool {
		if SharePath(root) {
			return nil
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			if !os.IsNotExist(err) {
				names.hasAlias = true
			}
			return nil
		}
		present := make(map[string]bool, len(entries))
		for _, entry := range entries {
			present[entry.Name()] = true
		}
		return present
	}
	addChild := func(root, physicalRoot, name string, present map[string]bool, add func(string)) {
		path := filepath.Join(root, name)
		add(path)
		if physicalRoot != "" {
			add(filepath.Join(physicalRoot, name))
		}
		first := name
		if cut := strings.IndexByte(name, '/'); cut >= 0 {
			first = name[:cut]
		}
		if SharePath(path) || !present[first] {
			return
		}
		entry, err := PathLstat(path)
		if err != nil && !os.IsNotExist(err) {
			names.hasAlias = true
		}
		// A nested protected entry can have a linked parent even when its
		// own final name has not been created yet.
		if err == nil && entry.Mode()&os.ModeSymlink == 0 && name != "previous/installer" {
			return
		}
		if err != nil && name != "previous/installer" {
			return
		}
		if resolved, ok := m.resolveWriteTarget(path); ok {
			add(resolved)
			if !samePathName(path, resolved) {
				names.hasAlias = true
			}
		}
	}
	sshRoot := resolvedRoot(ssh)
	sshEntries := readEntries(ssh)
	if sshRoot != "" {
		names.addDirectory(sshRoot)
	}
	for _, name := range AuthorizedKeysFiles {
		addChild(ssh, sshRoot, name, sshEntries, names.addFile)
	}
	for _, name := range SSHControlFiles {
		addChild(ssh, sshRoot, name, sshEntries, names.addFile)
	}
	if !sshOnly {
		state := filepath.Join(home, ".defenseclaw")
		stateRoot := resolvedRoot(state)
		names.addDirectory(state)
		if stateRoot != "" {
			names.addDirectory(stateRoot)
		}
		stateEntries := readEntries(state)
		for _, name := range activeStateFiles {
			addChild(state, stateRoot, name, stateEntries, names.addFile)
		}
		for _, name := range activeStateTrees {
			addChild(state, stateRoot, name, stateEntries, names.addTree)
		}
		if !SharePath(state) {
			m.addLinkedProtectedTreeNames(&names)
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

// A linked child of an active state tree makes its resolved destination part
// of that tree. Enumerate directories once per evaluation, following only
// linked directories and recording linked files as exact protected names.
func (m *TargetMemo) addLinkedProtectedTreeNames(names *reachNames) {
	queue := append([]string(nil), names.trees...)
	seen := make(map[string]bool)
	for len(queue) != 0 {
		dir := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if seen[dir] {
			continue
		}
		seen[dir] = true
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				names.hasAlias = true
			}
			continue
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			if entry.IsDir() {
				queue = append(queue, path)
				continue
			}
			if entry.Type()&os.ModeSymlink == 0 {
				continue
			}
			names.hasAlias = true
			resolved, ok := m.resolveWriteTarget(path)
			if !ok {
				continue
			}
			info, err := PathStat(path)
			if err != nil {
				if os.IsNotExist(err) {
					// A linked tree entry can name a parent that will be
					// created by the command being evaluated.
					names.addTree(resolved)
				}
				continue
			}
			if info.IsDir() {
				names.addTree(resolved)
				queue = append(queue, resolved)
			} else if info.Mode().IsRegular() {
				names.addFile(resolved)
			}
		}
	}
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
	if lexicalProtectedReach(target, home, sshOnly) {
		return GradeNamed
	}
	if m.protectedReachEmptyRootsMiss(target, home, sshOnly) {
		return GradeNone
	}
	return m.protectedReachUncached(target, home, sshOnly)
}

// A named protected spelling needs no file-system read. Physical aliases
// and file identities still use the two-sided resolver below.
func lexicalProtectedReach(target, home string, sshOnly bool) bool {
	ssh := filepath.Join(home, ".ssh")
	if samePathName(target, ssh) {
		return true
	}
	for _, name := range AuthorizedKeysFiles {
		if samePathName(target, filepath.Join(ssh, name)) {
			return true
		}
	}
	for _, name := range SSHControlFiles {
		if samePathName(target, filepath.Join(ssh, name)) {
			return true
		}
	}
	if sshOnly {
		return false
	}
	state := filepath.Join(home, ".defenseclaw")
	if samePathName(target, state) {
		return true
	}
	for _, name := range activeStateFiles {
		if samePathName(target, filepath.Join(state, name)) {
			return true
		}
	}
	for _, name := range activeStateTrees {
		if pathAtOrUnder(target, filepath.Join(state, name)) {
			return true
		}
	}
	return false
}

func (m *TargetMemo) protectedReachParentMissing(parent string) bool {
	if m != nil {
		m.mu.Lock()
		missing, ok := m.reachParentMissing[parent]
		m.mu.Unlock()
		if ok {
			return missing
		}
	}
	_, err := PathLstat(parent)
	missing := os.IsNotExist(err)
	if m != nil {
		m.mu.Lock()
		if m.reachParentMissing == nil {
			m.reachParentMissing = make(map[string]bool)
		}
		if len(m.reachParentMissing) < maxTargetMemoEntries {
			m.reachParentMissing[parent] = missing
		}
		m.mu.Unlock()
	}
	return missing
}

// An absent parent outside empty local protected roots has no current path
// or file identity through which it could reach a protected entry. Keep the
// full resolver whenever either root has contents, links, or an unknown read.
func (m *TargetMemo) protectedReachEmptyRootsMiss(target, home string, sshOnly bool) bool {
	if SharePath(target) || SharePath(home) {
		return false
	}
	ssh := filepath.Join(home, ".ssh")
	state := filepath.Join(home, ".defenseclaw")
	if pathAtOrUnder(target, ssh) || !sshOnly && pathAtOrUnder(target, state) {
		return false
	}
	if !m.protectedReachParentMissing(filepath.Dir(target)) {
		return false
	}
	key := home
	if sshOnly {
		key = "ssh:" + home
	}
	if m != nil {
		m.mu.Lock()
		empty, ok := m.emptyReachRoots[key]
		m.mu.Unlock()
		if ok {
			return empty
		}
	}
	empty := true
	for _, root := range []string{ssh, state} {
		if sshOnly && root == state {
			break
		}
		entry, err := PathLstat(root)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
			empty = false
			break
		}
		children, err := os.ReadDir(root)
		if err != nil || len(children) != 0 {
			empty = false
			break
		}
	}
	if m != nil {
		m.mu.Lock()
		if m.emptyReachRoots == nil {
			m.emptyReachRoots = make(map[string]bool)
		}
		m.emptyReachRoots[key] = empty
		m.mu.Unlock()
	}
	return empty
}

func (m *TargetMemo) protectedReachUncached(target, home string, sshOnly bool) Grade {
	names := m.protectedReachNames(home, sshOnly)
	target = filepath.Clean(target)
	if names.has(target) {
		return GradeNamed
	}
	// When the protected side has no links and this target's parent does not
	// exist, it cannot currently name a protected file by identity or path.
	// A linked protected entry keeps the full two-sided check, including a
	// link whose physical destination has not been created yet.
	if !names.hasAlias && !SharePath(target) {
		if m.protectedReachParentMissing(filepath.Dir(target)) {
			return GradeNone
		}
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
	// An existing file can sit below a protected tree whose entry links
	// outside the state root. Compare both resolved paths before matching
	// exact file identities.
	if file.err == nil {
		if resolved, ok := m.resolveWriteTarget(target); ok && names.has(resolved) {
			return GradeNamed
		}
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
	if file.err == nil && file.info.Mode().IsRegular() && linkCount(target, file.info) > 1 {
		// A hard link to a file inside a protected tree has no path relation
		// to that tree. Check the complete tree when file identity matters;
		// a bounded index cannot establish a negative result for this case.
		matched, unknown := m.protectedTreeSameFile(file.info, names)
		if matched {
			return GradeNamed
		}
		if unknown {
			return GradePossible
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

func (m *TargetMemo) protectedTreeSameFile(target os.FileInfo, names reachNames) (bool, bool) {
	seen := make(map[string]struct{}, len(names.trees))
	unknown := false
	for _, tree := range names.trees {
		root, ok := m.resolveWriteTarget(tree)
		if !ok {
			if _, err := PathLstat(tree); err != nil && !os.IsNotExist(err) {
				unknown = true
			}
			continue
		}
		if _, done := seen[root]; done {
			continue
		}
		seen[root] = struct{}{}
		matched := false
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if !os.IsNotExist(walkErr) {
					unknown = true
				}
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if entry.Type()&os.ModeSymlink != 0 {
				info, err = PathStat(path)
			}
			if err != nil {
				if !os.IsNotExist(err) {
					unknown = true
				}
				return nil
			}
			if info.Mode().IsRegular() && os.SameFile(target, info) {
				matched = true
				return fs.SkipAll
			}
			return nil
		})
		if matched {
			return true, unknown
		}
		if err != nil && !os.IsNotExist(err) {
			unknown = true
		}
	}
	return false, unknown
}
