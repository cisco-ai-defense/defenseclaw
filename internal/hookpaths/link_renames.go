package hookpaths

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// renameOp is one static mv or gmv call: its sources, its destination or
// target directory, and the directory it runs in (GAP-2532).
type renameOp struct {
	sources     []string
	dest        string
	targetDir   string
	noTargetDir bool
	wd          string
}

// parseRename reads the arguments of mv or gmv. ok is false for an option
// this package does not know or an operand that may be a pattern, so the
// caller keeps the conservative reading of an unread rename.
func parseRename(args []string, cwd string) (op renameOp, ok bool) {
	op.wd = cwd
	var operands []string
	end := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if end || arg == "-" || !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
			continue
		}
		if arg == "--" {
			end = true
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, value, hasValue := strings.Cut(arg[2:], "=")
			switch name {
			case "backup", "update", "context":
			case "force", "interactive", "no-clobber", "strip-trailing-slashes", "verbose", "no-copy", "debug":
				if hasValue {
					return op, false
				}
			case "no-target-directory":
				if hasValue {
					return op, false
				}
				op.noTargetDir = true
			case "suffix", "target-directory":
				if !hasValue {
					if i++; i >= len(args) {
						return op, false
					}
					value = args[i]
				}
				if name == "target-directory" {
					if value == "" {
						return op, false
					}
					op.targetDir = value
				}
			default:
				// --exchange swaps the names; an abbreviation is not read.
				return op, false
			}
			continue
		}
		for j := 1; j < len(arg); j++ {
			switch flag := arg[j : j+1]; flag {
			case "b", "f", "i", "n", "u", "v", "Z", "h":
			case "T":
				op.noTargetDir = true
			case "t", "S":
				value := arg[j+1:]
				if value == "" {
					if i++; i >= len(args) {
						return op, false
					}
					value = args[i]
				}
				if flag == "t" {
					if value == "" {
						return op, false
					}
					op.targetDir = value
				}
				j = len(arg)
			default:
				return op, false
			}
		}
	}
	for _, operand := range append(operands, op.targetDir) {
		if strings.ContainsAny(operand, "*?[") {
			return op, false
		}
	}
	switch {
	case op.targetDir != "":
		op.sources = operands
	case op.noTargetDir && len(operands) != 2:
		return op, false
	case len(operands) >= 2:
		op.sources, op.dest = operands[:len(operands)-1], operands[len(operands)-1]
	}
	return op, true
}

// destinations are the names source may have after the move: the
// destination itself and, unless -T, the name inside it when it is a
// directory.
func (op renameOp) destinations(source string) []string {
	base := filepath.Base(filepath.Clean(source))
	switch {
	case op.targetDir != "":
		return []string{filepath.Join(absolutePath(op.targetDir, op.wd), base)}
	case len(op.sources) > 1:
		return []string{filepath.Join(absolutePath(op.dest, op.wd), base)}
	case op.noTargetDir:
		return []string{absolutePath(op.dest, op.wd)}
	}
	dest := absolutePath(op.dest, op.wd)
	if info, err := os.Lstat(dest); err == nil && info.IsDir() {
		// A move onto an existing directory (not a link to one) goes inside
		// it; the name itself is not replaced.
		return []string{filepath.Join(dest, base)}
	}
	return []string{dest, filepath.Join(dest, base)}
}

func pathsOverlap(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	return pathAtOrUnder(a, b) || pathAtOrUnder(b, a)
}

// pathAtOrUnder is cutPathPrefix that also reads a root (/, C:\) as the
// parent of every path on it.
func pathAtOrUnder(path, prefix string) bool {
	if prefix != "" && os.IsPathSeparator(prefix[len(prefix)-1]) {
		return len(path) >= len(prefix) && samePathName(path[:len(prefix)], prefix)
	}
	_, under := cutPathPrefix(path, prefix)
	return under
}

// followRenames gives every link a static mv moves its new name, with the
// target a relative symbolic link has in its new directory. It reports
// false when a move lands on or around a link name or target (the move may
// replace what a link names) or moves a name through a link.
func (l *shellLinks) followRenames(ops []renameOp) bool {
	for _, op := range ops {
		before := append([]linkAlias(nil), l.aliases...)
		for _, source := range op.sources {
			from := absolutePath(source, op.wd)
			for _, dest := range op.destinations(source) {
				for _, alias := range before {
					if pathsOverlap(dest, alias.name) || pathsOverlap(dest, alias.target) {
						return false
					}
					if _, through := cutPathPrefix(from, alias.name); through && !samePathName(from, alias.name) {
						return false
					}
					rest, moved := cutPathPrefix(alias.name, from)
					if !moved {
						continue
					}
					name := dest
					if rest != "" {
						name = filepath.Join(dest, rest)
					}
					target := alias.target
					if alias.text != "" {
						target = filepath.Dir(name) + string(filepath.Separator) + alias.text
					}
					l.aliases = append(l.aliases, linkAlias{name: name, target: target, text: alias.text})
				}
			}
		}
	}
	return true
}

// aliasesAwayFromState reports that no link the command makes, nor any
// name its target reaches through the other links and the disk, can
// overlap SSH or DefenseClaw state: a target that holds the home directory
// (/, .., ~) overlaps it. Such links stay known when a nested shell or a
// wrapper changes directory (GAP-2533) or a static mv renames (GAP-2532).
// A name that goes through an existing file that is not a directory names
// nothing and is skipped (ln -s README.md docs.md also names
// docs.md/README.md).
func (l shellLinks) aliasesAwayFromState(cwd, home string) bool {
	if cwd == "" || home == "" || !filepath.IsAbs(cwd) {
		return false
	}
	if _, ok := ResolveWriteTarget(cwd); !ok {
		return false
	}
	state := newStateReach(home)
	reach := Links{links: l}
	for _, alias := range l.aliases {
		for _, form := range append([]string{alias.target}, reach.AliasTargets(alias.target, false)...) {
			resolved, ok := ResolveWriteTarget(form)
			if !ok {
				resolved, ok = resolveMissingDotDot(form)
			}
			if !ok {
				if throughFile(form) {
					continue
				}
				return false
			}
			if state.hits(resolved) {
				return false
			}
		}
	}
	return true
}

// dotDotPastLinksClear reports that no word of command steps through a
// link the command makes and then up with .. to SSH or DefenseClaw state.
// The kernel, and cd when the logical path is missing, resolve LINK/.. from
// the link target, so after ln -s ../proj p a cd p/../.ssh enters ~/.ssh
// while the lexical reading lands in the project (GAP-2600 checker). A
// physical walk that passes through state is not clear, nor one that ends
// in a directory holding state (the home) unless the word is a cd operand
// whose logical path exists: cwd and its parents exist, so cd p/.. back
// into the project stays clear. cd -P and set -P always go physical.
func (l shellLinks) dotDotPastLinksClear(command, cwd, home string) bool {
	if len(l.aliases) == 0 || home == "" || !strings.Contains(command, "..") {
		return true
	}
	state := newStateReach(home)
	words, programs := commandWordPrograms(command)
	for _, text := range l.linkTexts {
		for _, word := range commandWords(text) {
			if i := slices.Index(words, word); i >= 0 {
				words = slices.Delete(words, i, i+1)
				programs = slices.Delete(programs, i, i+1)
			}
		}
	}
	physical := physicalDirectoryMode(words, programs)
	for w, word := range words {
		parts := strings.Split(filepath.ToSlash(word), "/")
		for i, part := range parts {
			if !slices.Contains(parts[i+1:], "..") {
				break
			}
			for _, alias := range l.aliases {
				if part == "" || part == "." || part == ".." || filepath.Base(alias.name) != part {
					continue
				}
				end, through := state.physicalWalk(alias.target, parts[i+1:])
				if through {
					return false
				}
				if !state.hits(end) {
					continue
				}
				cdOperand := w > 0 && (words[w-1] == "cd" || words[w-1] == "pushd")
				if !cdOperand && readsOnly(programs[w]) && !state.within(end) {
					// A listing of the home or / names no state (GAP-2611).
					continue
				}
				if physical || !cdOperand || !logicalDirExists(absolutePath(word, cwd), cwd) {
					return false
				}
			}
		}
	}
	return true
}

// diskLinkDotDotReachesState is dotDotPastLinksClear for the links already
// on disk: a word that steps through a disk link and then up with .. is
// walked from the link target, so cd p/../.ssh with p -> ../proj reaches
// ~/.ssh. Only the user view of the disk shows the link; behind ProtectHome
// the gateway reads this walk from ActionDecisionKey (GAP-2600 pod).
func diskLinkDotDotReachesState(command, cwd, home string) bool {
	if home == "" || !strings.Contains(command, "..") {
		return false
	}
	start, ok := ResolveWriteTarget(cwd)
	if !ok {
		return false
	}
	state := newStateReach(home)
	words, programs := commandWordPrograms(command)
	physical := physicalDirectoryMode(words, programs)
	for w, word := range words {
		if !strings.Contains(word, "..") {
			continue
		}
		base, rest := start, word
		if strings.HasPrefix(word, "~") {
			expanded, known := tildeWordPath(word, cwd, home)
			if !known {
				continue
			}
			rest = expanded
		}
		if filepath.IsAbs(rest) {
			base = string(filepath.Separator)
		}
		parts := strings.Split(filepath.ToSlash(rest), "/")
		path := base
		for i, part := range parts {
			if part == "" || part == "." {
				continue
			}
			if part == ".." {
				path = filepath.Dir(path)
				continue
			}
			path = filepath.Join(path, part)
			info, err := os.Lstat(path)
			if err != nil {
				break
			}
			if info.Mode()&os.ModeSymlink == 0 {
				continue
			}
			if !slices.Contains(parts[i+1:], "..") {
				break
			}
			target, resolved := ResolveWriteTarget(path)
			if !resolved {
				break
			}
			end, through := state.physicalWalk(target, parts[i+1:])
			if through {
				return true
			}
			cdOperand := w > 0 && (words[w-1] == "cd" || words[w-1] == "pushd")
			if !cdOperand && readsOnly(programs[w]) && !state.within(end) {
				// A listing of the home or / names no state (GAP-2611).
				break
			}
			if state.hits(end) && (physical || !cdOperand || !logicalDirExists(absolutePath(word, cwd), cwd)) {
				return true
			}
			break
		}
	}
	return false
}

// readOnlyLinkWordPrograms read the paths they are given and write none,
// so a word of theirs that ends at a directory holding state (the home or
// /) through LINK/.. reaches no state; a word that passes through or ends
// in state still does (GAP-2611).
var readOnlyLinkWordPrograms = []string{
	"ls", "cat", "head", "tail", "less", "more", "stat", "du", "wc", "file", "tree", "readlink", "realpath",
	"grep", "egrep", "fgrep", "rg", "diff", "cmp", "md5sum", "sha1sum", "sha256sum", "dirname", "basename",
}

func readsOnly(program string) bool {
	return slices.Contains(readOnlyLinkWordPrograms, program)
}

// linkWordShells start a nested shell; their -c script names the program.
var linkWordShells = []string{"bash", "sh", "dash", "ksh", "zsh"}

// commandWordPrograms is commandWords(command) with, for each word, the
// program of the statement it is in (the script's first word for sh -c).
func commandWordPrograms(command string) (words, programs []string) {
	statements := strings.FieldsFunc(command, func(r rune) bool { return strings.ContainsRune(";&|()\n\r", r) })
	for _, statement := range statements {
		statementWords := commandWords(statement)
		program := ""
		if len(statementWords) > 0 {
			program = filepath.Base(statementWords[0])
			if slices.Contains(linkWordShells, program) {
				if c := slices.Index(statementWords, "-c"); c >= 0 && c+1 < len(statementWords) {
					program = filepath.Base(statementWords[c+1])
				}
			}
		}
		for _, word := range statementWords {
			words = append(words, word)
			programs = append(programs, program)
		}
	}
	return words, programs
}

// physicalDirectoryMode reports a statement that turns on the physical
// directory reading: cd -P, pushd -P, set -P, set -o physical, or a shell
// started with -P. A -P or the word physical of any other program (grep -P,
// cp -P, echo physical) does not (GAP-2611).
func physicalDirectoryMode(words, programs []string) bool {
	for i, word := range words {
		program := programs[i]
		if !slices.Contains([]string{"cd", "pushd", "set"}, program) && !slices.Contains(linkWordShells, program) {
			continue
		}
		if word == "physical" && i > 0 && words[i-1] == "-o" {
			return true
		}
		if len(word) > 1 && word[0] == '-' && word[1] != '-' && strings.ContainsRune(word[1:], 'P') {
			return true
		}
	}
	return false
}

// physicalWalk follows steps from a link target as the kernel does, through
// the disk links it can read; through is true when a step is at or in
// state.
func (s stateReach) physicalWalk(target string, steps []string) (end string, through bool) {
	path := filepath.Clean(target)
	if resolved, ok := ResolveWriteTarget(path); ok {
		path = resolved
	}
	for _, step := range steps {
		switch step {
		case "", ".":
			continue
		case "..":
			path = filepath.Dir(path)
		default:
			path = filepath.Join(path, step)
		}
		if resolved, ok := ResolveWriteTarget(path); ok {
			path = resolved
		}
		if s.within(path) {
			return path, true
		}
	}
	return path, false
}

// within reports a resolved path that is state or lies in it.
func (s stateReach) within(resolved string) bool {
	for _, path := range s.sensitive {
		if pathAtOrUnder(resolved, path) {
			return true
		}
	}
	return s.inState(resolved)
}

// logicalDirExists reports a directory that cwd is at or under, or one the
// disk shows; a gateway behind ProtectHome sees only the first kind.
func logicalDirExists(path, cwd string) bool {
	if pathAtOrUnder(cwd, path) {
		return true
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// stateReach tests resolved paths against SSH and DefenseClaw state: the
// state paths and their resolved forms, the authorized-keys files and the
// DefenseClaw state files.
type stateReach struct {
	home, ssh string
	sensitive []string
	protected protectedFiles
}

func newStateReach(home string) stateReach {
	state := stateReach{home: home, ssh: filepath.Join(home, ".ssh"), protected: newProtectedFiles(home)}
	for _, path := range append([]string{state.ssh, filepath.Join(home, ".defenseclaw")}, ProtectedAuthorizedKeysPaths(home)...) {
		state.sensitive = append(state.sensitive, filepath.Clean(path))
		if resolved, ok := ResolveWriteTarget(path); ok {
			state.sensitive = append(state.sensitive, resolved)
		}
	}
	return state
}

// hits reports a resolved path that is state, lies in it or holds it.
func (s stateReach) hits(resolved string) bool {
	for _, path := range s.sensitive {
		if pathsOverlap(resolved, path) {
			return true
		}
	}
	return s.inState(resolved)
}

func (s stateReach) inState(resolved string) bool {
	return protectedReachPath(resolved, s.protected, s.ssh) || actionProtectedStatePath(resolved, &actionStateHome{home: s.home})
}

// movedMatchHits reports that a match of pattern moved into the resolved
// directory dir can land on or in state.
func (s stateReach) movedMatchHits(dir, pattern string) bool {
	for _, path := range s.sensitive {
		if pathAtOrUnder(dir, path) {
			return true
		}
		rest, under := cutPathPrefix(path, dir)
		if !under || rest == "" {
			continue
		}
		first := strings.SplitN(filepath.ToSlash(rest), "/", 2)[0]
		if matched, err := filepath.Match(pattern, first); err != nil || matched {
			return true
		}
	}
	return s.inState(dir)
}

// maxLinkedTreeEntries bounds the walk of the directories the links name;
// a larger tree is read as one that may hold a link to state.
const maxLinkedTreeEntries = 20000

// linkedTreeBudget bounds the time of that walk on a hook call; a walk that
// runs longer is read the same way (RV-c5-2 note: /usr/lib took 3.8 s).
const linkedTreeBudget = 1500 * time.Millisecond

// linkedTreesClear reports that a directory change in a nested shell or a
// wrapper, or a find -exec mv, cannot reach SSH or DefenseClaw state through
// a disk link below a directory a link of the command names (RV-c4-1). The
// statement walk does not place those directory changes, so the disk links
// under the link are checked instead. The walk runs when a nested or
// wrapped directory change may enter a link (mayEnterLink), or when a find
// start path or move destination is at or under a link name or goes through
// a disk link. A find that names no link does not descend into one (find
// does not follow links), so a large linked tree beside it is not read
// (RV-c5-2). A plain cd resolves such disk links itself.
func (l shellLinks) linkedTreesClear(command, cwd, home string, wrapped bool, moves []findMove) bool {
	state := newStateReach(home)
	reach := Links{links: l}
	var dirs []string
	for _, alias := range l.aliases {
		for _, form := range append([]string{alias.target}, reach.AliasTargets(alias.target, false)...) {
			resolved, ok := ResolveWriteTarget(form)
			if !ok {
				resolved, ok = resolveMissingDotDot(form)
			}
			if !ok {
				if throughFile(form) {
					continue
				}
				return false
			}
			if info, err := os.Stat(resolved); err == nil && info.IsDir() {
				dirs = append(dirs, resolved)
			}
		}
	}
	if len(dirs) == 0 {
		return true
	}
	enter := wrapped && l.mayEnterLink(command, cwd, home)
	for _, move := range moves {
		for _, path := range append(slices.Clone(move.starts), move.dest) {
			enter = enter || l.pathEntersLink(path, cwd)
		}
	}
	return !enter || treesAwayFromState(dirs, state)
}

// pathEntersLink reports that an absolute path is at or under a link name
// of the command, or that a step of it is a disk link, dangling or not:
// the steps below cwd for a path under cwd, else every step.
func (l shellLinks) pathEntersLink(path, cwd string) bool {
	for _, alias := range l.aliases {
		if pathAtOrUnder(path, alias.name) {
			return true
		}
	}
	base, rest := string(filepath.Separator), strings.TrimLeft(path, string(filepath.Separator))
	if r, under := cutPathPrefix(path, cwd); under {
		base, rest = cwd, r
	}
	link, _ := diskLinkSteps(base, rest)
	return link
}

// diskLinkSteps reads word as a path from base, one step at a time while
// the steps exist: link is true when a step is a disk link, dangling or
// not; dirs are the directories the steps name.
func diskLinkSteps(base, word string) (link bool, dirs []string) {
	path := base
	for _, part := range strings.Split(filepath.ToSlash(word), "/") {
		if part == "" || part == "." {
			continue
		}
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if err != nil {
			return false, dirs
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return true, dirs
		}
		if info.IsDir() {
			dirs = append(dirs, path)
		}
	}
	return false, dirs
}

// maxEnterBases bounds the directories mayEnterLink reads words from.
const maxEnterBases = 64

// mayEnterLink reports that a word of command other than the link calls
// names a link (a path step equal to its base name), may expand or match
// one, makes find follow links, or goes through a disk link, dangling or
// not (RV-c5-1: a project disk link to a name the command links, d2/r ->
// ../e, or to one it re-targets, p2 -> e2). Each word is read as a path
// from cwd and from the directories earlier words name, so cd d2 && cd r/x
// is read too. The walk this starts only blocks when a linked tree holds a
// disk link to state.
// A word that starts with ~ is also read from the home it names (RV-c6-1,
// tildeWordPath); a tilde word that names no known home may name the link.
func (l shellLinks) mayEnterLink(command, cwd, home string) bool {
	if strings.ContainsAny(command, "$`*?[{\\") {
		return true
	}
	words := commandWords(command)
	for _, text := range l.linkTexts {
		for _, word := range commandWords(text) {
			if i := slices.Index(words, word); i >= 0 {
				words = slices.Delete(words, i, i+1)
			}
		}
	}
	// commandWords drops quotes, so a ~ word is read both as written (a
	// quoted '~/r' is a directory named ~ under cwd, RV-c7-1) and expanded.
	for _, word := range words {
		if !strings.HasPrefix(word, "~") {
			continue
		}
		expanded, ok := tildeWordPath(word, cwd, home)
		if !ok {
			return true
		}
		words = append(words, expanded)
	}
	names := make(map[string]bool)
	for _, alias := range l.aliases {
		names[filepath.Base(alias.name)] = true
	}
	for _, word := range words {
		if word == "-L" || word == "-follow" {
			return true
		}
		for _, part := range strings.Split(word, "/") {
			if names[part] {
				return true
			}
		}
	}
	bases := []string{filepath.Clean(cwd)}
	seen := map[string]bool{bases[0]: true}
	for range 2 {
		for _, word := range words {
			starts := bases
			if filepath.IsAbs(word) {
				starts = []string{string(filepath.Separator)}
			}
			for _, start := range starts {
				link, dirs := diskLinkSteps(start, word)
				if link {
					return true
				}
				for _, dir := range dirs {
					if !seen[dir] && len(bases) < maxEnterBases {
						seen[dir] = true
						bases = append(bases, dir)
					}
				}
			}
		}
	}
	return false
}

// tildeWordPath expands a leading tilde of word the way the shell does: ~
// and ~/ from home, ~+ from cwd, ~user from the user database (RV-c7-2).
// ok is false for ~- (the old directory is not known), a user that is not
// found, or an empty home.
func tildeWordPath(word, cwd, home string) (path string, ok bool) {
	name, rest, _ := strings.Cut(word[1:], "/")
	dir := home
	switch name {
	case "":
	case "+":
		dir = cwd
	case "-":
		return "", false
	default:
		account, err := user.Lookup(name)
		if err != nil {
			return "", false
		}
		dir = account.HomeDir
	}
	if dir == "" {
		return "", false
	}
	return filepath.Join(dir, rest), true
}

// commandWords splits command text into words; a word may be a path.
func commandWords(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		return strings.ContainsRune(" \t\n\r\"\x27;&|()<>=,", r)
	})
}

// movedEntriesAwayFromState reports that no entry a followed move takes is a
// disk link to SSH or DefenseClaw state, a directory that holds one, or an
// entry of state: the links of the command follow a move, a disk link moved
// to a new name does not. A find -exec mv takes the entries of its start
// trees that match its pattern. A tree too large to read is not clear.
// The moves after a directory change are read so (GAP-2602).
func movedEntriesAwayFromState(ops []renameOp, moves []findMove, home string) bool {
	state := newStateReach(home)
	entryClear := func(path string) bool {
		if parent, ok := ResolveWriteTarget(filepath.Dir(path)); !ok || state.within(parent) {
			return false
		}
		info, err := os.Lstat(path)
		switch {
		case os.IsNotExist(err):
			return true
		case err != nil:
			return false
		case info.Mode()&os.ModeSymlink != 0:
			resolved, ok := ResolveWriteTarget(path)
			return ok && !state.hits(resolved)
		case info.IsDir():
			return treesAwayFromState([]string{path}, state)
		}
		return true
	}
	for _, op := range ops {
		for _, source := range op.sources {
			if !entryClear(absolutePath(source, op.wd)) {
				return false
			}
		}
	}
	entries := 0
	deadline := time.Now().Add(linkedTreeBudget)
	for _, move := range moves {
		for _, start := range move.starts {
			clear := true
			err := filepath.WalkDir(start, func(path string, entry fs.DirEntry, err error) error {
				entries++
				if err != nil || entries > maxLinkedTreeEntries || entries%256 == 0 && time.Now().After(deadline) {
					clear = false
					return filepath.SkipAll
				}
				if matched, _ := filepath.Match(move.pattern, entry.Name()); matched && !entryClear(path) {
					clear = false
					return filepath.SkipAll
				}
				return nil
			})
			if err != nil || !clear {
				return false
			}
		}
	}
	return true
}

// treesAwayFromState walks dirs and the directories their disk links reach,
// and reports that no disk link reaches state.
func treesAwayFromState(dirs []string, state stateReach) bool {
	seen := make(map[string]bool)
	queue := slices.Clone(dirs)
	entries := 0
	deadline := time.Now().Add(linkedTreeBudget)
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		if seen[dir] {
			continue
		}
		seen[dir] = true
		clear := true
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			entries++
			if err != nil || entries > maxLinkedTreeEntries || entries%256 == 0 && time.Now().After(deadline) {
				clear = false
				return filepath.SkipAll
			}
			if entry.Type()&fs.ModeSymlink == 0 {
				return nil
			}
			resolved, ok := ResolveWriteTarget(path)
			if !ok || state.hits(resolved) {
				clear = false
				return filepath.SkipAll
			}
			if info, err := os.Stat(resolved); err == nil && info.IsDir() {
				queue = append(queue, resolved)
			}
			return nil
		})
		if err != nil || !clear {
			return false
		}
	}
	return true
}

func hasDotDotStep(path string) bool {
	return slices.Contains(strings.Split(filepath.ToSlash(path), "/"), "..")
}

// findExecCommands returns the source text of every child command a find
// call runs with -exec, -execdir, -ok or -okdir.
func findExecCommands(command, program string, args []*syntax.Word, words []string, static []bool) []string {
	if program != "find" && program != "gfind" {
		return nil
	}
	var children []string
	for i := 1; i < len(words)-1; i++ {
		if !static[i] || !slices.Contains([]string{"-exec", "-execdir", "-ok", "-okdir"}, words[i]) {
			continue
		}
		end := i + 1
		for end < len(words) && (!static[end] || words[end] != ";" && words[end] != "+") {
			end++
		}
		if end > i+1 {
			children = append(children, command[args[i+1].Pos().Offset():args[end-1].End().Offset()])
		}
		i = end
	}
	return children
}

// throughFile reports a path whose nearest existing parent is not a
// directory: no file can be written there.
func throughFile(path string) bool {
	if hasDotDotStep(path) || !filepath.IsAbs(path) {
		return false
	}
	path = filepath.Clean(path)
	for dir := filepath.Dir(path); dir != path; path, dir = dir, filepath.Dir(dir) {
		if info, err := os.Stat(dir); err == nil {
			return !info.IsDir()
		} else if !os.IsNotExist(err) && !errors.Is(err, syscall.ENOTDIR) {
			return false
		}
	}
	return false
}

// wrapperChangesDirectory reports env -C DIR, sudo -D DIR and find
// -execdir or -okdir: the child runs in another directory (GAP-2533).
func wrapperChangesDirectory(program string, words []string, static []bool) bool {
	switch program {
	case "find", "gfind":
		for i, word := range words {
			if static[i] && (word == "-execdir" || word == "-okdir") {
				return true
			}
		}
	case "env", "sudo":
		// Options before the child program; env and sudo options that
		// take a value skip it.
		valued := map[string][]string{"env": {"-u", "-S"}, "sudo": {"-u", "-g", "-h", "-p", "-C", "-r", "-t", "-U", "-T", "-R"}}[program]
		short, long := map[string]string{"env": "C", "sudo": "D"}[program], "--chdir"
		for i := 1; i < len(words); i++ {
			word := words[i]
			switch {
			case !static[i]:
				return true
			case word == "--":
				return false
			case word == long || strings.HasPrefix(word, long+"="):
				return true
			case strings.HasPrefix(word, "--"):
				continue
			case strings.HasPrefix(word, "-") && len(word) > 1:
				if strings.Contains(word[1:], short) {
					return true
				}
				if slices.Contains(valued, word) {
					i++
				}
			case program == "env" && strings.Contains(word, "="):
				continue
			default:
				return false
			}
		}
	}
	return false
}

// findMove is a find call whose only action is -exec mv {} DEST \; and
// whose only name test is one -name PATTERN: each match keeps its base
// name, which matches pattern, under dest when dir is set, or becomes dest.
type findMove struct {
	pattern, dest string
	dir           bool
	// starts are the absolute start paths (cwd when find names none).
	starts []string
}

// parseFindMove reads find PATH... [-type T] [-maxdepth N] [-mindepth N]
// -name PATTERN -exec mv [OPTIONS] {} DEST \; with every word static and
// DEST free of {}. Any other find call is not read as a move.
func parseFindMove(program string, words []string, static []bool, cwd string) (findMove, bool) {
	var move findMove
	if program != "find" && program != "gfind" || slices.Contains(static, false) {
		return move, false
	}
	i := 1
	for i < len(words) && !strings.HasPrefix(words[i], "-") && words[i] != "(" && words[i] != "!" {
		i++
	}
	for _, start := range words[1:i] {
		move.starts = append(move.starts, absolutePath(start, cwd))
	}
	if len(move.starts) == 0 {
		move.starts = []string{filepath.Clean(cwd)}
	}
	exec := false
	for ; i < len(words); i++ {
		switch words[i] {
		case "-name":
			if move.pattern != "" || i+1 >= len(words) {
				return move, false
			}
			i++
			move.pattern = words[i]
			if _, err := filepath.Match(move.pattern, ""); err != nil || move.pattern == "" {
				return move, false
			}
		case "-type", "-maxdepth", "-mindepth":
			if i+1 >= len(words) {
				return move, false
			}
			i++
		case "-exec":
			end := i + 1
			for end < len(words) && words[end] != ";" {
				end++
			}
			if exec || end != len(words)-1 || end-i < 2 {
				return move, false
			}
			child := words[i+1 : end]
			if base := programBase(child[0]); base != "mv" && base != "gmv" {
				return move, false
			}
			op, ok := parseRename(child[1:], cwd)
			if !ok || len(op.sources) != 1 || op.sources[0] != "{}" {
				return move, false
			}
			dest := op.targetDir
			move.dir = dest != ""
			if dest == "" {
				dest = op.dest
				move.dir = !op.noTargetDir && strings.HasSuffix(dest, "/")
				if info, err := os.Stat(absolutePath(dest, cwd)); !op.noTargetDir && err == nil && info.IsDir() {
					move.dir = true
				}
			}
			if dest == "" || strings.Contains(dest, "{}") || hasDotDotStep(dest) {
				return move, false
			}
			move.dest = filepath.Clean(absolutePath(dest, cwd))
			exec = true
			i = end
		default:
			return move, false
		}
	}
	return move, exec && move.pattern != ""
}

// findMovesClear reports that no find -exec mv can move a link or a
// directory holding one (no name of a link matches the pattern), and that
// no moved match can land on or above a link name or target. The
// destination is checked against both the written and the resolved names,
// read through the links of the command.
func (l shellLinks) findMovesClear(moves []findMove, home string) bool {
	state := newStateReach(home)
	reach := Links{links: l}
	for _, move := range moves {
		// The destination is read through the links of the command, as the
		// plain write is (RV-c4-1): a match moved into a link that reaches
		// state is a state write.
		var dests []string
		for _, form := range append([]string{move.dest}, reach.AliasTargets(move.dest, false)...) {
			resolved, ok := ResolveWriteTarget(form)
			if !ok || move.dir && state.movedMatchHits(resolved, move.pattern) || !move.dir && state.hits(resolved) {
				return false
			}
			dests = append(dests, filepath.Clean(form), resolved)
		}
		for _, alias := range l.aliases {
			for _, part := range strings.Split(filepath.ToSlash(filepath.Clean(alias.name)), "/") {
				if matched, _ := filepath.Match(move.pattern, part); matched {
					return false
				}
			}
			paths := []string{filepath.Clean(alias.name), filepath.Clean(alias.target)}
			for _, path := range paths[:2] {
				if resolved, ok := ResolveWriteTarget(path); ok {
					paths = append(paths, resolved)
				}
			}
			for _, dest := range dests {
				for _, path := range paths {
					if !move.dir {
						if pathsOverlap(dest, path) {
							return false
						}
						continue
					}
					rest, under := cutPathPrefix(path, dest)
					if !under || rest == "" {
						continue
					}
					first := strings.SplitN(filepath.ToSlash(rest), "/", 2)[0]
					if matched, err := filepath.Match(move.pattern, first); err != nil || matched {
						return false
					}
				}
			}
		}
	}
	return true
}

// resolveMissingDotDot resolves a name whose .. steps follow names that do
// not exist on disk (lib/../shared for ln -s ../shared lib, where lib is
// the new link): no disk link can sit there, so .. is read lexically. A
// name the command links there is read through its aliases instead.
func resolveMissingDotDot(path string) (string, bool) {
	if !filepath.IsAbs(path) || !hasDotDotStep(path) {
		return "", false
	}
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, part := range parts {
		if part != ".." || i == 0 {
			continue
		}
		before := filepath.FromSlash(strings.Join(parts[:i], "/"))
		if _, err := os.Lstat(before); !os.IsNotExist(err) {
			return "", false
		}
	}
	return ResolveWriteTarget(filepath.Clean(path))
}

// enteredOnlyLinkNames keeps the names of the link calls that no other word of
// command names, but for a cd or pushd operand that enters them: the call
// writes the name where the statement walk placed it. The rest of the command
// must be known readers alone, so nothing it runs after the entering cd can
// write through the link. A command with an expansion, a pattern or a tilde
// word keeps none, nor does a link to SSH or DefenseClaw state (GAP-0091).
func enteredOnlyLinkNames(file *syntax.File, command, cwd, home string, names []string, aliases []linkAlias, linkTexts []string, placed map[*syntax.CallExpr]bool) map[string]bool {
	if len(names) == 0 || strings.ContainsAny(command, "$`*?[{\\") || !readersBesides(file, home, placed, 0) {
		return nil
	}
	words, programs := commandWordPrograms(command)
	for _, text := range linkTexts {
		for _, word := range commandWords(text) {
			if i := slices.Index(words, word); i >= 0 {
				words = slices.Delete(words, i, i+1)
				programs = slices.Delete(programs, i, i+1)
			}
		}
	}
	cdOperand := func(i int) bool {
		return i > 0 && (words[i-1] == "cd" || words[i-1] == "pushd") && (programs[i] == "cd" || programs[i] == "pushd")
	}
	for i, word := range words {
		// A tilde word may name any path; as the operand of the cd that
		// enters it nothing is written through it.
		if strings.HasPrefix(word, "~") && !cdOperand(i) {
			return nil
		}
	}
	// A link that names SSH or DefenseClaw state is never exempt.
	state := newStateReach(home)
	var kept map[string]bool
	for _, name := range names {
		entered := true
		for _, alias := range aliases {
			if alias.name != name {
				continue
			}
			if state.within(filepath.Clean(alias.target)) {
				entered = false
			} else if resolved, ok := ResolveWriteTarget(alias.target); ok && state.within(resolved) {
				entered = false
			}
		}
		for i, word := range words {
			named := slices.Contains(strings.Split(filepath.ToSlash(word), "/"), filepath.Base(name))
			if !named && !filepath.IsAbs(word) {
				continue
			}
			if !named {
				_, named = cutPathPrefix(filepath.Clean(word), name)
			}
			if named && !cdOperand(i) {
				entered = false
				break
			}
		}
		if entered {
			if kept == nil {
				kept = make(map[string]bool)
			}
			kept[filepath.Clean(name)] = true
		}
	}
	return kept
}

// readerPrograms only read their operands; none has an output file option
// once actionReadOptionMayWrite has refused the output spellings.
var readerPrograms = []string{
	"cat", "head", "tail", "ls", "dir", "stat", "grep", "egrep", "fgrep", "wc", "du", "readlink", "realpath",
}

// readerDirectories are the places a reader program may be named from.
var readerDirectories = []string{"/bin", "/usr/bin", "/usr/local/bin"}

// readersBesides reports that file holds nothing but the skipped link calls,
// directory changes and known reader programs, also inside a literal shell
// body: no redirect, assignment, expansion, loop or function, and a program
// named by a path only from a standard directory.
func readersBesides(file *syntax.File, home string, skip map[*syntax.CallExpr]bool, depth int) bool {
	if depth > 2 {
		return false
	}
	env := expand.ListEnviron("HOME=" + strings.TrimRight(home, "/"))
	safe := true
	syntax.Walk(file, func(node syntax.Node) bool {
		if !safe {
			return false
		}
		switch n := node.(type) {
		case nil:
		case *syntax.File, *syntax.BinaryCmd, *syntax.Subshell, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted:
		case *syntax.Stmt:
			if n.Coprocess || len(n.Redirs) > 0 {
				safe = false
			}
		case *syntax.Word:
		case *syntax.CallExpr:
			if len(n.Assigns) > 0 || len(n.Args) == 0 {
				safe = false
				return false
			}
			if skip[n] {
				return true
			}
			words := make([]string, len(n.Args))
			static := make([]bool, len(n.Args))
			for i, arg := range n.Args {
				words[i], static[i] = staticShellWord(arg, env, home != "")
			}
			if !static[0] {
				safe = false
				return false
			}
			program := programBase(words[0])
			if slices.Contains(cdPrograms, program) || program == "dirs" {
				// A directory change writes nothing, whatever it names (a
				// tilde word of an unknown user is not static).
				safe = len(words) <= 3
				return false
			}
			if slices.Contains(static, false) {
				safe = false
				return false
			}
			if strings.Contains(words[0], "/") && !slices.Contains(readerDirectories, filepath.Dir(words[0])) {
				safe = false
				return false
			}
			switch {
			case slices.Contains(readerPrograms, program):
				for _, option := range words[1:] {
					if actionReadOptionMayWrite(option) {
						safe = false
					}
				}
			case literalShellBody(program, words, static) != "":
				inner, parsed := parseShell(literalShellBody(program, words, static))
				safe = parsed && readersBesides(inner, home, nil, depth+1)
			default:
				safe = false
			}
			return false
		default:
			safe = false
		}
		return safe
	})
	return safe
}
