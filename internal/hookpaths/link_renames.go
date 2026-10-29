package hookpaths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

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
	return protectedReachPath(resolved, s.protected, s.ssh) || actionProtectedStatePath(resolved, s.home)
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

// linkedTreesClear reports that a directory change in a nested shell or a
// wrapper, or a find -exec mv, cannot reach SSH or DefenseClaw state through
// a disk link below a directory a link of the command names (RV-c4-1). The
// statement walk does not place those directory changes, so the disk links
// under the link are checked instead: the walk runs only when a command
// word outside the link calls may name a link, and finds no disk link
// that reaches state. A plain cd resolves such disk links itself.
func (l shellLinks) linkedTreesClear(command, cwd, home string) bool {
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
	if len(dirs) == 0 || !l.mayEnterLink(command, cwd) {
		return true
	}
	return treesAwayFromState(dirs, state)
}

// mayEnterLink reports that a word of command other than the link calls
// names a link (its base name), may expand or match one, makes find follow
// links, or is a dangling disk link in cwd that may name a new link.
func (l shellLinks) mayEnterLink(command, cwd string) bool {
	if strings.ContainsAny(command, "$`*?[{\\") {
		return true
	}
	words := commandTokens(command)
	for _, text := range l.linkTexts {
		for _, word := range commandTokens(text) {
			if i := slices.Index(words, word); i >= 0 {
				words = slices.Delete(words, i, i+1)
			}
		}
	}
	names := make(map[string]bool)
	for _, alias := range l.aliases {
		names[filepath.Base(alias.name)] = true
	}
	for _, word := range words {
		if names[word] || word == "-L" || word == "-follow" {
			return true
		}
		path := absolutePath(word, cwd)
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			if _, err := filepath.EvalSymlinks(path); err != nil {
				return true
			}
		}
	}
	return false
}

// commandTokens splits command text into path components and words.
func commandTokens(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		return strings.ContainsRune(" \t\n\r/\"';&|()<>=,", r)
	})
}

// treesAwayFromState walks dirs and the directories their disk links reach,
// and reports that no disk link reaches state.
func treesAwayFromState(dirs []string, state stateReach) bool {
	seen := make(map[string]bool)
	queue := slices.Clone(dirs)
	entries := 0
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
			if err != nil || entries > maxLinkedTreeEntries {
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
		for end < len(words) && !(static[end] && (words[end] == ";" || words[end] == "+")) {
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
