package hookpaths

import (
	"errors"
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

// aliasesInProject reports that every link the command makes, and every
// name its target reaches through the other links and the disk, lies
// strictly inside the working directory, with no .. step and away from SSH
// and DefenseClaw state. Such a link stays an ordinary project link when it
// is renamed (GAP-2532).
func (l shellLinks) aliasesInProject(cwd, home string) bool {
	return l.aliasesReach(cwd, home, true)
}

// aliasesAwayFromState reports that no link the command makes, nor any
// name its target reaches, can overlap SSH or DefenseClaw state: a target
// that holds the home directory (/, .., ~) overlaps it. Such links stay
// known when a nested shell or a wrapper changes directory (GAP-2533).
func (l shellLinks) aliasesAwayFromState(cwd, home string) bool {
	return l.aliasesReach(cwd, home, false)
}

// aliasesReach is aliasesInProject when inProject is set, and
// aliasesAwayFromState otherwise. A name that goes through an existing
// file that is not a directory names nothing and is skipped (GAP-2532:
// ln -s README.md docs.md also names docs.md/README.md).
func (l shellLinks) aliasesReach(cwd, home string, inProject bool) bool {
	if cwd == "" || home == "" || !filepath.IsAbs(cwd) {
		return false
	}
	root, ok := ResolveWriteTarget(cwd)
	if !ok {
		return false
	}
	ssh := filepath.Join(home, ".ssh")
	var sensitive []string
	for _, path := range append([]string{ssh, filepath.Join(home, ".defenseclaw")}, ProtectedAuthorizedKeysPaths(home)...) {
		sensitive = append(sensitive, filepath.Clean(path))
		if resolved, ok := ResolveWriteTarget(path); ok {
			sensitive = append(sensitive, resolved)
		}
	}
	protected := newProtectedFiles(home)
	reach := Links{links: l}
	for _, alias := range l.aliases {
		for _, form := range append([]string{alias.target}, reach.AliasTargets(alias.target, false)...) {
			if inProject && hasDotDotStep(form) {
				return false
			}
			resolved, ok := ResolveWriteTarget(form)
			if !ok && !inProject {
				resolved, ok = resolveMissingDotDot(form)
			}
			if !ok {
				if throughFile(form) {
					continue
				}
				return false
			}
			if rest, under := cutPathPrefix(resolved, root); inProject && (!under || rest == "") {
				return false
			}
			for _, path := range sensitive {
				if pathsOverlap(resolved, path) {
					return false
				}
			}
			if protectedReachPath(resolved, protected, ssh) || actionProtectedStatePath(resolved, home) {
				return false
			}
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
// destination is checked against both the written and the resolved names.
func (l shellLinks) findMovesClear(moves []findMove) bool {
	for _, move := range moves {
		dests := []string{move.dest}
		if resolved, ok := ResolveWriteTarget(move.dest); ok {
			dests = append(dests, resolved)
		} else {
			return false
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
