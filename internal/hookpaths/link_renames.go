package hookpaths

import (
	"path/filepath"
	"slices"
	"strings"

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
	_, under := cutPathPrefix(a, b)
	_, over := cutPathPrefix(b, a)
	return under || over
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
// is renamed or a nested shell changes directory (GAP-2532, GAP-2533).
func (l shellLinks) aliasesInProject(cwd, home string) bool {
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
			if hasDotDotStep(form) {
				return false
			}
			resolved, ok := ResolveWriteTarget(form)
			if !ok {
				return false
			}
			if rest, under := cutPathPrefix(resolved, root); !under || rest == "" {
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
