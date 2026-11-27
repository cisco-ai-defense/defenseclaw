// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// BackupUnresolvedKey carries the hook client's finding that an in-place
// editor's backup file (sed -i, perl -i) could not be resolved to one path
// (SedInPlaceBackupUnresolved), for a gateway that does not open the user
// home. The value is "1".
const BackupUnresolvedKey = "\x00backup-unresolved"

// The in-place backup reader (rel-1-0-10:GAP-0414, GAP-0540..0543).
//
// sed -i and perl -i replace the edited file by a rename and a new file,
// and write a second path when a suffix is given: the backup. The reader
// judges every path the call can write, with the working directory of the
// command: the edited file and the backup its suffix names (sedGNUInPlace,
// sedBSDInPlace, perlInPlace and sedBackupName hold the name rules of GNU
// sed, BSD sed and perl). A path the words name in full that reaches a
// protected file is a block.
//
// A "*" suffix whose folder part is the keys folder (sed -i'~/.ssh/*.bak',
// perl -pi'~/.ssh/*') lets the operand name the entry the backup writes in
// that folder; the call is judged as a write to the keys folder itself, as a
// copy into it is (cp f ~/.ssh/), whatever the operand and in every spelling
// of the word: quoted, unquoted, escaped or from a brace list
// (rel-1-0-10:GAP-0669). A star later in the entry name (~/.ssh/x*) names
// only entries that start with that text and is judged by the backup name.
//
// A backup the reader cannot name in full is never a silent allow: it is
// reported as unresolved, and the hook judges the call at least in the
// unknown tier of the pack (the one bound rule, internal/guardrail/bounded):
// an alert in the default and permissive packs, a block in the strict pack.
// A backup is unresolved when
//   - the suffix has a word the shell expands at run time;
//   - the suffix has a "*" (GNU sed and perl put the operand as typed where
//     the star is, so the backup can be in another folder) and the operand
//     comes from run time (a variable, xargs, find -exec) or the name is
//     relative to a directory the words do not name;
//   - --follow-symlinks names the backup after the link target, and the
//     operand is dynamic or its link cannot be read.
//
// A plain suffix (".bak") puts the backup beside the edited file, so it adds
// nothing to the verdict of the edit itself: a dynamic operand or directory
// keeps the verdict the edit has. A word of the script is no part of any
// path.
//
// The words are those bash makes (rel-1-0-10:GAP-0667, GAP-0669): quotes and
// escapes removed (s''ed, s\ed), unquoted brace lists expanded (sed
// -i{.bak,keys/*} has two -i words and the last wins; a list past
// sedBraceWordLimit stays a run-time word), the program named by its word
// and never by a substring of the raw command. xargs options are read from
// the GNU and BSD grammars (sedXargsRead); sudo -D and --chdir set the
// directory like env -C; a shell reading standard input takes the literals an
// earlier stage of its pipeline prints; a call whose only argument is "$@"
// may edit in place and is unresolved.

// sedHole stands for the part of a word the shell expands at run time.
const sedHole = "\x01"

// sedKind is the reading of the call's command line.
type sedKind uint8

const (
	sedGNUKind sedKind = iota
	sedBSDKind
	sedPerlKind
)

// actionSedInPlaceWrite reports an in-place editor call of the command that
// writes a protected file, as the edited file or as its backup.
func actionSedInPlaceWrite(command, cwd, home string, memo *TargetMemo) bool {
	blocked, _ := actionSedInPlaceReading(command, cwd, home, memo, false)
	return blocked
}

// actionSedInPlaceBackupWrite reports an in-place editor call of the command
// whose backup (or --follow-symlinks name) is a protected file. The edited
// operand itself is left out: the replace-verb proof (replaceVerbSafeIn)
// decides whether the edit replaces that entry or writes through it, and a
// backup is a second path that proof never covers (rel-1-0-10:GAP-0414).
func actionSedInPlaceBackupWrite(command, cwd, home string, memo *TargetMemo) bool {
	blocked, _ := actionSedInPlaceReading(command, cwd, home, memo, true)
	return blocked
}

// actionSedInPlaceDecision is the client decision of an in-place editor call:
// a backup that is a protected file, or an edited operand that reaches one
// when the replace-verb proof does not hold. sed -i of a hard link of a
// protected file replaces the link and leaves the file as it was
// (rel-1-0-10:GAP-0377, the hlink matrix benign rows).
func actionSedInPlaceDecision(command, cwd, home string, memo *TargetMemo) bool {
	if actionSedInPlaceBackupWrite(command, cwd, home, memo) {
		return true
	}
	return actionSedInPlaceWrite(command, cwd, home, memo) &&
		!replaceVerbSafeIn(command, cwd, home, memo.shellStartup())
}

// SedInPlaceBackupUnresolved reports a command with an in-place editor
// whose backup path the reader cannot resolve in full (the comment above),
// and that is not already a proven write to a protected file. The hook
// judges it at least in the unknown tier.
func SedInPlaceBackupUnresolved(command, cwd, home string) bool {
	return (*TargetMemo)(nil).SedInPlaceBackupUnresolved(command, cwd, home)
}

// SedInPlaceBackupUnresolved is the package function of that name, with the
// file system answers of the evaluation m (nil: none).
func (m *TargetMemo) SedInPlaceBackupUnresolved(command, cwd, home string) bool {
	blocked, unresolved := actionSedInPlaceReading(command, cwd, home, m, false)
	return unresolved && !blocked
}

func actionSedInPlaceReading(command, cwd, home string, memo *TargetMemo, backupOnly bool) (blocked, unresolved bool) {
	if command == "" || home == "" || len(command) > MaxPayloadBytes || !filepath.IsAbs(cwd) || actionWindowsHome(home) {
		return false, false // an in-place editor is a POSIX path; a Windows home has its own readers
	}
	// No text test of the command stands in front of the reader: a program
	// name is what the parser makes of the word (quotes and escapes removed,
	// braces expanded, wrappers peeled), never a substring of the raw text
	// (rel-1-0-10:GAP-0667: s''ed, "s"ed and s\ed name sed too).
	reader := &sedBackupReader{cwd: cwd, home: home, ssh: filepath.Join(home, ".ssh"), memo: memo, backupOnly: backupOnly}
	reader.read(command, sedBackupScope{dirs: []string{cwd}}, 0)
	return reader.blocked, reader.unresolved
}

type sedBackupReader struct {
	cwd, home           string
	protected           protectedFiles
	haveProtected       bool
	ssh                 string
	memo                *TargetMemo
	blocked, unresolved bool
	// optionHole is set while a call is read that has a brace list too large
	// to expand where an option can start: any in-place editor in it may
	// have an option the words do not show.
	optionHole bool
	// backupOnly leaves the edited operand as typed out of the judged paths
	// (actionSedInPlaceBackupWrite).
	backupOnly bool
}

// protectedSet is the protected files of the home, read on the first path
// to judge: a command with no in-place editor never needs them.
func (r *sedBackupReader) protectedSet() protectedFiles {
	if !r.haveProtected {
		r.protected, r.haveProtected = r.memo.protectedFiles(r.home), true
	}
	return r.protected
}

// sedBackupScope is where the calls of a command run: every directory a cd
// of the command names (a relative name is judged from each, so a cd in a
// subshell or a branch cannot hide the write), and unknown when a directory
// change names none (cd -, cd "$D", env -C "$D", find -execdir).
type sedBackupScope struct {
	dirs    []string
	unknown bool
}

const sedBackupDepth = 8

func (r *sedBackupReader) read(command string, scope sedBackupScope, depth int) {
	// The reader only reads the tree: both readings of a decision share it.
	file, parsed := r.memo.parsedShell(command)
	if !parsed {
		return
	}
	values := actionValues{"HOME": r.home, "PWD": r.cwd}
	scope.dirs = slices.Clone(scope.dirs)
	pipes := map[*syntax.BinaryCmd]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		if r.blocked {
			return false
		}
		switch typed := node.(type) {
		case *syntax.Stmt:
			r.stdinBody(typed, values, scope, depth)
		case *syntax.BinaryCmd:
			if (typed.Op == syntax.Pipe || typed.Op == syntax.PipeAll) && !pipes[typed] {
				r.pipeline(typed, pipes, values, scope, depth)
			}
		case *syntax.CallExpr:
			if len(typed.Args) > 0 {
				words, overflow := r.callWords(typed.Args, values)
				saved := r.optionHole
				r.optionHole = overflow
				r.call(words, &scope, depth)
				// An escaped character (\*, s\ed) is the character itself to
				// the shell; the word text keeps the backslash, so both
				// spellings are judged.
				if slices.ContainsFunc(words, func(word string) bool { return strings.Contains(word, `\`) }) {
					plain := make([]string, len(words))
					for i, word := range words {
						plain[i] = actionUnescapeShell(word)
					}
					r.call(plain, &scope, depth)
				}
				r.optionHole = saved
			}
		}
		return !r.blocked
	})
}

// call reads one simple command; a cd changes the scope of the later calls.
func (r *sedBackupReader) call(words []string, scope *sedBackupScope, depth int) {
	if strings.Contains(words[0], sedHole) {
		// A program word that holds a hole is a run-time word, which other
		// layers judge; a hole that is a brace list past the caps (optionHole)
		// is a word the reader could not expand, so the call may be an editor
		// (bound rule, rel-1-0-10:GAP-0739).
		if r.optionHole {
			r.unresolved = true
		}
		return
	}
	switch programBase(words[0]) {
	case "cd", "pushd":
		r.changeDirectory(words, scope)
	case "popd":
		scope.unknown = true
	default:
		r.run(words, *scope, false, depth)
	}
}

func (r *sedBackupReader) changeDirectory(words []string, scope *sedBackupScope) {
	target, found := "", false
	for i := 1; i < len(words); i++ {
		word := words[i]
		if word == "--" {
			if i+1 < len(words) {
				target, found = words[i+1], true
			}
			break
		}
		if word == "-" {
			scope.unknown = true // OLDPWD
			return
		}
		if strings.HasPrefix(word, "-") {
			continue
		}
		target, found = word, true
		break
	}
	switch {
	case !found && programBase(words[0]) == "cd":
		scope.dirs = append(scope.dirs, r.home)
	case !found, strings.Contains(target, sedHole),
		strings.HasPrefix(target, "~"), // ~-, ~+, ~login: a tilde-prefix the words do not resolve (OLDPWD, PWD, a home)
		programBase(words[0]) == "pushd" && strings.HasPrefix(target, "+"):
		scope.unknown = true
	case target != "":
		scope.dirs = append(scope.dirs, OperandPath(target, scope.dirs[len(scope.dirs)-1]))
	}
}

// run reads one command after the prefix wrappers (env -C DIR, nice, time,
// sudo...). implicit marks a command whose operands come from run time
// (xargs).
func (r *sedBackupReader) run(words []string, scope sedBackupScope, implicit bool, depth int) {
	words, scope = r.unwrap(words, scope)
	if len(words) == 0 || strings.Contains(words[0], sedHole) {
		if len(words) > 0 && r.optionHole {
			r.unresolved = true // as in call: a brace list past the caps names the program
		}
		return
	}
	switch program := sedProgram(words[0]); {
	case program == "sed":
		r.sed(words, scope, implicit)
	case program == "perl":
		if r.optionHole {
			r.unresolved = true
		}
		if files, suffix, ok := perlInPlace(words); ok {
			r.inPlace(sedPerlKind, files, suffix, false, scope, implicit)
		} else {
			r.splat(words)
		}
	case program == "xargs":
		r.xargs(words, scope, depth)
	case program == "find":
		for _, exec := range sedFindExecs(words) {
			inner := scope
			inner.unknown = inner.unknown || exec.dirUnknown
			r.run(exec.child, inner, false, depth)
		}
	case program == "eval" && len(words) > 1:
		if depth >= sedBackupDepth {
			r.unresolved = true // the depth cap: the body is not read (bound rule, rel-1-0-10:GAP-0738)
			return
		}
		r.read(strings.Join(words[1:], " "), scope, depth+1)
	case posixShellProgram(program):
		if body, ok := actionShellCommandBody(words); ok {
			if depth >= sedBackupDepth {
				r.unresolved = true // as for eval above
				return
			}
			r.read(body, scope, depth+1)
		}
	}
}

// sedProgram is the program a command word names, as the readers of this
// file know it: the last element of its path in lower case, with the GNU
// prefix of the macOS ports (gsed, gxargs, gfind) dropped; programBase
// already drops the version of perl (perl5.38.2).
func sedProgram(word string) string {
	name := programBase(word)
	switch {
	case name == "gsed":
		return "sed"
	case name == "gxargs":
		return "xargs"
	case name == "gfind":
		return "find"
	}
	return name
}

// splat marks a call whose only argument is "$@" or "$*" (a function or
// script that forwards its own arguments: every word of the call, options
// included, comes from run time): it may or may not edit in place. A "$@"
// next to other words is a run-time operand, as any variable is.
func (r *sedBackupReader) splat(words []string) {
	if len(words) == 2 && words[1] == sedSplat {
		r.unresolved = true
	}
}

// unwrap peels the prefix wrappers off words and applies the directory a
// wrapper sets.
func (r *sedBackupReader) unwrap(words []string, scope sedBackupScope) ([]string, sedBackupScope) {
	static := make([]bool, len(words))
	for i := range static {
		static[i] = true
	}
	wrapped, ok := actionfacts.StaticPrefixWrapperChild(words, static)
	if !ok || wrapped.Index >= len(words) {
		return words, scope
	}
	switch {
	case strings.Contains(wrapped.Dir, sedHole):
		scope.unknown = true
	case wrapped.Dir != "":
		dirs := make([]string, len(scope.dirs))
		for i, dir := range scope.dirs {
			dirs[i] = OperandPath(wrapped.Dir, dir)
		}
		scope.dirs = dirs
	}
	if wrapped.DirUnknown {
		scope.unknown = true
	}
	return words[wrapped.Index:], scope
}

func (r *sedBackupReader) sed(words []string, scope sedBackupScope, implicit bool) {
	if r.optionHole {
		r.unresolved = true
	}
	follow := sedFollowsInPlaceLinks(words)
	found := false
	if files, suffix, ok := sedGNUInPlace(words); ok {
		found = true
		r.inPlace(sedGNUKind, files, suffix, follow, scope, implicit)
	}
	if files, suffix, ok := sedBSDInPlace(words); ok {
		found = true
		r.inPlace(sedBSDKind, files, suffix, false, scope, implicit)
	}
	if !found {
		r.splat(words)
	}
}

// inPlace judges the paths an in-place call of the given reading writes.
func (r *sedBackupReader) inPlace(kind sedKind, files []string, suffix string, follow bool, scope sedBackupScope, implicit bool) {
	if implicit {
		files = append(slices.Clone(files), sedHole)
	}
	suffixHole := strings.Contains(suffix, sedHole)
	star := kind != sedBSDKind && !suffixHole && strings.Contains(suffix, "*")
	if folder := sedStarFolder(suffix); star && folder != "" && slices.ContainsFunc(files, func(file string) bool { return file != "" }) {
		r.judge(folder, scope.dirs)
	}
	for _, file := range files {
		if file == "" || r.blocked {
			continue
		}
		fileHole := strings.Contains(file, sedHole)
		var names []string
		if !fileHole && !r.backupOnly {
			names = append(names, file)
		}
		switch {
		case suffix == "":
		case suffixHole:
			// The separate word BSD sed reads as the suffix of a bare -i is
			// usually the script of GNU sed (sed -i "s/$A/$B/" f g), and a
			// BSD suffix cannot leave the folder of the edited file: only a
			// word that is nothing but run-time text counts as a suffix.
			if kind != sedBSDKind || strings.Trim(suffix, sedHole) == "" {
				r.unresolved = true
			}
		case fileHole:
			if star || follow {
				r.unresolved = true
			}
		default:
			backup := sedBackupName(kind, file, suffix)
			names = append(names, backup)
			if star && scope.unknown && !filepath.IsAbs(backup) {
				r.unresolved = true
			}
		}
		for _, name := range names {
			r.judge(name, scope.dirs)
		}
		if follow && suffix != "" && !suffixHole && !fileHole {
			r.followed(kind, file, suffix, scope)
		}
	}
}

// followed judges the backup of --follow-symlinks: GNU sed edits the file a
// link names and builds the backup from that name (the link target joined
// to the folder of the link), not from the operand as typed.
func (r *sedBackupReader) followed(kind sedKind, file, suffix string, scope sedBackupScope) {
	if scope.unknown && !filepath.IsAbs(file) {
		r.unresolved = true
		return
	}
	for _, dir := range scope.dirs {
		name, ok := sedFollowedName(file, dir)
		switch {
		case !ok:
			r.unresolved = true
		case name != file:
			r.judge(name, []string{dir})
			r.judge(sedBackupName(kind, name, suffix), []string{dir})
		}
	}
}

func (r *sedBackupReader) judge(name string, dirs []string) {
	if strings.ContainsAny(name, "\x00\r\n") || strings.Contains(name, sedHole) {
		return
	}
	for _, dir := range dirs {
		if protectedReachPathWith(OperandPath(name, dir), r.protectedSet(), r.ssh, r.memo) {
			r.blocked = true
			return
		}
	}
}

// sedStarFolder is the folder a "*" suffix puts its backups in when the
// first star starts an entry name (dir/*.bak, dir/*): the text before the
// star, which ends in a slash. It is "" for a star inside an entry name
// (dir/x*) and for a suffix with no folder part (*.bak, beside the file).
func sedStarFolder(suffix string) string {
	star := strings.IndexByte(suffix, '*')
	if star <= 0 || suffix[star-1] != '/' {
		return ""
	}
	return suffix[:star]
}

// sedBackupName is the backup the editor writes for file with a suffix
// (never empty): BSD sed appends it verbatim; GNU sed and perl put file as
// typed where each "*" stands, or append the suffix when it has none.
func sedBackupName(kind sedKind, file, suffix string) string {
	if kind == sedBSDKind {
		return file + suffix
	}
	return starBackupName(file, suffix)
}

// sedFollowedName is the name sed --follow-symlinks edits for file typed in
// dir: the chain of links read with readlink, a relative target joined to
// the folder part of the name before it. ok is false when a link or the
// file cannot be read, or the chain is too long.
func sedFollowedName(file, dir string) (string, bool) {
	current := file
	for hops := 0; hops < 40; hops++ {
		path := current
		if !filepath.IsAbs(path) {
			path = dir + "/" + path
		}
		info, err := pathLstat(path)
		if err != nil {
			return "", false
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return current, true
		}
		target, err := pathReadlink(path)
		if err != nil || target == "" {
			return "", false
		}
		if slash := strings.LastIndexByte(current, '/'); filepath.IsAbs(target) || slash < 0 {
			current = target
		} else {
			current = current[:slash+1] + target
		}
	}
	return "", false
}

// sedSplat stands for a word that is all of "$@" or "$*": the shell makes
// any number of words of it, options among them. It holds a sedHole, so a
// reader that does not know it reads a run-time word.
const sedSplat = sedHole + "\x02"

// sedBraceWordLimit and sedBraceCallLimit bound the words the brace lists
// of one word and of one command expand to; a list past either is run-time
// text (a hole) and the call that holds it is at least unresolved when it
// is an in-place editor call.
const (
	sedBraceWordLimit = 256
	sedBraceCallLimit = 1024
)

// callWords makes the words of a simple command as bash does: each unquoted
// brace list is expanded first (sed -i{.bak,keys/*} is two -i words, the
// last wins), then each part the shell expands at run time is a hole.
// overflow is set when a brace list too large to expand stands where an
// option can start.
func (r *sedBackupReader) callWords(args []*syntax.Word, values actionValues) (words []string, overflow bool) {
	budget := sedBraceCallLimit
	for _, arg := range args {
		expanded, over := sedBraceWords(arg, &budget)
		for _, word := range expanded {
			text, _ := sedHoledWord(word, values, r.cwd, r.home)
			words = append(words, text)
			// A list too large to expand can hide an option only at the
			// start of a word (-{i,n}{1..999}); inside a file name or a
			// suffix it is a run-time part the readers already know.
			if over && strings.HasPrefix(strings.TrimLeft(text, "-"), sedHole) {
				overflow = true
			}
		}
	}
	return words, overflow
}

// sedBraceWords expands the unquoted brace lists of word. A word with none
// is returned as it is. A list past the limits stays unexpanded (its parts
// read as holes) and sets overflow.
func sedBraceWords(word *syntax.Word, budget *int) (words []*syntax.Word, overflow bool) {
	if !slices.ContainsFunc(word.Parts, func(part syntax.WordPart) bool {
		lit, ok := part.(*syntax.Lit)
		return ok && strings.Contains(lit.Value, "{")
	}) {
		return []*syntax.Word{word}, false
	}
	// SplitBraces rewrites the parts of the word it is given; the tree may be
	// shared (the parse cache), so it gets a copy.
	split := &syntax.Word{Parts: slices.Clone(word.Parts)}
	if !syntax.SplitBraces(split) || !sedHasBraceList(split.Parts) {
		return []*syntax.Word{word}, false
	}
	limit := min(sedBraceWordLimit, *budget)
	count := sedBraceCount(split.Parts, limit)
	if count > limit {
		return []*syntax.Word{split}, true
	}
	expanded, ok := sedExpandBraces(split)
	if !ok {
		return []*syntax.Word{split}, true
	}
	*budget -= len(expanded)
	return expanded, false
}

// sedExpandBraces is expand.Braces with a panic of the library read as a
// word it cannot expand.
func sedExpandBraces(word *syntax.Word) (words []*syntax.Word, ok bool) {
	defer func() {
		if recover() != nil {
			words, ok = nil, false
		}
	}()
	return expand.Braces(word), true
}

func sedHasBraceList(parts []syntax.WordPart) bool {
	return slices.ContainsFunc(parts, func(part syntax.WordPart) bool {
		_, ok := part.(*syntax.BraceExp)
		return ok
	})
}

// sedBraceCount is an upper bound of the words the brace lists of parts
// expand to, and limit+1 when it is past limit.
func sedBraceCount(parts []syntax.WordPart, limit int) int {
	total := 1
	for _, part := range parts {
		list, ok := part.(*syntax.BraceExp)
		if !ok {
			continue
		}
		count := 0
		if list.Sequence {
			count = sedSequenceCount(list, limit)
		} else {
			for _, elem := range list.Elems {
				count += sedBraceCount(elem.Parts, limit)
				if count > limit {
					return limit + 1
				}
			}
		}
		total *= max(count, 1)
		if total > limit {
			return limit + 1
		}
	}
	return total
}

// sedSequenceCount is the size of a {from..to} list: the distance of its
// ends plus one (the step only makes it smaller), limit+1 for ends that are
// not small numbers or characters.
func sedSequenceCount(list *syntax.BraceExp, limit int) int {
	if len(list.Elems) < 2 {
		return limit + 1
	}
	from, to := list.Elems[0].Lit(), list.Elems[1].Lit()
	low, errLow := strconv.Atoi(from)
	high, errHigh := strconv.Atoi(to)
	if errLow != nil || errHigh != nil {
		if len(from) != 1 || len(to) != 1 {
			return limit + 1
		}
		low, high = int(from[0]), int(to[0])
	}
	distance := high - low
	if distance < 0 {
		distance = -distance
	}
	if distance < 0 || distance >= limit {
		return limit + 1
	}
	return distance + 1
}

// sedHoledWord is the text of a command word with each part the shell
// expands at run time replaced by sedHole; static reports a word with none.
// A word that is all of "$@" or "$*" is sedSplat.
func sedHoledWord(word *syntax.Word, values actionValues, cwd, home string) (text string, static bool) {
	if sedSplatWord(word) {
		return sedSplat, false
	}
	if !sedHasBraceList(word.Parts) {
		if value, ok := actionWordValueWithGlob(word, values, cwd, home, true); ok {
			return value, true
		}
	}
	var out strings.Builder
	var parts func([]syntax.WordPart)
	parts = func(items []syntax.WordPart) {
		for _, item := range items {
			if quoted, ok := item.(*syntax.DblQuoted); ok {
				parts(quoted.Parts)
				continue
			}
			if _, list := item.(*syntax.BraceExp); list {
				out.WriteString(sedHole)
				continue
			}
			if value, ok := actionWordValueWithGlob(&syntax.Word{Parts: []syntax.WordPart{item}}, values, cwd, home, true); ok {
				out.WriteString(value)
			} else {
				out.WriteString(sedHole)
			}
		}
	}
	parts(word.Parts)
	return out.String(), false
}

// sedSplatWord reports a word that is all of $@ or $* (quoted or not, with
// or without a slice): "$@", ${@:2}, $*.
func sedSplatWord(word *syntax.Word) bool {
	parts := word.Parts
	if len(parts) == 1 {
		if quoted, ok := parts[0].(*syntax.DblQuoted); ok {
			parts = quoted.Parts
		}
	}
	if len(parts) != 1 {
		return false
	}
	param, ok := parts[0].(*syntax.ParamExp)
	return ok && param.Param != nil && (param.Param.Value == "@" || param.Param.Value == "*")
}

// sedWordText is the text of a word the shell may read as a program: its
// value when static, else its source text (a dynamic part stays a dynamic
// part for the reader of the body).
func sedWordText(word *syntax.Word, values actionValues, cwd, home string) string {
	if value, ok := actionWordValueWithGlob(word, values, cwd, home, true); ok {
		return value
	}
	var out strings.Builder
	if err := syntax.NewPrinter().Print(&out, word); err != nil {
		return ""
	}
	return out.String()
}

// sedXargsCandidates bounds the words after an unknown xargs option that are
// tried as the start of the command.
const sedXargsCandidates = 16

// xargs reads the command xargs runs. Without a replacement string xargs
// appends the operands it reads from standard input (implicit). An option
// the grammar below does not know may take a value, so the command can start
// at any later word and each is read.
func (r *sedBackupReader) xargs(words []string, scope sedBackupScope, depth int) {
	parsed := sedXargsRead(words)
	starts := []int{parsed.child}
	if parsed.unknown {
		starts = starts[:0]
		end := min(len(words), parsed.child+sedXargsCandidates)
		for at := parsed.child; at < end; at++ {
			starts = append(starts, at)
		}
		if end < len(words) {
			r.unresolved = true // the bound rule: the words past the cap are not read
		}
	}
	for _, start := range starts {
		if start >= len(words) {
			continue
		}
		child := words[start:]
		if parsed.replace != "" {
			r.run(sedReplaceWords(child, parsed.replace), scope, false, depth)
		} else {
			r.run(child, scope, true, depth)
		}
	}
}

// sedXargs is the reading of an xargs command line: child is the index of
// the word that starts the command (len(words) for none), replace the
// replacement string of -I, -J, -i or --replace, and unknown is set when an
// option of this reading is not in the grammar (child is then the index of
// that option).
type sedXargs struct {
	child   int
	replace string
	unknown bool
}

// The options of xargs, GNU findutils and BSD (FreeBSD, macOS), as getopt
// reads them: an option stops at the first word that is not an option.
const (
	xargsFlags     = "0oprtx"      // GNU and BSD options without a value
	xargsValued    = "aEIJLnPRSsd" // -a -d (GNU) -E -I -L -n -P -s (both) -J -R -S (BSD): the value is the rest of the word or the next word
	xargsOptionals = "eil"         // GNU -e, -i, -l: the value is the rest of the word, never the next
)

type xargsLong struct {
	name string
	kind byte // 'f' no value, 'v' a value (=VALUE or the next word), 'o' an optional =VALUE
	// short is the equivalent short option ('I' for --replace is -i)
	short byte
}

var xargsLongOptions = []xargsLong{
	{"null", 'f', '0'}, {"arg-file", 'v', 'a'}, {"delimiter", 'v', 'd'}, {"eof", 'o', 'e'},
	{"replace", 'o', 'i'}, {"max-lines", 'o', 'l'}, {"max-args", 'v', 'n'}, {"max-chars", 'v', 's'},
	{"max-procs", 'v', 'P'}, {"process-slot-var", 'v', 0}, {"interactive", 'f', 'p'},
	{"no-run-if-empty", 'f', 'r'}, {"open-tty", 'f', 'o'}, {"verbose", 'f', 't'}, {"exit", 'f', 'x'},
	{"show-limits", 'f', 0}, {"version", 'f', 0}, {"help", 'f', 0},
}

// sedXargsRead reads the options of an xargs call from its grammar.
func sedXargsRead(words []string) sedXargs {
	var parsed sedXargs
	i := 1
	for ; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "--":
			parsed.child = i + 1
			return parsed
		case !strings.HasPrefix(word, "-") || word == "-":
			parsed.child = i
			return parsed
		case strings.HasPrefix(word, "--"):
			name, value, hasValue := strings.Cut(word[2:], "=")
			option, ok := sedXargsLongOption(name)
			if !ok {
				parsed.child, parsed.unknown = i, true
				return parsed
			}
			if option.kind == 'v' && !hasValue {
				i++ // the value is the next word
			}
			if option.short == 'i' {
				parsed.replace = "{}"
				if value != "" {
					parsed.replace = value
				}
			}
		default:
			// A cluster of short options (-0rn1, -I{}, -i, -n 1).
			for j := 1; j < len(word); j++ {
				letter := word[j]
				switch {
				case strings.IndexByte(xargsFlags, letter) >= 0:
					continue
				case strings.IndexByte(xargsOptionals, letter) >= 0:
					if letter == 'i' {
						parsed.replace = "{}"
						if word[j+1:] != "" {
							parsed.replace = word[j+1:]
						}
					}
				case strings.IndexByte(xargsValued, letter) >= 0:
					value := word[j+1:]
					if value == "" && i+1 < len(words) {
						i++
						value = words[i]
					}
					if letter == 'I' || letter == 'J' {
						parsed.replace = value
					}
				default:
					parsed.child, parsed.unknown = i, true
					return parsed
				}
				break // the rest of the word was the value
			}
		}
	}
	parsed.child = i
	return parsed
}

// sedXargsLongOption finds the long option of GNU xargs a name stands for:
// the exact name, else the one option it is the prefix of.
func sedXargsLongOption(name string) (xargsLong, bool) {
	var found xargsLong
	matches := 0
	for _, option := range xargsLongOptions {
		if option.name == name {
			return option, true
		}
		if name != "" && strings.HasPrefix(option.name, name) {
			found, matches = option, matches+1
		}
	}
	return found, matches == 1
}

// sedReplaceWords is words with the replacement string of xargs -I (the
// operand the run time fills in) as a hole.
func sedReplaceWords(words []string, replace string) []string {
	out := make([]string, len(words))
	for i, word := range words {
		out[i] = strings.ReplaceAll(word, replace, sedHole)
	}
	return out
}

type sedFindExec struct {
	child      []string
	dirUnknown bool
}

// sedFindExecs lists the commands of -exec, -execdir, -ok and -okdir of a
// find call, the found file ({}) as a hole. The -dir forms run in the
// folder of the found file, which the words do not name.
func sedFindExecs(words []string) (execs []sedFindExec) {
	for i := 1; i < len(words); i++ {
		switch words[i] {
		case "-exec", "-execdir", "-ok", "-okdir":
			end := i + 1
			for end < len(words) && words[end] != ";" && words[end] != "+" {
				end++
			}
			execs = append(execs, sedFindExec{
				child:      sedReplaceWords(words[i+1:end], "{}"),
				dirUnknown: words[i] == "-execdir" || words[i] == "-okdir",
			})
			i = end
		}
	}
	return execs
}

// sedStdinPath reports a script operand that names standard input.
func sedStdinPath(word string) bool {
	switch filepath.Clean(word) {
	case "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0":
		return true
	}
	return false
}

// readsShellStdin reports a POSIX shell call that reads its program from
// standard input: no -c body and no script operand (or an operand that is
// standard input: /dev/stdin), and source or . of standard input.
func (r *sedBackupReader) readsShellStdin(call *syntax.CallExpr, values actionValues) bool {
	words, _ := r.callWords(call.Args, values)
	words, _ = r.unwrap(words, sedBackupScope{})
	if len(words) == 0 || strings.Contains(words[0], sedHole) {
		return false
	}
	program := programBase(actionUnescapeShell(words[0]))
	switch {
	case program == "source" || program == ".":
		return len(words) > 1 && sedStdinPath(words[1])
	case posixShellProgram(program):
		if _, body := actionShellCommandBody(words); body {
			return false
		}
		script, has := shellScriptOperand(words)
		return !has || sedStdinPath(script)
	}
	return false
}

// stdinBody reads the program a shell takes from a heredoc or a herestring.
func (r *sedBackupReader) stdinBody(stmt *syntax.Stmt, values actionValues, scope sedBackupScope, depth int) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 || len(stmt.Redirs) == 0 || !r.readsShellStdin(call, values) {
		return
	}
	bodies := sedRedirectBodies(stmt, values, r.cwd, r.home)
	if depth >= sedBackupDepth && len(bodies) > 0 {
		r.unresolved = true // the depth cap: the heredoc is not read (bound rule)
		return
	}
	for _, text := range bodies {
		r.read(text, scope, depth+1)
	}
}

// sedRedirectBodies lists the text of the heredocs and herestrings of stmt.
func sedRedirectBodies(stmt *syntax.Stmt, values actionValues, cwd, home string) (bodies []string) {
	for _, redirect := range stmt.Redirs {
		switch redirect.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			if redirect.Hdoc != nil {
				bodies = append(bodies, sedWordText(redirect.Hdoc, values, cwd, home))
			}
		case syntax.WordHdoc:
			if redirect.Word != nil {
				bodies = append(bodies, sedWordText(redirect.Word, values, cwd, home))
			}
		}
	}
	return bodies
}

// pipeline reads the programs a pipeline feeds a shell that reads standard
// input: every literal an earlier stage of it prints (echo, printf, a cat of
// a heredoc, in any block, loop or branch of that stage), whatever the
// stages between do with it (a filter may change the text; the literal is
// the program that can arrive).
func (r *sedBackupReader) pipeline(top *syntax.BinaryCmd, seen map[*syntax.BinaryCmd]bool, values actionValues, scope sedBackupScope, depth int) {
	var stages []*syntax.Stmt
	var flatten func(*syntax.Stmt)
	flatten = func(stmt *syntax.Stmt) {
		if stmt == nil {
			return
		}
		if pipe, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && (pipe.Op == syntax.Pipe || pipe.Op == syntax.PipeAll) {
			seen[pipe] = true
			flatten(pipe.X)
			flatten(pipe.Y)
			return
		}
		stages = append(stages, stmt)
	}
	seen[top] = true
	flatten(top.X)
	flatten(top.Y)
	for at, stage := range stages {
		reader, ok := stage.Cmd.(*syntax.CallExpr)
		if !ok || len(reader.Args) == 0 || !r.readsShellStdin(reader, values) {
			continue
		}
		if depth >= sedBackupDepth {
			if at > 0 {
				r.unresolved = true // the depth cap: what the earlier stages print is not read (bound rule)
			}
			continue
		}
		for _, producer := range stages[:at] {
			for _, body := range r.producedBodies(producer, values) {
				r.read(body, scope, depth+1)
			}
		}
	}
}

// producedBodies lists the program texts the commands of stage print as
// literals: echo, printf, and cat of a heredoc.
func (r *sedBackupReader) producedBodies(stage *syntax.Stmt, values actionValues) (bodies []string) {
	syntax.Walk(stage, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		producer, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(producer.Args) == 0 {
			return true
		}
		program, static := StaticWord(producer.Args[0], r.home)
		if !static {
			return true
		}
		args := make([]string, 0, len(producer.Args)-1)
		for _, arg := range producer.Args[1:] {
			args = append(args, sedWordText(arg, values, r.cwd, r.home))
		}
		switch programBase(program) {
		case "echo":
			for len(args) > 0 && len(args[0]) > 1 && args[0][0] == '-' && strings.Trim(args[0][1:], "neE") == "" {
				args = args[1:]
			}
			bodies = append(bodies, strings.Join(args, " "))
		case "printf":
			if len(args) > 1 && strings.Contains(args[0], "%") {
				args = args[1:]
			}
			bodies = append(bodies, strings.Join(args, "\n"))
		case "cat":
			if len(args) == 0 {
				bodies = append(bodies, sedRedirectBodies(stmt, values, r.cwd, r.home)...)
			}
		}
		return true
	})
	return bodies
}

// actionShellCommandBody returns the -c body of a POSIX shell call (bash -c
// BODY, sh -ec BODY), skipping the options that take a value.
func actionShellCommandBody(words []string) (string, bool) {
	for j := 1; j+1 < len(words); j++ {
		option := words[j]
		if !strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "+") {
			return "", false
		}
		switch option {
		case "-o", "+o", "-O", "+O", "--rcfile", "--init-file":
			j++ // This option consumes the next word (bash -O dotglob -c).
			continue
		}
		if option == "-c" || len(option) > 2 && !strings.HasPrefix(option, "--") &&
			!strings.ContainsAny(option, "=/") && strings.Contains(option[1:], "c") {
			return words[j+1], true
		}
	}
	return "", false
}

// actionUnescapeShell removes the backslash of each escaped character of an
// unquoted shell word text.
func actionUnescapeShell(word string) string {
	var out strings.Builder
	for i := 0; i < len(word); i++ {
		if word[i] == '\\' && i+1 < len(word) {
			i++
		}
		out.WriteByte(word[i])
	}
	return out.String()
}
