// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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
// command: the edited file and the backup its suffix names (sedInPlaceWrites
// and perlInPlace hold the name rules of GNU sed, BSD sed and perl). A path
// the words name in full that reaches a protected file is a block.
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
	blocked, _ := actionSedInPlaceReading(command, cwd, home, memo)
	return blocked
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
	blocked, unresolved := actionSedInPlaceReading(command, cwd, home, m)
	return unresolved && !blocked
}

func actionSedInPlaceReading(command, cwd, home string, memo *TargetMemo) (blocked, unresolved bool) {
	if command == "" || home == "" || len(command) > MaxPayloadBytes || !filepath.IsAbs(cwd) || actionWindowsHome(home) {
		return false, false // an in-place editor is a POSIX path; a Windows home has its own readers
	}
	if !strings.Contains(command, "sed") && !strings.Contains(command, "perl") {
		return false, false
	}
	reader := &sedBackupReader{cwd: cwd, home: home, protected: memo.protectedFiles(home),
		ssh: filepath.Join(home, ".ssh"), memo: memo}
	reader.read(command, sedBackupScope{dirs: []string{cwd}}, 0)
	return reader.blocked, reader.unresolved
}

type sedBackupReader struct {
	cwd, home           string
	protected           protectedFiles
	ssh                 string
	memo                *TargetMemo
	blocked, unresolved bool
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
	file, parsed := parseShell(command)
	if !parsed {
		return
	}
	values := actionValues{"HOME": r.home, "PWD": r.cwd}
	scope.dirs = slices.Clone(scope.dirs)
	syntax.Walk(file, func(node syntax.Node) bool {
		if r.blocked {
			return false
		}
		switch typed := node.(type) {
		case *syntax.Stmt:
			r.stdinBody(typed, values, scope, depth)
		case *syntax.BinaryCmd:
			if typed.Op == syntax.Pipe || typed.Op == syntax.PipeAll {
				r.pipedBody(typed, values, scope, depth)
			}
		case *syntax.CallExpr:
			if len(typed.Args) > 0 {
				words := make([]string, len(typed.Args))
				for i, arg := range typed.Args {
					words[i], _ = sedHoledWord(arg, values, r.cwd, r.home)
				}
				r.call(words, &scope, depth)
			}
		}
		return !r.blocked
	})
}

// call reads one simple command; a cd changes the scope of the later calls.
func (r *sedBackupReader) call(words []string, scope *sedBackupScope, depth int) {
	if strings.Contains(words[0], sedHole) {
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
		return
	}
	switch program := programBase(words[0]); {
	case program == "sed" || program == "gsed":
		r.sed(words, scope, implicit)
	case program == "perl":
		if files, suffix, ok := perlInPlace(words); ok {
			r.inPlace(sedPerlKind, files, suffix, false, scope, implicit)
		}
	case program == "xargs":
		if child, replace := sedXargsChild(words); len(child) > 0 {
			if replace != "" {
				r.run(sedReplaceWords(child, replace), scope, false, depth)
			} else {
				r.run(child, scope, true, depth)
			}
		}
	case program == "find":
		for _, exec := range sedFindExecs(words) {
			inner := scope
			inner.unknown = inner.unknown || exec.dirUnknown
			r.run(exec.child, inner, false, depth)
		}
	case program == "eval" && depth < sedBackupDepth && len(words) > 1:
		r.read(strings.Join(words[1:], " "), scope, depth+1)
	case posixShellProgram(program) && depth < sedBackupDepth:
		if body, ok := actionShellCommandBody(words); ok {
			r.read(body, scope, depth+1)
		}
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
	// An escaped character (\*) is the character itself to the shell; the
	// word text keeps the backslash, so both spellings are judged.
	variants := [][]string{words}
	if slices.ContainsFunc(words, func(word string) bool { return strings.Contains(word, `\`) }) {
		plain := make([]string, len(words))
		for i, word := range words {
			plain[i] = actionUnescapeShell(word)
		}
		variants = append(variants, plain)
	}
	follow := sedFollowsInPlaceLinks(words)
	for _, variant := range variants {
		if files, suffix, ok := sedGNUInPlace(variant); ok {
			r.inPlace(sedGNUKind, files, suffix, follow, scope, implicit)
		}
		if files, suffix, ok := sedBSDInPlace(variant); ok {
			r.inPlace(sedBSDKind, files, suffix, false, scope, implicit)
		}
	}
}

// inPlace judges the paths an in-place call of the given reading writes.
func (r *sedBackupReader) inPlace(kind sedKind, files []string, suffix string, follow bool, scope sedBackupScope, implicit bool) {
	if implicit {
		files = append(slices.Clone(files), sedHole)
	}
	suffixHole := strings.Contains(suffix, sedHole)
	star := kind != sedBSDKind && !suffixHole && strings.Contains(suffix, "*")
	for _, file := range files {
		if file == "" || r.blocked {
			continue
		}
		fileHole := strings.Contains(file, sedHole)
		var names []string
		if !fileHole {
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
		if protectedReachPathWith(OperandPath(name, dir), r.protected, r.ssh, r.memo) {
			r.blocked = true
			return
		}
	}
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

// sedHoledWord is the text of a command word with each part the shell
// expands at run time replaced by sedHole; static reports a word with none.
func sedHoledWord(word *syntax.Word, values actionValues, cwd, home string) (text string, static bool) {
	if value, ok := actionWordValueWithGlob(word, values, cwd, home, true); ok {
		return value, true
	}
	var out strings.Builder
	var parts func([]syntax.WordPart)
	parts = func(items []syntax.WordPart) {
		for _, item := range items {
			if quoted, ok := item.(*syntax.DblQuoted); ok {
				parts(quoted.Parts)
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

// sedXargsChild is the command xargs runs and its replacement string (-I,
// -i, --replace): without one, xargs appends the operands it reads.
func sedXargsChild(words []string) (child []string, replace string) {
	for i := 1; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "--":
			return words[i+1:], replace
		case !strings.HasPrefix(word, "-") || word == "-":
			return words[i:], replace
		case word == "-I":
			if i+1 < len(words) {
				replace = words[i+1]
			}
			i++
		case strings.HasPrefix(word, "-I"):
			replace = word[2:]
		case word == "-i" || word == "--replace":
			replace = "{}"
		case strings.HasPrefix(word, "-i"), strings.HasPrefix(word, "--replace="):
			_, value, _ := strings.Cut(word, "=")
			if value == "" {
				value = word[2:]
			}
			replace = value
		case slices.Contains([]string{"-a", "-d", "-E", "-L", "-n", "-P", "-s"}, word):
			i++
		}
	}
	return nil, replace
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

// readsShellStdin reports a POSIX shell call that reads its program from
// standard input: no -c body and no script operand.
func (r *sedBackupReader) readsShellStdin(call *syntax.CallExpr, values actionValues) bool {
	words := make([]string, len(call.Args))
	for i, arg := range call.Args {
		words[i], _ = sedHoledWord(arg, values, r.cwd, r.home)
	}
	words, _ = r.unwrap(words, sedBackupScope{})
	if len(words) == 0 || strings.Contains(words[0], sedHole) || !posixShellProgram(programBase(words[0])) {
		return false
	}
	if _, body := actionShellCommandBody(words); body {
		return false
	}
	_, script := shellScriptOperand(words)
	return !script
}

// stdinBody reads the program a shell takes from a heredoc or a herestring.
func (r *sedBackupReader) stdinBody(stmt *syntax.Stmt, values actionValues, scope sedBackupScope, depth int) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 || len(stmt.Redirs) == 0 || depth >= sedBackupDepth || !r.readsShellStdin(call, values) {
		return
	}
	for _, text := range sedRedirectBodies(stmt, values, r.cwd, r.home) {
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

// pipedBody reads the program a literal piped into a shell: echo, printf or
// a cat of a heredoc.
func (r *sedBackupReader) pipedBody(pipe *syntax.BinaryCmd, values actionValues, scope sedBackupScope, depth int) {
	if pipe.X == nil || pipe.Y == nil || depth >= sedBackupDepth {
		return
	}
	reader, ok := pipe.Y.Cmd.(*syntax.CallExpr)
	if !ok || len(reader.Args) == 0 || !r.readsShellStdin(reader, values) {
		return
	}
	producer, ok := pipe.X.Cmd.(*syntax.CallExpr)
	if !ok || len(producer.Args) == 0 {
		return
	}
	program, static := StaticWord(producer.Args[0], r.home)
	if !static {
		return
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
		r.read(strings.Join(args, " "), scope, depth+1)
	case "printf":
		if len(args) > 1 && strings.Contains(args[0], "%") {
			args = args[1:]
		}
		r.read(strings.Join(args, "\n"), scope, depth+1)
	case "cat":
		if len(args) == 0 {
			for _, text := range sedRedirectBodies(pipe.X, values, r.cwd, r.home) {
				r.read(text, scope, depth+1)
			}
		}
	}
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
