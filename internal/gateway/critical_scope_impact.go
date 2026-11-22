// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// rel-1-0-10:GAP-0594. A rule that blocks the delete of the filesystem root,
// a system folder or the home matches the whole scope it protects, not one
// spelling of it:
//
//   - the contents of a critical folder or of the home (`rm -rf /etc/*`,
//     `rm -rf ~/*`, `rm -rf "$HOME"/.[!.]*`) and the direct children of the
//     system payload folders (/usr/lib, /boot/grub) are critical scope as
//     much as the folder is;
//   - an unrestricted `find <critical> -delete` and a recursive chmod that
//     locks the owner out of (or opens to everyone) a critical scope are the
//     same destruction by another program;
//   - the shell expands a glob after the hook reads it, so the facts keep only
//     its spelling and the parse is partial; the directory part and the
//     match-everything last component are static, so the target is proven
//     from the words (the same reading globbedStateMutation uses for the
//     state), and the call no longer depends on a complete parse;
//   - the rules that are alert-only or detection-only by design because a
//     recursive chmod or a fork bomb may be authorized administration or a
//     drill (CMD-CHMOD-WORLD, impact.fork_bomb) alert in the default and
//     permissive packs and block in strict and managed, where the target is
//     proven. CMD-MKFS and CMD-DEVICE-WIPE stay detection-only in every
//     pack (the 1.0.10 lead's ruling: a format may be provisioning).

// criticalPayloadParents are the system payload folders whose direct
// children (/usr/lib, /usr/bin, /boot/grub) are critical delete scope.
var criticalPayloadParents = []string{"/bin", "/boot", "/lib", "/lib64", "/sbin", "/usr"}

// nonPayloadChildren are children of a payload folder that hold locally
// installed or source files an administrator or a developer removes on
// purpose (/usr/local, /usr/src, /usr/include); they keep rel's verdict
// (rel-1-0-10:GAP-0695, lead ruling).
var nonPayloadChildren = []string{"/usr/include", "/usr/local", "/usr/src"}

// criticalDeleteScope reports whether removing value (a canonical, lower
// case slash path) removes a host or an account: the filesystem or a drive
// root, a top-level system folder, the active home, or a direct child of a
// system payload folder. home is the canonical active home, "" when unknown.
func criticalDeleteScope(value, home string) bool {
	if value == "/" || windowsDriveRoot(value) {
		return true
	}
	trimmed := strings.TrimRight(value, "/")
	switch trimmed {
	case "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
		"/mnt", "/opt", "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var",
		"/applications", "/library", "/system", "/users",
		"c:/program files", "c:/program files (x86)", "c:/programdata",
		"c:/users", "c:/windows":
		return true
	}
	if home != "" && trimmed == home {
		return true
	}
	// Another account's home is not judged: removing it is the ordinary
	// offboarding of an account (userdel -r, dscl -delete) and owner traces
	// carry it as benign. Only the active home is critical.
	return strings.HasPrefix(trimmed, "/") &&
		slices.Contains(criticalPayloadParents, path.Dir(trimmed)) &&
		!slices.Contains(nonPayloadChildren, trimmed)
}

// forkBombProof is forkBombFallbackProof for a call whose command text is in
// the tool arguments (a Bash hook call) as well as in Input.Command.
//
// The bomb is also proven when it is the last statement of a script (`echo
// x; :(){ :|:& };:`) and when a shell -c script of a top-level command, behind
// a transparent wrapper or not, is the bomb or ends with it (rel-1-0-10:
// GAP-0696). The scan allocates nothing and stops at the first byte that
// cannot be part of the bomb.
func forkBombProof(input actionfacts.Input, facts actionfacts.Facts) bool {
	if command, known := trustedBashCommandInput(input); known && endsWithForkBomb(command) {
		return true
	}
	if forkBombFallbackProof(input, facts) {
		return true
	}
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 || command.Dialect != actionfacts.DialectPOSIX {
			continue
		}
		words, ok := stateOperandWords(command)
		if !ok {
			continue
		}
		inner, innerWords := unwrapStateWrapper(command, words)
		if !shellProgram(inner.Program) {
			continue
		}
		for index, word := range innerWords {
			if index+1 < len(innerWords) && shellCommandOption(word) && endsWithForkBomb(innerWords[index+1]) {
				return true
			}
		}
	}
	return false
}

// shellCommandOption reports a shell option word that takes the script as
// its next word: -c, or a cluster of single-letter options that ends in c.
func shellCommandOption(word string) bool {
	return len(word) >= 2 && word[0] == '-' && word[1] != '-' &&
		strings.HasSuffix(word, "c") && strings.Trim(word[1:], "abefhikmnptuvxBCHPcl") == ""
}

// forkBombText is the canonical fork bomb with every blank removed.
const forkBombText = ":(){:|:&};:"

// matchesForkBomb reports whether text is the fork bomb, blanks aside.
func matchesForkBomb(text string) bool {
	matched := 0
	for index := 0; index < len(text); index++ {
		switch character := text[index]; character {
		case ' ', '\t', '\r', '\n':
		default:
			if matched >= len(forkBombText) || character != forkBombText[matched] {
				return false
			}
			matched++
		}
	}
	return matched == len(forkBombText)
}

// endsWithForkBomb reports a script whose last statement is the fork bomb:
// the whole text, or a tail that starts after a statement separator.
func endsWithForkBomb(text string) bool {
	if matchesForkBomb(text) {
		return true
	}
	for index := 0; index < len(text); index++ {
		switch text[index] {
		case ';', '&', '|', '\n', '(', '{':
		default:
			continue
		}
		next := index + 1
		for next < len(text) && (text[next] == ' ' || text[next] == '\t' || text[next] == '\r' || text[next] == '\n') {
			next++
		}
		// A tail can only be the bomb when it starts with its first byte.
		if next < len(text) && text[next] == ':' && matchesForkBomb(text[next:]) {
			return true
		}
		index = next - 1
	}
	return false
}

// matchesEveryEntry reports whether a glob's last component names every
// entry of a directory (or every dot entry): only wildcards, the dot and a
// negated dot class, with at least one `*`. `*`, `.*`, `.[!.]*`, `..?*`,
// `?*`; never a name with a literal letter (`*.log`, `build*`).
func matchesEveryEntry(name string) bool {
	if !strings.Contains(name, "*") {
		return false
	}
	for _, char := range name {
		if !strings.ContainsRune("*?[]!^.", char) {
			return false
		}
	}
	return true
}

func hasGlobMeta(word string) bool { return strings.ContainsAny(word, "*?[") }

// criticalDeleteWord reports whether a recursive delete of the word (a static
// operand: a path, a home spelling, or a glob whose last component matches
// every entry) removes a critical scope. A relative word is not judged here.
func criticalDeleteWord(word, home string) bool {
	word = strings.TrimSpace(strings.ReplaceAll(word, `\`, "/"))
	if word == "" {
		return false
	}
	lower := strings.ToLower(word)
	rest, homeSpelled := "", false
	switch {
	case lower == "~" || lower == "$home" || lower == "${home}":
		homeSpelled = true
	case strings.HasPrefix(lower, "~/"):
		rest, homeSpelled = lower[2:], true
	case strings.HasPrefix(lower, "$home/"):
		rest, homeSpelled = lower[6:], true
	case strings.HasPrefix(lower, "${home}/"):
		rest, homeSpelled = lower[8:], true
	}
	if homeSpelled {
		rest = path.Clean("/" + rest)[1:]
		switch {
		case rest == "":
			return true
		case !strings.Contains(rest, "/"):
			return matchesEveryEntry(rest)
		}
		return false
	}
	if !strings.HasPrefix(lower, "/") {
		return false
	}
	cleaned := path.Clean(lower)
	if hasGlobMeta(cleaned) {
		dir, last := path.Split(cleaned)
		if !matchesEveryEntry(last) || hasGlobMeta(dir) {
			return false
		}
		cleaned = path.Clean(dir)
	}
	return criticalDeleteScope(cleaned, home)
}

// criticalScopeHome is the canonical active home of the facts.
func criticalScopeHome(facts actionfacts.Facts) string {
	return strings.TrimRight(canonicalSemanticPath(facts.ActiveHome), "/")
}

// criticalWrappedChild reports a child fact that runs because of its parents
// only: a script of a shell -c or a command behind a transparent wrapper
// (sudo, env, nohup, ...), at any depth (rel-1-0-10:GAP-0694). A child of
// find -exec, xargs, ssh, a container run or another program stays out: the
// program it runs is not this host's shell.
func criticalWrappedChild(command actionfacts.CommandFact) bool {
	for _, wrapper := range command.Wrappers {
		base := strings.ToLower(path.Base(wrapper.Executable))
		if _, transparent := stateWrapperValueOptions[base]; !transparent && !shellProgram(base) {
			return false
		}
	}
	return true
}

// criticalScopeCommands calls visit with the program a top-level POSIX
// command, or a child of a shell -c or of a transparent wrapper, runs
// (through a transparent wrapper such as sudo) and its static operand words,
// for each command whose words are readable. A parse that is
// not complete (a glob, or any other word the parser could not read) is
// judged only on a command with no unreadable word beside the glob, and only
// the glob targets count: a root or a folder named next to an unrelated
// dynamic word stays at the unknown tier of the pack, as before.
//
// stdin is set when the words hold what xargs read from the stage before it
// (xargsStdinRun): no rule reads them from the argv, so a proof judges them
// itself.
func criticalScopeCommands(facts actionfacts.Facts, visit func(command actionfacts.CommandFact, program string, words []string, partial, stdin bool) bool) bool {
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 && !criticalWrappedChild(command) ||
			command.Effect == actionfacts.EffectPreview ||
			command.Dialect != actionfacts.DialectPOSIX {
			continue
		}
		// A command whose own argv is complete (an option the parser does
		// not model, such as `chmod -R -x /usr`, makes the call partial)
		// is read like a call that parsed in full.
		partial := !facts.Authoritative() && !command.ArgvComplete
		words, ok := stateOperandWords(command)
		if !ok || partial && slices.Contains(words, "") {
			continue
		}
		inner, innerWords := unwrapStateWrapper(command, words)
		stdin := false
		if strings.ToLower(path.Base(inner.Program)) == "xargs" {
			// xargs runs its program with the words it reads from stdin
			// (echo ~ | xargs rm -rf removes the home, rel-1-0-10:GAP-0762).
			// A wrapper xargs runs (xargs sudo rm -rf) runs its program with
			// those words too (rel-1-0-10:GAP-1247).
			if program, run, ok := xargsStdinRun(facts, command, innerWords); ok {
				inner.Program, stdin = program, true
				inner, innerWords = unwrapStateWrapper(inner, run)
			}
		}
		if visit(command, strings.ToLower(path.Base(inner.Program)), innerWords, partial, stdin) {
			return true
		}
	}
	return false
}

// xargsOperandOptions are the xargs options that leave the words it reads as
// operands of its program, each with whether it takes the next word. An
// option that changes how the input is split (-d, -a, -E, -e, -s) is not
// read; -0 and -I are read by xargsStdinRun.
var xargsOperandOptions = map[string]bool{
	"-r": false, "--no-run-if-empty": false, "-t": false, "--verbose": false, "-x": false, "--exit": false,
	"-n": true, "--max-args": true, "-L": true, "--max-lines": true, "-P": true, "--max-procs": true,
}

// xargsHome marks, in the text xargsStdinRun reads from the stage before
// xargs, a "~" the caller shell expanded to the home. A "~" the source
// quoted or escaped stays a "~": that stage prints a literal ~, which names
// ./~ for xargs's program (rel-1-0-10:GAP-1247). A shell word holds no
// such control byte, so the marker names nothing else.
const xargsHome = "\x1f"

// xargsStdinPrograms are the programs whose output xargs reads when their
// own words are static, from those words (each a "~" of the home written as
// xargsHome): echo prints its words, and printf prints a format of plain
// text, %s and the \n and \t escapes with its arguments.
var xargsStdinPrograms = map[string]func(words []string) (string, bool){
	"echo": func(words []string) (string, bool) {
		newline := "\n"
		for len(words) > 0 && (words[0] == "-n" || words[0] == "-e" || words[0] == "-E") {
			if words[0] == "-n" {
				newline = ""
			}
			words = words[1:]
		}
		return strings.Join(words, " ") + newline, true
	},
	"printf": func(words []string) (string, bool) {
		if len(words) == 0 {
			return "", false
		}
		format := strings.NewReplacer(`\n`, "\n", `\t`, "\t").Replace(words[0])
		parts := strings.Split(format, "%s")
		if strings.Contains(format, `\`) || strings.Count(format, "%") != len(parts)-1 {
			return "", false
		}
		args := words[1:]
		var out strings.Builder
		for {
			out.WriteString(parts[0])
			for _, part := range parts[1:] {
				if len(args) > 0 {
					out.WriteString(args[0])
					args = args[1:]
				}
				out.WriteString(part)
			}
			// printf reuses the format while arguments are left.
			if len(parts) == 1 || len(args) == 0 {
				return out.String(), true
			}
		}
	},
}

// xargsPrintedWords are the static words of command (stateOperandWords) with
// each "~" the shell expands to the home written as xargsHome: a word the
// source quoted or escaped keeps its "~" as text.
func xargsPrintedWords(command actionfacts.CommandFact) ([]string, bool) {
	words, ok := stateOperandWords(command)
	if !ok || slices.Contains(words, "") || strings.Contains(strings.Join(words, ""), xargsHome) {
		return nil, false
	}
	for i, word := range words {
		if argument := command.Arguments[i+1]; argument.Value == "" && strings.HasPrefix(word, "~") {
			words[i] = xargsHome + word[1:]
		}
	}
	return words, true
}

// xargsInputWord is one item xargs read: a "~" the shell expanded to the
// home names the home again, and a literal "~" at its start names ./~.
func xargsInputWord(item string) string {
	if strings.HasPrefix(item, "~") {
		item = "./" + item
	}
	return strings.ReplaceAll(item, xargsHome, "~")
}

// xargsStdinRun returns the program an xargs call runs and its words, with
// the words the stage before it in the pipeline prints (xargsStdinPrograms)
// placed as xargs places them: appended after blanks split them, as one word
// with -0 (the input holds no NUL), or one call per line in place of the
// replace string with -I. ok is false when the xargs options or the stage
// before it are not read.
func xargsStdinRun(facts actionfacts.Facts, command actionfacts.CommandFact, words []string) (string, []string, bool) {
	index := 0
	null, replace := false, ""
	for index < len(words) && strings.HasPrefix(words[index], "-") {
		word := words[index]
		if word == "--" {
			index++
			break
		}
		switch {
		case word == "-0" || word == "--null":
			null = true
			index++
			continue
		case word == "-I":
			if index+1 >= len(words) || words[index+1] == "" {
				return "", nil, false
			}
			replace = words[index+1]
			index += 2
			continue
		case strings.HasPrefix(word, "-I"):
			replace = word[2:]
			index++
			continue
		case word == "-i" || word == "--replace":
			replace = "{}"
			index++
			continue
		case strings.HasPrefix(word, "-i") || strings.HasPrefix(word, "--replace="):
			replace = strings.TrimPrefix(strings.TrimPrefix(word, "--replace="), "-i")
			index++
			continue
		}
		name, _, attached := strings.Cut(word, "=")
		value, known := xargsOperandOptions[name]
		if !known && len(word) > 2 && !strings.HasPrefix(word, "--") {
			// -n1, -P4: the value attached to a short option that takes one.
			if takes := xargsOperandOptions[word[:2]]; takes {
				value, known, attached = true, true, true
			}
		}
		if !known {
			return "", nil, false
		}
		index++
		if value && !attached {
			index++
		}
	}
	if index >= len(words) || words[index] == "" || command.PipelineID == 0 {
		return "", nil, false
	}
	var before *actionfacts.CommandFact
	for i := range facts.Commands {
		other := &facts.Commands[i]
		if other.PipelineID == command.PipelineID && other.ParentCommandID == 0 && other.ID < command.ID &&
			(before == nil || other.ID > before.ID) {
			before = other
		}
	}
	if before == nil || !before.ArgvComplete {
		return "", nil, false
	}
	read, known := xargsStdinPrograms[strings.ToLower(path.Base(before.Program))]
	if !known {
		return "", nil, false
	}
	printed, ok := xargsPrintedWords(*before)
	if !ok {
		return "", nil, false
	}
	text, ok := read(printed)
	if !ok {
		return "", nil, false
	}
	program, initial := path.Base(words[index]), words[index+1:]
	var run []string
	items := 0
	switch {
	case replace != "":
		// -I reads one item per line, leading blanks dropped, and runs the
		// program once per item with the item in place of the replace
		// string; the words of every call are read together.
		for _, line := range strings.Split(text, "\n") {
			if item := strings.TrimLeft(line, " \t"); item != "" {
				items++
				for _, word := range initial {
					run = append(run, strings.ReplaceAll(word, replace, xargsInputWord(item)))
				}
			}
		}
	case null:
		run = append(slices.Clone(initial), xargsInputWord(text))
		if text != "" {
			items = 1
		}
	default:
		run = slices.Clone(initial)
		for _, item := range strings.Fields(text) {
			run = append(run, xargsInputWord(item))
			items++
		}
	}
	if items == 0 {
		return "", nil, false
	}
	return program, run, true
}

// criticalTarget reports a word that removes or locks a critical scope; in a
// partial parse only a glob target counts (criticalScopeCommands).
func criticalTarget(word, home string, partial bool) bool {
	return (!partial || hasGlobMeta(word)) && criticalDeleteWord(word, home)
}

// rmRecursiveOptions reads the options of an rm call: whether it recurses
// (-r, -R, --recursive), forces (-f, --force) and is interactive (-i, -I,
// --interactive).
func rmRecursiveOptions(words []string) (recursive, force, interactive bool) {
	for _, word := range words {
		if word == "--" {
			break
		}
		if len(word) < 2 || word[0] != '-' {
			continue
		}
		switch {
		case strings.HasPrefix(word, "--"):
			// GNU getopt takes any unambiguous prefix of a long option, so
			// --rec, --for and --int are --recursive, --force and
			// --interactive; every long option of rm that starts with r, f
			// or i is that one (rel-1-0-10:GAP-0743).
			name, when, hasWhen := strings.Cut(word[2:], "=")
			switch {
			case name == "":
			case !hasWhen && strings.HasPrefix("recursive", name):
				recursive = true
			case !hasWhen && strings.HasPrefix("force", name):
				force = true
			case !hasWhen && strings.HasPrefix("interactive", name):
				interactive = true
			case hasWhen && strings.HasPrefix("interactive", name):
				// --interactive=never (no, none) never asks, so it is the
				// removal itself; the last prompting option wins, as in rm
				// (rel-1-0-10:GAP-0743). argmatch takes a prefix of a WHEN
				// value, and every prefix of never, no and none is a "never".
				interactive = !rmNeverPrompts(when)
			}
		default:
			for _, flag := range word[1:] {
				recursive = recursive || flag == 'r' || flag == 'R'
				force = force || flag == 'f'
				interactive = interactive || flag == 'i' || flag == 'I'
			}
		}
	}
	return recursive, force, interactive
}

// rmNeverPrompts reports a WHEN value of rm --interactive=WHEN that never
// asks before a removal: never, no, none or a prefix of them (coreutils
// argmatch, which accepts a prefix whose matches share one meaning).
func rmNeverPrompts(when string) bool {
	return when != "" && when[0] == 'n' &&
		(strings.HasPrefix("never", when) || strings.HasPrefix("none", when))
}

// stdinAnswersYesPrograms are the programs whose output answers every prompt
// of an interactive rm with yes: yes with no word, or with a word that
// starts with y or Y.
var stdinAnswersYesPrograms = map[string]func(args []string) bool{
	"yes": func(args []string) bool {
		return len(args) == 0 || strings.HasPrefix(strings.ToLower(args[0]), "y")
	},
}

// stdinAnswersYes reports a command whose pipeline starts with a program of
// stdinAnswersYesPrograms before it (yes | rm -ri ~): every question an
// interactive rm asks is answered yes, so it removes what rm -r removes
// (rel-1-0-10:GAP-0743).
func stdinAnswersYes(facts actionfacts.Facts, command actionfacts.CommandFact) bool {
	if command.PipelineID == 0 {
		return false
	}
	for _, other := range facts.Commands {
		if other.PipelineID != command.PipelineID || other.ID >= command.ID || len(other.Argv) == 0 {
			continue
		}
		if answers, ok := stdinAnswersYesPrograms[strings.ToLower(path.Base(other.Program))]; ok && answers(other.Argv[1:]) {
			return true
		}
	}
	return false
}

// criticalDeleteProof proves a recursive `rm` of a critical scope from the
// words of the call: the shell expands a glob after the hook reads it, so the
// parse is partial, but the directory part and the match-everything last
// component are static. A recursive delete that does not force (`rm -r ~`)
// is the same removal unless it asks first (-i, -I, with no -f after it)
// and nothing answers yes for it (stdinAnswersYes). A complete parse with -f is judged by the CMD-RM-RF owner itself.
func criticalDeleteProof(_ actionfacts.Input, facts actionfacts.Facts) bool {
	home := criticalScopeHome(facts)
	return criticalScopeCommands(facts, func(command actionfacts.CommandFact, program string, words []string, partial, stdin bool) bool {
		recursive, force, interactive := rmRecursiveOptions(words)
		if program != "rm" || !recursive || interactive && !force && !stdinAnswersYes(facts, command) ||
			force && facts.Authoritative() && !stdin {
			return false
		}
		options := true
		for _, word := range words {
			switch {
			case options && word == "--":
				options = false
			case options && strings.HasPrefix(word, "-") && word != "-":
			case criticalTarget(word, home, partial):
				return true
			}
		}
		return false
	})
}

// unrestrictedFindDelete reports a `find ... -delete` whose expression has
// no test (name, type, time, owner, path...) that narrows what it removes:
// only traversal options and -delete.
func unrestrictedFindDelete(command actionfacts.CommandFact) bool {
	if !oneOfFold(command.Program, "find") {
		return false
	}
	argv := command.Argv
	index := 1
	for index < len(argv) && (argv[index] == "-H" || argv[index] == "-L" || argv[index] == "-P") {
		index++
	}
	for index < len(argv) && !strings.HasPrefix(argv[index], "-") &&
		argv[index] != "(" && argv[index] != "!" {
		index++
	}
	deletes := false
	for ; index < len(argv); index++ {
		switch argv[index] {
		case "-delete":
			deletes = true
		case "-depth", "-xdev", "-mount", "-ignore_readdir_race", "-noignore_readdir_race":
		case "-mindepth", "-maxdepth":
			index++
		default:
			return false
		}
	}
	return deletes
}

// chmodLocksOut reports a mode that, applied recursively, makes the tree
// unusable: it takes an owner permission away (a directory loses search, a
// file its read or write) or opens it to every user for writing.
func chmodLocksOut(mode string) bool {
	if parsed, err := strconv.ParseUint(mode, 8, 16); err == nil {
		if len(mode) > 4 {
			return false
		}
		return parsed&0700 != 0700 || parsed&0002 != 0
	}
	for _, clause := range strings.Split(strings.ToLower(mode), ",") {
		operator := strings.IndexAny(clause, "+-=")
		if operator < 0 {
			return false
		}
		who, permissions := clause[:operator], clause[operator+1:]
		if strings.Trim(who, "ugoa") != "" || strings.Trim(permissions, "rwxXst") != "" {
			return false
		}
		owner := who == "" || strings.ContainsAny(who, "ua")
		public := who == "" || strings.ContainsAny(who, "oa")
		op := clause[operator]
		if owner && op == '-' && strings.ContainsAny(permissions, "rwx") {
			return true
		}
		if owner && op == '=' && (!strings.Contains(permissions, "r") ||
			!strings.Contains(permissions, "w") || !strings.Contains(permissions, "x")) {
			return true
		}
		if public && op != '-' && strings.Contains(permissions, "w") {
			return true
		}
	}
	return false
}

// criticalRecursiveLockoutProof proves a recursive chmod of a critical scope
// to a mode that locks it out or opens it for writing.
func criticalRecursiveLockoutProof(_ actionfacts.Input, facts actionfacts.Facts) bool {
	home := criticalScopeHome(facts)
	return criticalScopeCommands(facts, func(_ actionfacts.CommandFact, program string, words []string, partial, _ bool) bool {
		if program != "chmod" {
			return false
		}
		recursive, options, mode := false, true, ""
		var targets []string
		for _, word := range words {
			switch {
			case options && word == "--":
				options = false
			case options && (word == "--recursive"):
				recursive = true
			case options && strings.HasPrefix(word, "--"):
				if strings.HasPrefix(word, "--reference") {
					return false
				}
			case options && len(word) > 1 && word[0] == '-' && strings.Trim(word[1:], "RfvcHLPh") == "":
				recursive = recursive || strings.Contains(word, "R")
			case mode == "":
				mode = word
			default:
				targets = append(targets, word)
			}
		}
		if !recursive || mode == "" || !chmodLocksOut(mode) {
			return false
		}
		return slices.ContainsFunc(targets, func(target string) bool {
			return criticalTarget(target, home, partial)
		})
	})
}

// provenScopeRule is a rule whose scope this lane proves from the words of
// the call. tiered rules are the ones that are alert-only by design outside
// strict and managed (see withProvenScopeFindings).
type provenScopeRule struct {
	ruleID string
	proves func(actionfacts.Input, actionfacts.Facts) bool
	tiered bool
}

var provenScopeRules = []provenScopeRule{
	{ruleID: "CMD-RM-RF", proves: criticalDeleteProof},
	{ruleID: "CMD-CHMOD-WORLD", proves: criticalRecursiveLockoutProof, tiered: true},
	{ruleID: "impact.fork_bomb", proves: forkBombProof, tiered: true},
}

// withProvenScopeFindings adds the findings of provenScopeRules the pack
// carries and the call proves, and grades the tiered ones: an alert outside
// strict and managed, enforceable in them (rel-1-0-10:GAP-0594).
func withProvenScopeFindings(
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
	findings []RuleFinding,
) []RuleFinding {
	findings = slices.Clone(findings)
	grade := func(finding *RuleFinding, tiered bool) {
		if !request.EnforcementCapable {
			finding.Proof = finding.Proof.Record()
			return
		}
		finding.proof = newActionFactsSubgraphFindingProof(finding.RuleID, true, true)
		switch {
		case !tiered:
			finding.Proof = finding.Proof.Enforce()
		default:
			finding.Proof = request.tieredProof(finding.Proof, tierGateManaged)
		}
		if tiered && guardrailSeverityRank(finding.Severity) < guardrailSeverityRank("CRITICAL") {
			finding.Severity = "CRITICAL"
		}
	}
	for _, rule := range provenScopeRules {
		if !rule.proves(request.Input, facts) {
			continue
		}
		index := slices.IndexFunc(findings, func(f RuleFinding) bool {
			return canonicalTrustedRuleID(f.RuleID) == canonicalTrustedRuleID(rule.ruleID)
		})
		if index >= 0 {
			if findings[index].disposition != findingDispositionUnspecified {
				continue
			}
			grade(&findings[index], rule.tiered)
			continue
		}
		_, catalog, ok := trustedActionCatalogRule(generation, rule.ruleID)
		if !ok {
			continue
		}
		finding := RuleFinding{
			RuleID: catalog.ID, Title: catalog.Title, Severity: catalog.Severity,
			Confidence: catalog.Confidence, Tags: append([]string(nil), catalog.Tags...),
			Evidence: trustedActionInputText(request.Input, ""), LineNumber: 1,
		}
		grade(&finding, rule.tiered)
		findings = append(findings, adjustConfidence(request.Input.Tool, finding))
	}
	return findings
}
