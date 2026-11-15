// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// The launcher screen of a call past the input bound (hostLauncherMention)
// reads the command text the way the shell does, with the layout reader the
// over-limit command reading already uses: its quotes (single, double, ANSI-C,
// a quote split inside a word), comments, redirections, assignments,
// substitutions and statement ends are the shell's, not a count of quote
// characters. A statement names a launcher when the command it runs is
// powershell, pwsh or cmd: the first word, or the word a wrapper (sudo, env,
// nohup, timeout, xargs, start, wsl ...) runs after its options and their
// operands, or the script a local shell -c, eval or a backtick runs, read as
// a command text of its own. The quoted argument of any other command (an
// ssh remote command, a message, a script argument) is that command's data
// and names nothing (rel-1-0-10:GAP-0608, GAP-0740).

// maxLauncherScriptDepth bounds how many shell -c, eval and backtick scripts
// deep the screen reads; a text nested deeper counts as naming a launcher
// (the one bound rule: an unread part is at least the unknown tier).
const maxLauncherScriptDepth = 4

// hostLauncherStatements reports a command text one of whose statements runs
// a launcher. A carriage return ends a statement as a line break does (the
// Windows shells read it so).
func hostLauncherStatements(text string, depth int) bool {
	if depth > maxLauncherScriptDepth {
		return true
	}
	if strings.IndexByte(text, '\r') >= 0 {
		text = strings.ReplaceAll(text, "\r", "\n")
	}
	found := false
	_, readable := readLayoutVisit(text, 0, func(source string, words []layoutWord) {
		if !found && launcherStatement(source, words, depth) {
			found = true
		}
	})
	// A text the reading cannot follow (an unterminated quote, a process
	// substitution, an arithmetic bracket) hides its quote structure: a
	// launcher at a command position anywhere in it counts, quoted or not
	// (the one bound rule: an unproven reading is at least the unknown tier).
	return found || !readable && hostLauncherAtCommand.MatchString(text)
}

// hostLauncherArgv reports an argv, or the words of a JSON array command,
// whose command runs a launcher: the same reading as one statement of a text.
func hostLauncherArgv(argv []string, depth int) bool {
	words := make([]layoutWord, len(argv))
	for index, word := range argv {
		words[index] = layoutWord{literal: word, plain: true, assign: assignmentNameAt(word, 0) != ""}
	}
	return launcherStatement("", words, depth)
}

// launcherStatement reads one statement: the backticks in its words are
// command texts of their own, and the command it runs is read from its first
// word that is no assignment and no leading reserved word (if, then, do, !, {).
func launcherStatement(source string, words []layoutWord, depth int) bool {
	for _, word := range words {
		for _, span := range word.code {
			if span.end-span.start >= 2 && source[span.start] == shellBacktick && source[span.end-1] == shellBacktick &&
				hostLauncherStatements(source[span.start+1:span.end-1], depth+1) {
				return true
			}
		}
	}
	first := 0
	for first < len(words) && (words[first].assign || words[first].plain && layoutReserved[words[first].literal]) {
		first++
		if words[first-1].plain && words[first-1].literal == "time" {
			// The time keyword's own options (time -p, time --) are no
			// command (rel-1-0-10:GAP-0970).
			for first < len(words) && words[first].plain && (words[first].literal == "-p" || words[first].literal == "--") {
				first++
			}
		}
	}
	return launcherCommand(source, words, first, depth)
}

// launcherCommand reads the command at words[first]. An ordinary command's
// words are its arguments and name nothing. A wrapper runs the first word
// after its options: the words between are flags, assignments, durations,
// empty words, a start title and the operand a flag takes; a word that follows
// a flag is read as that operand and as the command both, since the flag's
// arity is the wrapper's.
//
// cmd's start takes its first quoted word as the window title: in an argv,
// which carries no quotes, the first word after start's switches may be the
// title too (launcherStarts reads it both ways, rel-1-0-10:GAP-0857).
func launcherCommand(source string, words []layoutWord, first, depth int) bool {
	wrapped, afterFlag, wrapper, titled := false, false, "", false
	for index := first; index < len(words); index++ {
		word := words[index]
		if launcherWord(source, word) {
			return true
		}
		name := commandBase(word.literal)
		if layoutShells[name] && shellScriptLauncher(words[index+1:], depth) {
			return true
		}
		if name == "eval" && evalLauncher(words[index+1:], depth) {
			return true
		}
		switch {
		case launcherWrapper(name):
			if (name == "command" || name == "builtin") && queryOnlyCommand(words[index+1:]) {
				return false
			}
			wrapped, afterFlag, wrapper, titled = true, false, name, false
		case !wrapped:
			return false
		case launcherPrefix(word, wrapper):
			if wrapper == "start" && (word.literal == "" || word.quoted) {
				titled = true
			}
			afterFlag = launcherFlag(word)
		case afterFlag:
			// env -S takes a command text as its operand.
			if word.quoted && strings.ContainsAny(word.literal, " \t") && hostLauncherStatements(word.literal, depth+1) {
				return true
			}
			afterFlag = false
		case wrapper == "start" && !titled:
			titled = true
		default:
			return false
		}
	}
	return false
}

// launcherWord reports a word that is a powershell, pwsh or cmd program by
// its last path element, as its quotes make it and as it is written (an
// unquoted backslash is a path separator to the Windows shells, an escape to
// the layout reading, which drops it).
func launcherWord(source string, word layoutWord) bool {
	if hostLauncherWord(word.literal) {
		return true
	}
	if word.start >= word.end || word.end > len(source) {
		return false
	}
	raw := source[word.start:word.end]
	if !strings.Contains(raw, `\`) {
		return false
	}
	return hostLauncherWord(strings.NewReplacer(`"`, "", `'`, "", "`", "").Replace(raw))
}

// commandBase is the lower-case last path element of a command word without
// a .exe suffix.
func commandBase(word string) string {
	base := strings.ToLower(word[strings.LastIndexAny(word, `/\`)+1:])
	return strings.TrimSuffix(base, ".exe")
}

// launcherWrapper reports a command that runs the command it is given on
// this machine. ssh runs it on another one: its argument is no local launcher.
// Every pass-through wrapper the analysis unwraps (staticPOSIXWrapperPrograms:
// time and nsenter as well as env, sudo, nice, timeout, nohup ...) is one, so
// the launcher reader and the screen read through every wrapper the analysis
// reads through; a wrapper missing here hid the launcher behind it while the
// analysis read the chain whole (rel-1-0-10:GAP-0970).
func launcherWrapper(name string) bool {
	switch name {
	case "ssh":
		return false
	case "start", "wsl":
		return true
	}
	if _, ok := staticPOSIXWrapperPrograms[name]; ok {
		return true
	}
	return layoutWrappers[name]
}

// queryOnlyCommand reports command -v and -V, which only print.
func queryOnlyCommand(rest []layoutWord) bool {
	return len(rest) != 0 && layoutOptions(rest[0].literal) && strings.ContainsAny(rest[0].literal, "vV")
}

// launcherFlag reports an option word (-x, --name, -n=1), not the -- that ends
// the options.
func launcherFlag(word layoutWord) bool {
	return len(word.literal) >= 2 && word.literal[0] == '-' && word.literal != "--" && !strings.Contains(word.literal, "=")
}

// launcherPrefix reports a word between a wrapper and the command it runs.
func launcherPrefix(word layoutWord, wrapper string) bool {
	literal := word.literal
	switch {
	case word.assign, literal == "", literal == "--", launcherFlag(word), strings.HasPrefix(literal, "-") && strings.Contains(literal, "="):
		return true
	case wrapper == "start" && word.quoted:
		return true
	case launcherDuration(literal), launcherSwitch(literal):
		return true
	}
	return false
}

// launcherDuration reports a number with an optional s, m, h or d suffix.
func launcherDuration(word string) bool {
	if word != "" && strings.IndexByte("smhd", word[len(word)-1]) >= 0 {
		word = word[:len(word)-1]
	}
	return word != "" && strings.Trim(word, "0123456789.") == ""
}

// launcherSwitch reports a Windows switch (/wait, /min, /d).
func launcherSwitch(word string) bool {
	return len(word) >= 2 && len(word) <= 12 && word[0] == '/' && strings.Trim(word[1:], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:") == ""
}

// shellScriptLauncher reads the script a local shell is given with -c (alone
// or in a group of options such as -lc): the word after the first such option,
// as a command text of its own.
func shellScriptLauncher(rest []layoutWord, depth int) bool {
	for index, word := range rest {
		literal := word.literal
		if len(literal) >= 2 && literal[0] == '-' && literal[1] != '-' && strings.IndexByte(literal, 'c') > 0 {
			return index+1 < len(rest) && hostLauncherStatements(rest[index+1].literal, depth+1)
		}
	}
	return false
}

// evalLauncher reads the words eval joins as a command text of their own.
func evalLauncher(rest []layoutWord, depth int) bool {
	if len(rest) == 0 {
		return false
	}
	words := make([]string, len(rest))
	for index, word := range rest {
		words[index] = word.literal
	}
	return hostLauncherStatements(strings.Join(words, " "), depth+1)
}
