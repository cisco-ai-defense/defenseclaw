// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"maps"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// ActionStateTargetMention applies the same independent target scan to the
// active DefenseClaw security state, without attributing it to SSH keys.
func ActionStateTargetMention(command, cwd, home string) bool {
	return (*TargetMemo)(nil).ActionStateTargetMention(command, cwd, home)
}

// ActionStateTargetMention is the package function of that name, with the
// file system answers of the evaluation m (nil: none).
func (m *TargetMemo) ActionStateTargetMention(command, cwd, home string) bool {
	return actionProtectedTargetMentionIn(command, cwd, home, 0, true, nil, "", m)
}

// actionProtectedTargetMentionDepth is independent of a program's operand
// roles. A resolved protected path in a writable command is enough for the
// action decision; commands with no such path continue through the existing
// proof. globs carries the hook client's pattern answers (actionGlobs).
func actionProtectedTargetMentionDepth(command, cwd, home string, depth int, stateOnly bool, globs *actionGlobs) bool {
	return actionProtectedTargetMentionIn(command, cwd, home, depth, stateOnly, globs, "", nil)
}

// actionProtectedTargetMentionIn is actionProtectedTargetMentionDepth with
// the gateway's shell dialect hint (actionWindowsTargetMention).
func actionProtectedTargetMentionIn(command, cwd, home string, depth int, stateOnly bool, globs *actionGlobs, dialect actionfacts.Dialect, memo *TargetMemo) bool {
	if command == "" || home == "" || len(command) > MaxPayloadBytes || depth >= 8 {
		return false
	}
	if depth == 0 {
		globs = globs.forCommand(command)
	}
	if memo == nil {
		// A nested body's scan carries the memo of the call it is in.
		memo = globs.targetMemo()
	}
	if memo == nil {
		memo = NewTargetMemo()
	}
	if depth == 0 {
		// globs is this call's own scan state (forCommand).
		globs.memo = memo
	}
	if actionWindowsHome(home) {
		return actionWindowsTargetMention(command, cwd, home, depth, stateOnly, dialect, memo)
	}
	return actionPosixTargetMention(command, cwd, home, depth, stateOnly, globs)
}

// actionPosixTargetMention is the POSIX-grammar target scan. On a native
// Windows host it also reads a POSIX shell's command (Git Bash, MSYS) under
// a Windows home, on the Windows file system (ActionCommandDecisionWithDialectAndGlobFacts).
func actionPosixTargetMention(command, cwd, home string, depth int, stateOnly bool, globs *actionGlobs) bool {
	// spelledWindows: a Windows home this host cannot open (the gateway is
	// not on Windows). Its paths are judged by their spelling
	// (actionWindowsPath), as the Windows reading judges them (GAP-1504).
	spelledWindows := runtime.GOOS != "windows" && actionWindowsHome(home)
	if !spelledWindows && !filepath.IsAbs(cwd) && (!actionPosixWindowsHome(home) || !path.IsAbs(cwd)) {
		return false
	}
	file, parsed := parseShell(command)
	if depth == 0 && parsed && (actionKnownReadOnlyShell(file, home) ||
		!stateOnly && (actionSSHSetupAndReadsOnly(file, cwd, home) ||
			strings.Contains(command, "pwd") && actionReadOnlyListingCompound(file, cwd, home))) {
		return false
	}
	// A function the command never calls never runs (GAP-1535).
	var uncalled map[*syntax.FuncDecl]bool
	if parsed {
		uncalled = actionUncalledFunctions(file, command)
		command = actionBlankFunctions(command, uncalled)
	}
	var nestedBodies []*syntax.Word
	if parsed {
		var nestedFound bool
		nestedBodies, nestedFound = actionPosixNestedShellMention(file, cwd, home, depth, stateOnly, globs)
		if nestedFound {
			return true
		}
		if !stateOnly && actionInterpreterBuildsKeyPath(file, cwd, home) {
			return true
		}
	}
	memo := globs.targetMemo()
	protected := memo.protectedFiles(home).keysOnlyWith(home, memo)
	ssh := filepath.Join(home, ".ssh")
	stateHome := memo.stateHome(home)
	// base places a relative value: the effective cwd for a parsed word,
	// the request cwd for the text scan.
	// Git Bash spells a Windows drive /c/... (GAP-0781 RV8-1).
	windowsHost := runtime.GOOS == "windows" && actionWindowsHome(home)
	// literal: the value is one entry name whose *, ?, [ and ] were quoted
	// or escaped, so they are not a pattern (GAP-0293).
	checkValue := func(value string, tilde bool, base string, literal bool) bool {
		if len(value) == 0 || len(value) > MaxWriteTargetPathBytes {
			return false
		}
		if windowsHost {
			value = actionMSYSDrivePath(value)
		}
		if spelledWindows {
			return actionSpelledWindowsTarget(value, tilde, base, home, stateOnly)
		}
		if tilde && strings.HasPrefix(value, "~/") {
			if actionPosixWindowsHome(home) {
				value = path.Join(home, value[2:])
			} else {
				value = filepath.Join(home, value[2:])
			}
		}
		if !literal && strings.ContainsAny(value, "*?[]") {
			if stateOnly {
				return false
			}
			if actionPosixWindowsHome(home) {
				return actionPosixWindowsProtectedGlob(value, base, home)
			}
			return actionProtectedFileGlobReach(value, base, protected, ssh, home, globs)
		}
		if actionPosixWindowsHome(home) {
			if stateOnly {
				return actionPosixWindowsStatePath(value, base, home)
			}
			return actionPosixWindowsProtected(value, base, home)
		}
		operand := OperandPath(value, base)
		if stateOnly {
			return actionProtectedStatePath(operand, stateHome)
		}
		if _, resolved := memo.resolveWriteTarget(operand); !resolved {
			// A gateway behind ProtectHome cannot resolve the home: a word
			// that names the .ssh directory itself (rel-1-0-6:GAP-0130) or
			// one of its authorized-keys files (rel-1-0-6:GAP-0046) is still
			// that path, as a per-user gateway reads it.
			if clean := filepath.Clean(operand); samePathName(clean, ssh) || protected.has(clean) {
				return true
			}
		}
		return protectedReachPathWith(operand, protected, ssh, memo)
	}
	// The hook client records an answer for every pattern the scan checks,
	// so while recording it never stops at a match. A long command repeats
	// its words (a heredoc body, a generated script): each distinct value is
	// resolved once per scan, because its answer depends only on the value,
	// its tilde form and its base (GAP-2279, answer budget).
	type mention struct {
		value, base    string
		tilde, literal bool
	}
	answers := map[mention]bool{}
	checkAs := func(value string, tilde bool, base string, literal bool) bool {
		key := mention{value: value, base: base, tilde: tilde, literal: literal}
		found, seen := answers[key]
		if !seen {
			found = checkValue(value, tilde, base, literal)
			answers[key] = found
		}
		return found && !globs.recording()
	}
	check := func(value string, tilde bool, base string) bool { return checkAs(value, tilde, base, false) }
	if parsed {
		// $USER and $LOGNAME name the home's own directory, as
		// actionfacts reads /home/$USER/... (GAP-2269).
		user := filepath.Base(home)
		values := actionValues{"HOME": home, "PWD": cwd, "USER": user, "LOGNAME": user}
		found := false
		effectiveCWD := cwd
		var directoryStack []string
		var judgedWords []*syntax.Word
		// replacedEntries: the link entries plain mv calls replaced so far,
		// in the order the walk reads the statements.
		var replacedEntries []string
		copyOptionCandidate := !stateOnly && strings.Contains(command, "cp") && strings.Contains(command, "$")
		// A brace word of fixed text is the words bash makes of it
		// (rel-1-0-6:GAP-0233, GAP-0255): each is judged as if it were
		// spelled out. A redirect word counts only when it makes one word
		// (more is an ambiguous redirect: nothing is written), and an
		// assignment value is not brace-expanded.
		checkBraceFields := func(word *syntax.Word, redirect bool) bool {
			fields := actionMentionBraceFields(word, home)
			if redirect && len(fields) != 1 {
				return false
			}
			for _, field := range fields {
				if check(field, false, effectiveCWD) {
					return true
				}
			}
			return false
		}
		// removedEntries: the link entries plain rm calls remove. A word of
		// a read-only statement outside a pipeline (ls -l link, cat link)
		// that names such an entry reads the link, before or after the rm,
		// not a key write target (GAP-2590): pendingReads holds those words
		// until the walk has seen every rm.
		var removedEntries []string
		type pendingRead struct {
			word *syntax.Word
			cwd  string
			vals actionValues
			// enters: the statement changes the directory (cd ~/.ssh), which
			// decides what the statements after it write.
			enters bool
		}
		var pendingReads []pendingRead
		direct := actionDirectStatements(file)
		// Quoting makes *, ? and [ literal only in a POSIX reading of a
		// POSIX home; a Windows-spelled home reads them as wildcards.
		literalReading := !spelledWindows && !actionPosixWindowsHome(home)
		checkWord := func(word *syntax.Word) bool {
			value, known := actionWordValue(word, values, effectiveCWD, home)
			activeGlob := actionWordHasUnquotedGlob(word, command)
			if !known && activeGlob {
				value, known = actionWordValueWithGlob(word, values, effectiveCWD, home, true)
			}
			if known && (!strings.ContainsAny(value, "*?[]") || activeGlob) {
				// The value spells a quoted part's glob characters as
				// pattern characters ('k[1]'* reads as k[1]*, matching k1x
				// and missing k[1]x). The pattern that escapes them is the
				// shell's reading (GAP-0293).
				if activeGlob && literalReading && noDereferenceTouchLiteralWord(word) {
					if pattern, escaped := noDereferenceTouchPattern(word, home); escaped {
						value = pattern
					}
				}
				// A parsed value has had its shell tilde expanded already;
				// a remaining "~/" was quoted, escaped or parameter-derived.
				if check(value, false, effectiveCWD) {
					return true
				}
				if _, target, attached := strings.Cut(value, "="); attached {
					return check(target, actionAttachedTildeExpands(word, command), effectiveCWD)
				}
				return false
			}
			// Quoted or escaped glob characters are part of the name: the
			// word names that one entry, a hard link of a protected file
			// included (GAP-0293: 'k[1]' was never resolved).
			if !literalReading {
				return !stateOnly && !globs.recording() && actionUnknownWordMayNameKey(word, effectiveCWD, home)
			}
			// A double-quoted or backslash-escaped one has no plain value:
			// the shell's own field is the name.
			if !known && noDereferenceTouchLiteralWord(word) {
				if fields, err := shellparse.Fields(&expand.Config{Env: expand.ListEnviron("HOME=" + home)}, word); err == nil && len(fields) == 1 {
					value, known = fields[0], true
				}
			}
			if known {
				if checkAs(value, false, effectiveCWD, true) {
					return true
				}
				if _, target, attached := strings.Cut(value, "="); attached &&
					checkAs(target, actionAttachedTildeExpands(word, command), effectiveCWD, true) {
					return true
				}
			}
			return !stateOnly && !globs.recording() && actionUnknownWordMayNameKey(word, effectiveCWD, home)
		}
		syntax.Walk(file, func(node syntax.Node) bool {
			if found {
				return false
			}
			if decl, ok := node.(*syntax.FuncDecl); ok && uncalled[decl] {
				return false
			}
			if iter, ok := node.(*syntax.WordIter); ok {
				for _, word := range iter.Items {
					if actionExpandedWordGlob(word, values, effectiveCWD, home, check) || checkBraceFields(word, false) || checkWord(word) {
						found = true
						return false
					}
				}
				actionLoopBindsUser(iter, values, effectiveCWD, home)
				return true
			}
			stmt, ok := node.(*syntax.Stmt)
			if !ok {
				return true
			}
			values["PWD"] = effectiveCWD
			// The shell expands and opens a statement's redirects before the
			// command runs, so what the command itself binds (printf -v and
			// %n, read, cd, export, declare, local) cannot move them. The
			// values from before the statement are read too (GAP-0428
			// regression of the GAP-2298 class: printf "$X" >
			// "$HOME"/.defenseclaw/config.yaml). An assignment-only statement
			// gets both readings: bash assigns first, dash opens the redirect
			// first, and the hook cannot tell which shell runs it.
			var before actionValues
			if len(stmt.Redirs) > 0 {
				before = maps.Clone(values)
			}
			actionUpdateValues(stmt, values, effectiveCWD, home)
			redirectMentions := func(redir *syntax.Redirect) bool {
				return actionExpandedWordGlob(redir.Word, values, effectiveCWD, home, check) || checkBraceFields(redir.Word, true) || checkWord(redir.Word)
			}
			for _, redir := range stmt.Redirs {
				if redir.Word == nil {
					continue
				}
				hit := redirectMentions(redir)
				if !hit && before != nil {
					after := values
					values = before
					hit = redirectMentions(redir)
					values = after
				}
				if hit {
					found = true
					return false
				}
			}
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
				if copyOptionCandidate {
					if destination, ok := actionPosixCopyVariableTarget(call, values, effectiveCWD, home); ok &&
						check(destination, false, effectiveCWD) {
						found = true
						return false
					}
				}
				for _, assign := range call.Assigns {
					// A variable only holds the text: where it is used decides, and
					// the use is judged with its value (actionUpdateValues).
					if memo.nonWritesExcused() && len(call.Args) == 0 && !actionWordMayBePattern(assign.Value) {
						if assign.Value != nil {
							judgedWords = append(judgedWords, assign.Value)
						}
						continue
					}
					if assign.Value != nil && checkWord(assign.Value) {
						found = true
						return false
					}
				}
				var moved *syntax.Word
				var movedEntry string
				var removed map[*syntax.Word]string
				if !stateOnly {
					// A plain mv onto a link replaces the link: judge its
					// entry, not the file it names (GAP-2559). A plain rm of
					// a link removes the link (GAP-2590).
					if word, entry, ok := actionPlainMoveOntoLink(call, values, effectiveCWD, home); ok {
						moved, movedEntry = word, entry
						judgedWords = append(judgedWords, word)
					}
					removed = actionPlainRemovedLinks(call, values, effectiveCWD, home)
				}
				// An --eval text that only defines rules make does not run
				// is not a target of the call (GAP-2169).
				inert := actionInertMakeEvals(call, effectiveCWD, home)
				// mkdir or a tightening chmod of exactly the home's .ssh
				// folder writes no keys file (rel-1-0-6:GAP-0298).
				if !stateOnly {
					inert = append(inert, actionSSHDirectorySetupWords(call, values, effectiveCWD, home)...)
				}
				judgedWords = append(judgedWords, inert...)
				// A read-only call after a plain mv replaced a link reads the
				// moved file under that name (rel-1-0-6:GAP-0217).
				readOnly := !stateOnly && actionKnownReadOnlyShell(&syntax.File{Stmts: []*syntax.Stmt{stmt}}, home)
				if !readOnly && !stateOnly && memo.nonWritesExcused() {
					// A shell body or an ssh remote command that only reads.
					readOnly = actionKnownReadOnlyShellMode(&syntax.File{Stmts: []*syntax.Stmt{stmt}}, home, 0, true)
				}
				readsReplaced := len(replacedEntries) > 0 && readOnly
				var quick func([]string) bool
				if !stateOnly {
					quick = func(fields []string) bool {
						return actionMissingSimpleTargets(fields, effectiveCWD, protected, ssh, memo)
					}
				}
				if strings.Contains(command, "{") && actionOversizedTouchOperands(call, home, effectiveCWD, check, quick) {
					found = true
					return false
				}
				roleUnknown := memo.nonWritesExcused() && actionCallRoleUnknown(call, home)
				// A statement that only reads, outside a pipeline and not a cd, names
				// the file to read it: its words leave the text scan too (a quoted
				// remote command, a shell body), as a read-only statement's hit words
				// are judged above. The walk keeps the old reading when a link is
				// removed or replaced (a word then names a removed entry).
				blankReads := memo.nonWritesExcused() && readOnly && direct[stmt] && !actionCallChangesDirectory(call, home)
				for _, word := range call.Args {
					if blankReads && len(removedEntries) == 0 && len(replacedEntries) == 0 {
						judgedWords = append(judgedWords, word)
					}
					if roleUnknown {
						// A word handed to a program the scan has no model of is
						// data of unknown role, not a write target: ActionMentionsNoWriteRole
						// leaves it out of this walk and of the text scan.
						judgedWords = append(judgedWords, word)
						continue
					}
					if readsReplaced && actionReplacedEntryWord(word, values, effectiveCWD, home, replacedEntries) {
						judgedWords = append(judgedWords, word)
						continue
					}
					if moved != nil && word == moved {
						if protectedEntry(movedEntry, protected, ssh) {
							found = true
							return false
						}
						continue
					}
					if entry, ok := removed[word]; ok {
						if protectedEntry(entry, protected, ssh) {
							found = true
							return false
						}
						removedEntries = append(removedEntries, entry)
						judgedWords = append(judgedWords, word)
						continue
					}
					if slices.Contains(inert, word) {
						continue
					}
					if actionExpandedWordGlob(word, values, effectiveCWD, home, check) || checkBraceFields(word, false) || checkWord(word) {
						if readOnly && direct[stmt] {
							pendingReads = append(pendingReads, pendingRead{word: word, cwd: effectiveCWD, vals: maps.Clone(values), enters: actionCallChangesDirectory(call, home)})
							judgedWords = append(judgedWords, word)
							continue
						}
						found = true
						return false
					}
				}
				if moved != nil {
					replacedEntries = append(replacedEntries, movedEntry)
				}
				actionPosixAdvanceDirectory(call, values, home, &effectiveCWD, &directoryStack)
			}
			return true
		})
		for _, read := range pendingReads {
			if found {
				break
			}
			if memo.nonWritesExcused() && !read.enters && len(removedEntries) == 0 && len(replacedEntries) == 0 {
				// ActionMentionsNoWriteRole: no link was removed or replaced, so a
				// statement that only reads names the file to read it.
				continue
			}
			found = !actionReplacedEntryWord(read.word, read.vals, read.cwd, home, removedEntries)
		}
		if found {
			return true
		}
		// The text scan below would read the words judged above again: the
		// link a move replaces or an rm removes, an inert make --eval text.
		nestedBodies = append(nestedBodies, judgedWords...)
	}
	text := actionBlankPatchBodies(command, actionMaskLiteralMetacharacters(command))
	if parsed && actionLiteralArgumentProgramsOnly(file, home) {
		text = actionMarkLiteralTildes(text)
	}
	// A static nested shell body was scanned above in its own quoting, so a
	// tilde quoted inside it is literal and an unquoted one is the home. The
	// outer quotes around the body say nothing about that (round m).
	text = actionBlankWords(text, nestedBodies)
	if parsed {
		// A # that starts a word comments out the rest of its line in
		// bash, sh and zsh alike: the shell runs none of it, so a path
		// only a comment names is no target (rel-1-0-6:GAP-0133; the
		// Windows plain reading has the same rule, GAP-1982).
		text = actionBlankComments(text, command)
	}
	text = strings.ReplaceAll(strings.ReplaceAll(text, "${HOME}/", home+"/"), "$HOME/", home+"/")
	for _, token := range actionMentionToken.FindAllString(text, -1) {
		literalTilde := strings.HasPrefix(token, actionLiteralTilde)
		token = strings.ReplaceAll(token, actionLiteralTilde, "~")
		if strings.ContainsAny(token, "*?[]") && (parsed || !strings.ContainsAny(token, "/\\")) {
			continue // Shell case labels and patch text are not argv glob operands.
		}
		if check(token, !literalTilde, cwd) {
			return true
		}
	}
	return false
}

// actionInterpreterSSHName and actionInterpreterKeysName match the two
// protected names of an authorized-keys path in inline interpreter code.
// Code that names both and has an executable writer is a protected target
// in action mode however it joins them: an f-string, +, os.path.join,
// pathlib, str.format, % formatting, Perl's . operator or a .ssh directory
// variable joined later (GAP-1732, GAP-2005, the GAP-0475 class).
var (
	actionInterpreterSSHName  = lazyregexp.New(`\.ssh\b`)
	actionInterpreterKeysName = lazyregexp.New(`\bauthorized_keys2?\b`)
)

// actionInterpreterHomeCall matches the home spellings that the
// interpreter-path proof judges with its binding rules (Path.home(),
// expanduser: GAP-0475, a path bound again before the write, GAP-1299).
// Such code is allowed only when that proof places every write on an
// ordinary path; a home call elsewhere in the code proves nothing (GAP-2005).
var actionInterpreterHomeCall = lazyregexp.New(`Path\.home\(\)|expanduser\(`)

// actionInterpreterCodeWrites reports a writer call (open, write_text,
// appendFileSync ...) in executable code, not inside a string or comment:
// a path built only inside inert text writes nothing (GAP-0475 row).
func actionInterpreterCodeWrites(code, language string) bool {
	for _, location := range unprovenWriter.FindAllStringIndex(code, -1) {
		if language == "python" || strings.HasPrefix(language, "python3") {
			if pythonExecutableCodePosition(code, location[0]) {
				return true
			}
		} else if literalCodePosition(code, location[0], language) {
			return true
		}
	}
	return false
}

// actionInterpreterBuildsKeyPath reports a python -c, perl/ruby/node -e call
// whose code names an authorized-keys path and has a write. The interpreter
// may be run through a wrapper program (env, command, nice, timeout, ...)
// and may have other options before its code option (GAP-2005 RV9-1).
func actionInterpreterBuildsKeyPath(file *syntax.File, cwd, home string) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if found || !ok || len(call.Args) < 3 {
			return !found
		}
		program, known := staticProgramWord(call.Args[0], home)
		if !known {
			return true
		}
		// A word the hook cannot spell stays "": never an option, never code.
		words := []string{program}
		for _, word := range call.Args[1:] {
			value, _ := StaticWord(word, home)
			words = append(words, value)
		}
		at := actionInterpreterProgramIndex(words)
		if at < 0 {
			return true
		}
		if code, ok := actionInterpreterInlineCode(words, at); ok &&
			actionInterpreterKeyPathCode(code, actionInterpreterKind(words[at]), cwd, home) {
			found = true
		}
		return !found
	})
	return found
}

// actionInterpreterKeyPathCode reports inline code that names both
// authorized-keys path parts and has an executable writer, unless the
// binding rules place every write of home-call code on an ordinary path.
func actionInterpreterKeyPathCode(code, language, cwd, home string) bool {
	return actionInterpreterSSHName.MatchString(code) && actionInterpreterKeysName.MatchString(code) &&
		actionInterpreterCodeWrites(code, language) && !actionInterpreterHomeWriteProved(code, language, cwd, home)
}

// actionInterpreterKind names the interpreter family of a program word:
// python (python, python3*, py), node (node, nodejs), perl or ruby; ""
// for any other program.
func actionInterpreterKind(word string) string {
	switch base := programBase(word); {
	case base == "py" || base == "python" || strings.HasPrefix(base, "python3"):
		return "python"
	case base == "node" || base == "nodejs":
		return "node"
	case base == "perl" || base == "ruby":
		return base
	}
	return ""
}

// actionInterpreterWrappers run their operand words as a command.
var actionInterpreterWrappers = map[string]bool{
	"env": true, "command": true, "exec": true, "builtin": true, "nice": true, "timeout": true,
	"nohup": true, "stdbuf": true, "xargs": true, "time": true, "ionice": true, "setsid": true,
	"chrt": true, "taskset": true, "unbuffer": true, "sudo": true, "doas": true, "caffeinate": true,
}

// actionInterpreterProgramIndex returns the index of the interpreter a POSIX
// call runs: the program word itself, or the first interpreter word after a
// wrapper program and its options, NAME=value words and option values; -1
// when the call runs no interpreter.
func actionInterpreterProgramIndex(words []string) int {
	if actionInterpreterKind(words[0]) != "" {
		return 0
	}
	if !actionInterpreterWrappers[programBase(words[0])] {
		return -1
	}
	for i := 1; i < len(words); i++ {
		if actionInterpreterKind(words[i]) != "" {
			return i
		}
	}
	return -1
}

// actionInterpreterInlineCode returns the inline code of the interpreter at
// words[at]: the word after its code option, past the interpreter's other
// options and the values of the options that take one (python -X/-W, node
// -r/--require/--import/--loader, perl -I/-M/-m, ruby -I/-r), so an extra
// option before the code does not hide it (GAP-2005 RV9-1).
func actionInterpreterInlineCode(words []string, at int) (string, bool) {
	kind := actionInterpreterKind(words[at])
	for j := at + 1; j+1 < len(words); j++ {
		option := words[j]
		if !strings.HasPrefix(option, "-") || option == "-" || option == "--" || kind == "python" && option == "-m" {
			return "", false
		}
		if actionWindowsInterpreterCodeOption(kind, option) {
			return words[j+1], true
		}
		if actionInterpreterOptionTakesValue(kind, option) {
			j++
		}
	}
	return "", false
}

// actionInterpreterOptionTakesValue reports an interpreter option whose
// value is the next word.
func actionInterpreterOptionTakesValue(kind, option string) bool {
	switch kind {
	case "python":
		// --check-hash-based-pycs is the one long python option with a value.
		return option == "-X" || option == "-W" || option == "-Q" || option == "--check-hash-based-pycs"
	case "node":
		switch option {
		case "-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions",
			"--input-type", "--env-file", "--title":
			return true
		}
	case "perl":
		return option == "-I" || option == "-M" || option == "-m"
	case "ruby":
		return option == "-I" || option == "-r" || option == "-C" || option == "-E"
	}
	return false
}

// actionInterpreterHomeWriteProved reports home-call code whose every write
// the interpreter-path binding rules place on an ordinary path.
func actionInterpreterHomeWriteProved(code, language, cwd, home string) bool {
	if !actionInterpreterHomeCall.MatchString(code) {
		return false
	}
	class, _ := unprovenInterpreterCode(code, language, cwd, home, true)
	return class == ""
}

// actionLoopBindsUser takes USER or LOGNAME out of values when the for or
// select loop iter binds it to words that all read as other logins: the
// loop body and the statements after it name another user home, not the
// active one. A word the scan cannot read, an empty list (the positional
// parameters) or the active login itself keeps the value, so the body is
// still read as the active user (rel-1-0-6:GAP-0601 review 5).
func actionLoopBindsUser(iter *syntax.WordIter, values actionValues, cwd, home string) {
	if iter.Name == nil || iter.Name.Value != "USER" && iter.Name.Value != "LOGNAME" || len(iter.Items) == 0 {
		return
	}
	active := values[iter.Name.Value]
	for _, word := range iter.Items {
		if value, known := actionWordValue(word, values, cwd, home); !known || value == active || strings.ContainsAny(value, "*?[") {
			return
		}
	}
	delete(values, iter.Name.Value)
}

// actionUncalledFunctions lists the function definitions whose name the
// command never names outside the definition itself: no call, no export -f,
// trap, alias, eval or xargs argument. Such a body never runs. Names the
// shell calls on its own (command_not_found_handle, zsh hooks and TRAP*)
// always count as called.
func actionUncalledFunctions(file *syntax.File, command string) map[*syntax.FuncDecl]bool {
	var decls []*syntax.FuncDecl
	syntax.Walk(file, func(node syntax.Node) bool {
		if decl, ok := node.(*syntax.FuncDecl); ok && decl.Name != nil {
			decls = append(decls, decl)
		}
		return true
	})
	if len(decls) == 0 {
		return nil
	}
	staticNames, static := actionStaticCallWords(file)
	if !static {
		// A program word the hook cannot spell (an expansion, a command
		// substitution, an indirect name), eval, source or a quoted handler
		// can call any function: every body is scanned (classifier RV3-2).
		return nil
	}
	uncalled := make(map[*syntax.FuncDecl]bool)
	for _, decl := range decls {
		name := decl.Name.Value
		if staticNames[name] {
			continue // called through another spelling, such as f\oo or fo""o
		}
		switch {
		case name == "" || strings.HasPrefix(name, "TRAP") || strings.HasPrefix(name, "command_not_found_handl"):
			continue
		}
		switch name {
		case "precmd", "preexec", "chpwd", "periodic", "zshexit", "zshaddhistory", "zle-line-init":
			continue
		}
		start, end := int(decl.Pos().Offset()), int(decl.End().Offset())
		if start < 0 || end > len(command) || start >= end {
			continue
		}
		pattern := regexp.MustCompile(`(^|[^A-Za-z0-9_.:-])` + regexp.QuoteMeta(name) + `($|[^A-Za-z0-9_.:-])`)
		rest := command[:start] + strings.Repeat(" ", end-start) + command[end:]
		if !pattern.MatchString(rest) {
			uncalled[decl] = true
		}
	}
	if len(uncalled) > 0 && actionEvaluatesRuntimeNames(file, uncalled) {
		// bash evaluates a string as code or arithmetic here, and a
		// subscript such as a[$(f""oo)] runs a command substitution that
		// can call any function: every body is scanned (GAP-2089).
		return nil
	}
	return uncalled
}

// actionEvaluatesRuntimeNames reports whether the command, outside its
// uncalled function bodies, has a construct in which bash evaluates a string
// that the command does not spell as a call: an arithmetic expansion,
// command or loop, let, a [[ ]] arithmetic or -v test, an indirect,
// subscripted, sliced or @-transformed parameter expansion, an assignment
// with a subscript or to a prompt variable, a declaration with options, and
// the builtins that take a variable name or a callback (mapfile -C, read,
// printf -v, test -v ...). Plain $name expansions only expand (GAP-2089).
func actionEvaluatesRuntimeNames(file *syntax.File, uncalled map[*syntax.FuncDecl]bool) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		switch node := node.(type) {
		case *syntax.FuncDecl:
			if uncalled[node] {
				return false // never runs
			}
		case *syntax.ArithmExp, *syntax.ArithmCmd, *syntax.LetClause, *syntax.CStyleLoop:
			found = true
		case *syntax.BinaryTest:
			switch node.Op {
			case syntax.TsEql, syntax.TsNeq, syntax.TsLeq, syntax.TsGeq, syntax.TsLss, syntax.TsGtr:
				found = true
			}
		case *syntax.UnaryTest:
			found = node.Op == syntax.TsVarSet || node.Op == syntax.TsRefVar
		case *syntax.ParamExp:
			found = node.Excl || node.Slice != nil || node.NestedParam != nil || !actionPlainSubscript(node.Index) ||
				(node.Exp != nil && node.Exp.Op == syntax.OtherParamOps)
		case *syntax.Assign:
			if !actionPlainSubscript(node.Index) {
				found = true
			} else if node.Name != nil {
				switch node.Name.Value {
				case "PS0", "PS1", "PS2", "PS3", "PS4", "PROMPT_COMMAND",
					"PROMPT", "PROMPT2", "PROMPT3", "PROMPT4", "RPROMPT", "RPROMPT2", "RPS1", "RPS2", "SPROMPT":
					found = true
				}
			} else if node.Value != nil {
				// declare -i, local -n, typeset -a ...: an option word.
				value, fixed := StaticWord(node.Value, "")
				found = !fixed || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "+")
			}
		case *syntax.ArrayElem:
			found = !actionPlainSubscript(node.Index)
		case *syntax.ExtGlob:
			// zsh reads *(e:code:) and *(+name) as glob qualifiers that
			// run code for every file (RV5-1).
			found = true
		case *syntax.Word:
			// A static word that holds a command substitution is code
			// for whatever evaluates it: zsh print -P with promptsubst,
			// ${(e)...}, zstyle -e, a later eval (RV5-1).
			if value, fixed := StaticWord(node, ""); fixed && (strings.Contains(value, "$(") || strings.Contains(value, "`") ||
				actionZshQualifierText.MatchString(value)) {
				found = true
			}
			// zsh $~name, ${~name} and ${(~)name} glob a value at run
			// time, and a qualifier in it can run any function (RV6-1).
			if actionZshGlobSubstWord(node) {
				found = true
			}
		case *syntax.DeclClause:
			found = node.Variant != nil && node.Variant.Value == "nameref"
		case *syntax.CallExpr:
			found = actionCallEvaluatesNames(node.Args)
		}
		return !found
	})
	return found
}

// actionZshQualifierText matches a string that holds a zsh glob qualifier
// that runs code for every file: a pattern followed by (e:code:),
// (e'code'), (+name) or a longer qualifier list such as (.e:code:)
// (RV6-1). Prose such as "see (e.g. x)" has a space before the paren.
var actionZshQualifierText = lazyregexp.New(`[^\s(]\([^()\s]*(?:e[^A-Za-z0-9_\s()]|\+[A-Za-z_])`)

// actionZshGlobSubstWord reports a word with a zsh glob-subst expansion:
// $~name, ${~name} or a ${(...~...)name} flag list. The bash parser reads
// $~ as literal text, so the raw literal is checked as well (RV6-1).
func actionZshGlobSubstWord(word *syntax.Word) bool {
	found := false
	syntax.Walk(word, func(node syntax.Node) bool {
		if found {
			return false
		}
		if lit, ok := node.(*syntax.Lit); ok && (strings.Contains(lit.Value, "$~") || strings.Contains(lit.Value, "${~") ||
			strings.Contains(lit.Value, "${(")) {
			found = true
		}
		return !found
	})
	return found
}

// actionPlainSubscript reports a missing subscript or one bash does not
// evaluate as an expression: a number, @ or *.
func actionPlainSubscript(index syntax.ArithmExpr) bool {
	if index == nil {
		return true
	}
	word, ok := index.(*syntax.Word)
	if !ok {
		return false
	}
	value, fixed := StaticWord(word, "")
	if !fixed || value == "" {
		return false
	}
	if value == "@" || value == "*" {
		return true
	}
	return strings.Trim(value, "0123456789") == ""
}

// actionCallEvaluatesNames reports a call of a builtin that evaluates a
// variable name (with its subscript) or runs a callback it is given.
func actionCallEvaluatesNames(args []*syntax.Word) bool {
	for i := 0; i < len(args); i++ {
		program, fixed := StaticWord(args[i], "")
		if !fixed {
			return false // a run-time program word is actionStaticCallWords' case
		}
		switch programBase(program) {
		case "builtin", "command":
			for i+1 < len(args) {
				option, fixed := StaticWord(args[i+1], "")
				if !fixed || !strings.HasPrefix(option, "-") {
					break
				}
				i++
			}
			continue
		case "mapfile", "readarray", "let", "read", "unset", "getopts", "wait", "fc", "sched", "zstyle", "zle",
			"declare", "typeset", "local", "export", "readonly":
			return true
		case "printf":
			if i+1 < len(args) {
				option, fixed := StaticWord(args[i+1], "")
				return !fixed || strings.HasPrefix(option, "-v")
			}
		case "print":
			// zsh print -P expands prompt escapes (with promptsubst, a
			// command substitution) and print -v assigns a name (RV5-1).
			for _, arg := range args[i+1:] {
				option, fixed := StaticWord(arg, "")
				if !fixed {
					return true
				}
				if option == "--" || option == "-" || !strings.HasPrefix(option, "-") {
					break
				}
				if strings.ContainsAny(option, "Pv") {
					return true
				}
			}
		case "test", "[":
			for _, arg := range args[i+1:] {
				value, fixed := StaticWord(arg, "")
				if !fixed || value == "-v" || value == "-R" {
					return true
				}
			}
		}
		return false
	}
	return false
}

// actionStaticCallWords lists the static values of the words of every call
// and declaration in file. It reports false when a function could run under
// a name the command does not spell: a program word that is not static, an
// eval, source or . call, or a trap, alias, bind or complete argument that is
// not static or carries shell quoting, escapes or expansions.
func actionStaticCallWords(file *syntax.File) (map[string]bool, bool) {
	names := make(map[string]bool)
	static := true
	syntax.Walk(file, func(node syntax.Node) bool {
		if !static {
			return false
		}
		switch node := node.(type) {
		case *syntax.CallExpr:
			if len(node.Args) == 0 {
				return true
			}
			program, fixed := StaticWord(node.Args[0], "")
			if !fixed {
				static = false
				return false
			}
			switch programBase(program) {
			case "eval", "source", ".":
				static = false
				return false
			}
			names[program] = true
			code := false
			switch programBase(program) {
			case "trap", "alias", "bind", "complete", "compgen":
				code = true
			}
			for _, arg := range node.Args[1:] {
				value, fixed := StaticWord(arg, "")
				if code && (!fixed || strings.ContainsAny(value, "'\"\\$`")) {
					static = false
					return false
				}
				if fixed {
					names[value] = true
				}
			}
		case *syntax.DeclClause:
			for _, assign := range node.Args {
				if assign.Name != nil {
					names[assign.Name.Value] = true
				}
				if assign.Value == nil {
					continue
				}
				value, fixed := StaticWord(assign.Value, "")
				if !fixed && assign.Name == nil {
					static = false // export -f "$name" exports any function
					return false
				}
				if fixed {
					names[value] = true
				}
			}
		}
		return true
	})
	return names, static
}

// actionBlankFunctions blanks the uncalled function definitions in command,
// keeping every offset.
func actionBlankFunctions(command string, uncalled map[*syntax.FuncDecl]bool) string {
	if len(uncalled) == 0 {
		return command
	}
	out := []byte(command)
	for decl := range uncalled {
		start, end := int(decl.Pos().Offset()), int(decl.End().Offset())
		for i := start; i < end && i < len(out); i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	return string(out)
}

// actionBlankPatchBodies blanks, in the text scan, the content lines of the
// patch envelopes apply_patch calls read: those calls write only the files
// their headers name, which stay (GAP-0781, GAP-1106). text is command with
// its literal metacharacters masked, line for line.
func actionBlankPatchBodies(command, text string) string {
	if !strings.Contains(command, patchBeginMarker) {
		return text
	}
	fed := patchFedLines(command)
	lines := strings.Split(text, "\n")
	if fed == nil || len(lines) != len(fed) {
		return text
	}
	commandLines := strings.Split(command, "\n")
	for i, line := range commandLines {
		if !fed[i] && patchCommandResolutionChange(line) {
			// Another apply_patch may run and read the body as a script.
			return text
		}
	}
	for i, line := range commandLines {
		if fed[i] && !strings.HasPrefix(strings.TrimSpace(line), "***") {
			lines[i] = strings.Repeat(" ", len(lines[i]))
		}
	}
	return strings.Join(lines, "\n")
}

// patchResolutionChanges match shell text that may change the program an
// apply_patch word runs: a PATH (zsh path) assignment, export or unset, the
// PowerShell Env:PATH drive, or a sourced, evaluated or aliased definition.
// Envelope lines (headers such as "*** Add File: PATH.md") and text that only
// mentions or reads PATH change nothing (round n review).
var patchResolutionChanges = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(^|[^a-z0-9_-])path\s*(\+?=|\[)`),
	regexp.MustCompile(`(?i)(^|[^a-z0-9_-])(export|unset|declare|typeset|readonly|local|setenv|env)\b.*\bpath\b`),
	regexp.MustCompile(`(?i)env:\\?path\b|setenvironmentvariable|\b(iex|invoke-expression)\b`),
	regexp.MustCompile(`(^|[\s;&|(])(source|eval|\.)(\s|$)|\b(alias|functions|hash|enable)\b`),
}

func patchCommandResolutionChange(line string) bool {
	for _, change := range patchResolutionChanges {
		if change.MatchString(line) {
			return true
		}
	}
	return false
}

// The text scan finds paths in payloads another program interprets (inline
// interpreter code, nested shells), where a quoted "~/" may still expand.
// When every program in the command only reads, prints or writes its file
// operands as written and nothing is redirected to a file, a quoted or escaped "~/" is the literal
// name the shell passes. It is marked so the scan resolves it below the cwd,
// not the home. Writers and redirects keep the conservative home spelling.
const actionLiteralTilde = "\x1e"

var actionMentionToken = lazyregexp.New(`[A-Za-z0-9_./~*?\[\]\x1e-]+`)

func actionLiteralArgumentProgramsOnly(file *syntax.File, home string) bool {
	literal := true
	syntax.Walk(file, func(node syntax.Node) bool {
		if !literal {
			return false
		}
		switch node := node.(type) {
		case *syntax.FuncDecl, *syntax.ProcSubst, *syntax.CoprocClause:
			literal = false
			return false
		case *syntax.Redirect:
			// Writing the text keeps the 1.0.0 mention rule: an output
			// redirect of a key spelling is a protected-named write.
			switch node.Op {
			case syntax.RdrIn, syntax.DplIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
			default:
				literal = false
				return false
			}
		}
		if _, ok := node.(*syntax.DeclClause); ok {
			// export, declare, local, readonly: a value may reach a
			// program that runs it through a shell (GIT_PAGER, LESSOPEN).
			literal = false
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		if !actionLiteralAssignments(call.Assigns) {
			literal = false
			return false
		}
		if len(call.Args) == 0 {
			return true
		}
		args, known := actionLiteralCommandWords(call.Args, home)
		if !known {
			literal = false
			return false
		}
		program, _ := staticProgramWord(args[0], home)
		switch programBase(program) {
		case "echo", "printf", "grep", "egrep", "fgrep", "rg", "cat", "head", "tail", "less", "more",
			"wc", "ls", "dir", "stat", "file", "sort", "uniq", "cut", "tr", "diff", "cmp", "cd",
			// Codex names its Windows PowerShell tool Bash: there these
			// print their arguments as written, and no POSIX shell has
			// them (GAP-1473).
			"write-output", "write-host",
			"pushd", "popd", "dirs", "pwd", "true", "false", "test", "[", "basename", "dirname",
			// File writers take their operands as written: a quoted "~/" is
			// a directory named "~" below the cwd, not the home (round l).
			"cp", "mv", "touch", "mkdir", "rm", "ln", "install", "tee", "dd":
		case "git":
			literal = actionLiteralGitWords(args[1:], home)
		default:
			literal = false
		}
		return literal
	})
	return literal
}

// actionLiteralCommandWords strips the wrappers that pass the rest of argv
// on as written (command, builtin, nohup, exec, nice, env with plain
// assignments) and returns the wrapped program's words. known is false for
// a dynamic word or an option it does not know, such as env -S or -C.
func actionLiteralCommandWords(args []*syntax.Word, home string) (words []*syntax.Word, known bool) {
	for wrapper := 0; wrapper < 8 && len(args) > 0; wrapper++ {
		program, fixed := staticProgramWord(args[0], home)
		if !fixed {
			return nil, false
		}
		program = programBase(program)
		index := 1
		switch program {
		case "command", "builtin", "nohup", "exec", "nice", "env", "sudo", "doas", "timeout",
			"stdbuf", "ionice", "setsid":
		default:
			return args, true
		}
		durationPending := program == "timeout"
		for index < len(args) {
			word, fixed := StaticWord(args[index], home)
			if !fixed {
				return nil, false
			}
			if word == "--" {
				index++
				break
			}
			if program == "env" && !strings.HasPrefix(word, "-") && strings.Contains(word, "=") {
				name, _, _ := strings.Cut(word, "=")
				if !actionLiteralEnvironmentName(name) {
					return nil, false
				}
				index++
				continue
			}
			if !strings.HasPrefix(word, "-") {
				if durationPending {
					// timeout DURATION COMMAND: the duration is not the program.
					if !literalDuration(word) {
						return nil, false
					}
					durationPending = false
					index++
					continue
				}
				break
			}
			if consumed, ok := actionLiteralWrapperOption(program, word, args[index+1:], home); ok {
				index += consumed
				continue
			}
			switch {
			case program == "command" && word == "-p",
				program == "exec" && (word == "-c" || word == "-l"),
				program == "env" && (word == "-i" || word == "--ignore-environment"):
				index++
			case program == "nice" && index == 1 && (word == "-n" || word == "--adjustment"):
				if index+1 >= len(args) {
					return nil, false
				}
				value, fixed := StaticWord(args[index+1], home)
				if !fixed || !literalInteger(value) {
					return nil, false
				}
				index += 2
			case program == "nice" && index == 1 && strings.HasPrefix(word, "--adjustment=") &&
				literalInteger(strings.TrimPrefix(word, "--adjustment=")):
				index++
			case program == "nice" && index == 1 && strings.HasPrefix(word, "-n") && literalInteger(word[2:]):
				index++
			default:
				return nil, false
			}
		}
		if index >= len(args) || durationPending {
			return nil, false
		}
		args = args[index:]
	}
	return nil, false
}

// actionLiteralWrapperOption reports how many words an option of sudo, doas,
// timeout, stdbuf, ionice, setsid or env takes when the wrapper still runs
// the next words as argv. Options that start a shell, edit a file, change
// the directory or list instead of running (sudo -s/-i/-e/-D/-l, doas -s,
// env -C/-S) are not listed, so the command stays on the home spelling.
func actionLiteralWrapperOption(program, word string, rest []*syntax.Word, home string) (int, bool) {
	value := func() bool {
		if len(rest) == 0 {
			return false
		}
		_, fixed := StaticWord(rest[0], home)
		return fixed
	}
	switch program {
	case "sudo":
		switch word {
		case "-n", "--non-interactive", "-E", "--preserve-env", "-H", "--set-home", "-S", "--stdin",
			"-k", "--reset-timestamp", "-b", "--background", "-P", "--preserve-groups":
			return 1, true
		case "-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "--close-from",
			"-T", "--command-timeout", "-r", "--role", "-t", "--type", "-U", "--other-user":
			return 2, value()
		}
		for _, prefix := range []string{"--user=", "--group=", "--host=", "--prompt=", "--close-from=",
			"--command-timeout=", "--role=", "--type="} {
			if strings.HasPrefix(word, prefix) {
				return 1, true
			}
		}
		if len(word) > 2 && !strings.HasPrefix(word, "--") && strings.Trim(word[1:], "nEHSkbP") == "" {
			return 1, true // combined switches such as -nE
		}
	case "doas":
		switch word {
		case "-n":
			return 1, true
		case "-u":
			return 2, value()
		}
	case "timeout":
		switch word {
		case "--foreground", "--preserve-status", "-v", "--verbose":
			return 1, true
		case "-k", "--kill-after", "-s", "--signal":
			return 2, value()
		}
		if strings.HasPrefix(word, "--kill-after=") || strings.HasPrefix(word, "--signal=") ||
			strings.HasPrefix(word, "-k") || strings.HasPrefix(word, "-s") {
			return 1, true
		}
	case "stdbuf":
		switch word {
		case "-i", "-o", "-e", "--input", "--output", "--error":
			return 2, value()
		}
		if len(word) > 2 && (strings.HasPrefix(word, "-i") || strings.HasPrefix(word, "-o") ||
			strings.HasPrefix(word, "-e")) && !strings.HasPrefix(word, "--") ||
			strings.HasPrefix(word, "--input=") || strings.HasPrefix(word, "--output=") ||
			strings.HasPrefix(word, "--error=") {
			return 1, true
		}
	case "ionice":
		switch word {
		case "-c", "--class", "-n", "--classdata":
			return 2, value()
		case "-t", "--ignore":
			return 1, true
		}
		if len(word) > 2 && (strings.HasPrefix(word, "-c") || strings.HasPrefix(word, "-n")) &&
			!strings.HasPrefix(word, "--") {
			return 1, true
		}
	case "setsid":
		switch word {
		case "-f", "--fork", "-w", "--wait", "-c", "--ctty":
			return 1, true
		}
	case "env":
		switch word {
		case "-u", "--unset":
			return 2, value()
		case "-0", "--null":
			return 1, true
		}
		if strings.HasPrefix(word, "--unset=") {
			return 1, true
		}
	}
	return 0, false
}

// actionLiteralAssignments reports whether every assignment of a command
// sets only a name no listed program hands to a shell. GIT_PAGER, PAGER,
// EDITOR, LESSOPEN and the like run their value, so they are not literal.
func actionLiteralAssignments(assigns []*syntax.Assign) bool {
	for _, assign := range assigns {
		if assign == nil || assign.Name == nil || assign.Append || assign.Naked || assign.Index != nil ||
			assign.Array != nil || !actionLiteralEnvironmentName(assign.Name.Value) {
			return false
		}
	}
	return true
}

// A lower-case name is a shell variable by convention; the programs above
// read only upper-case environment names, and of those only the locale and
// terminal ones are known not to run their value.
func actionLiteralEnvironmentName(name string) bool {
	if name != "" && strings.ToLower(name) == name {
		return true
	}
	switch name {
	case "LANG", "LANGUAGE", "TZ", "NO_COLOR", "TERM", "COLUMNS", "LINES":
		return true
	}
	return strings.HasPrefix(name, "LC_") && len(name) > len("LC_")
}

// actionLiteralGitWords reports whether a git command only reads or records
// its message text. Global options that only move or scope the repository
// are skipped; -c, --config-env, --exec-path and similar can install a
// command that runs later, and grep -O runs its value through a shell.
func actionLiteralGitWords(words []*syntax.Word, home string) bool {
	for len(words) > 0 {
		option, fixed := StaticWord(words[0], home)
		if !fixed {
			return false
		}
		switch option {
		case "-C":
			if len(words) < 2 {
				return false
			}
			words = words[2:]
			continue
		case "-c":
			// An identity or display setting runs nothing (GAP-1473).
			if len(words) < 2 {
				return false
			}
			if setting, fixed := StaticWord(words[1], home); !fixed || !actionGitInertConfig(setting) {
				return false
			}
			words = words[2:]
			continue
		case "--no-pager", "-P", "--no-optional-locks", "--literal-pathspecs", "--glob-pathspecs",
			"--noglob-pathspecs", "--icase-pathspecs", "--no-replace-objects":
			words = words[1:]
			continue
		}
		switch option {
		case "commit", "log", "show", "diff", "status":
			return true
		case "grep":
			for _, word := range words[1:] {
				value, fixed := StaticWord(word, home)
				if !fixed || strings.HasPrefix(value, "--o") ||
					strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "--") && strings.Contains(value, "O") {
					return false
				}
			}
			return true
		}
		return false
	}
	return false
}

// actionMarkLiteralTildes marks each quoted or escaped tilde that starts a
// path token. The input keeps the command's quotes, so their state is exact.
func actionMarkLiteralTildes(text string) string {
	quoted := actionShellQuotedBytes(text)
	var out strings.Builder
	out.Grow(len(text))
	for i := 0; i < len(text); i++ {
		if text[i] == '~' && quoted[i] && i+1 < len(text) && text[i+1] == '/' &&
			(i == 0 || !actionMentionToken.MatchString(text[i-1:i])) {
			out.WriteString(actionLiteralTilde)
			continue
		}
		out.WriteByte(text[i])
	}
	return out.String()
}

// actionShellQuotedBytes reports, per byte, whether the outer shell quotes
// or escapes it.
func actionShellQuotedBytes(command string) []bool {
	quoted := make([]bool, len(command))
	var quote byte
	escaped := false
	for i := 0; i < len(command); i++ {
		c := command[i]
		quoted[i] = escaped || quote != 0
		switch {
		case escaped:
			escaped = false
		case c == '\\' && quote != '\'':
			escaped = true
		case c == '\'' && quote == 0:
			quote = '\''
		case c == '\'' && quote == '\'':
			quote = 0
		case c == '"' && quote == 0:
			quote = '"'
		case c == '"' && quote == '"':
			quote = 0
		}
	}
	return quoted
}

// The shell expands a tilde right after the "=" of an assignment-shaped
// argument (of=~/x) only when that tilde is unquoted.
func actionAttachedTildeExpands(word *syntax.Word, command string) bool {
	start, end := int(word.Pos().Offset()), int(word.End().Offset())
	if start < 0 || end > len(command) || start >= end {
		return false
	}
	raw := command[start:end]
	equals := strings.IndexByte(raw, '=')
	return equals >= 0 && equals+1 < len(raw) && raw[equals+1] == '~' &&
		!actionShellQuotedBytes(raw)[equals+1]
}

// A Windows hook may receive a POSIX-dialect command from WSL or another
// shell with a POSIX active home. The host filesystem cannot resolve those
// names, so compare only their bounded lexical protected-target spelling.
func actionPosixWindowsHome(home string) bool {
	return runtime.GOOS == "windows" && strings.HasPrefix(home, "/") && !strings.HasPrefix(home, "//")
}

func actionPosixWindowsPath(value, cwd, home string) string {
	if value == "~" {
		value = home
	} else if strings.HasPrefix(value, "~/") {
		value = path.Join(home, value[2:])
	}
	if !path.IsAbs(value) {
		value = path.Join(cwd, value)
	}
	return path.Clean(value)
}

func actionPosixWindowsProtected(value, cwd, home string) bool {
	resolved := actionPosixWindowsPath(value, cwd, home)
	ssh := path.Join(home, ".ssh")
	if resolved == ssh {
		return true
	}
	for _, name := range AuthorizedKeysFiles {
		if resolved == path.Join(ssh, name) {
			return true
		}
	}
	return false
}

func actionPosixWindowsProtectedGlob(value, cwd, home string) bool {
	resolved := actionPosixWindowsPath(value, cwd, home)
	ssh := path.Join(home, ".ssh")
	if matched, _ := path.Match(resolved, ssh); matched {
		return true
	}
	for _, name := range AuthorizedKeysFiles {
		if matched, _ := path.Match(resolved, path.Join(ssh, name)); matched {
			return true
		}
	}
	return false
}

// Match known protected names first, then expand the pattern as the shell
// does, one component at a time, so a wildcard in any component that selects
// a directory alias of ~/.ssh or a key file is followed (GAP-1445). The walk
// is bounded; past the bound a final component that can select a key or
// the .ssh directory stays protected-named.
//
// A gateway behind ProtectHome cannot read the user's directories, so its
// walk is incomplete. The managed hook client expands the same pattern as
// the user and sends its answer (GlobFactPrefix); that answer decides, as
// the walk of a gateway that can see the home would (GAP-1460 review). With
// no answer, the name fallback below keeps the pattern closed.
func actionProtectedFileGlobReach(pattern, cwd string, protected protectedFiles, ssh, home string, globs *actionGlobs) bool {
	return actionProtectedFileGlobReachAs(pattern, cwd, protected, ssh, home, globs, false)
}

// actionProtectedFileGlobReachAs is actionProtectedFileGlobReach; windows
// reads the pattern as a PowerShell or cmd wildcard, which matches a leading
// dot, where a POSIX shell's * and ? skip it (Git Bash too, GAP-1717).
func actionProtectedFileGlobReachAs(pattern, cwd string, protected protectedFiles, ssh, home string, globs *actionGlobs, windows bool) bool {
	literal := ""
	if !filepath.IsAbs(pattern) {
		literal = filepath.Clean(cwd)
	}
	pattern = OperandPath(pattern, cwd)
	dots := sync.OnceValue(func() bool { return windows || globs.dotNames() || actionShellProfileMayDotglob(home) })
	for _, target := range append([]string{ssh}, ProtectedAuthorizedKeysPaths(home)...) {
		// In a POSIX shell * and ? skip a leading dot: at the home folder
		// echo * names no .ssh unless dotglob may be on (rel-1-0-6:GAP-0211).
		if matched, _ := filepath.Match(pattern, target); matched && (actionGlobDotComponentsMatch(pattern, target) || dots()) {
			return true
		}
	}
	if _, err := filepath.Match(pattern, ""); err != nil || globs.full() {
		return false
	}
	hidden := actionGlobViewHidden(cwd, home)
	userView := !hidden && actionProcessOwnsHome(home)
	candidates, complete, unseen := actionExpandGlob(pattern, literal, hidden, userView, dots)
	for _, candidate := range candidates {
		if protectedReachPath(candidate, protected, ssh) {
			globs.note(pattern, "1")
			return true
		}
	}
	if complete {
		globs.note(pattern, "0")
		return false
	}
	if hidden && unseen {
		if answer := globs.answer(pattern); answer != "" {
			// A walk this process could not see defers to the client,
			// which expanded the pattern as the user.
			return answer == "1"
		}
		if !globs.fromClient() {
			// No client evidence at all (an older hook client): the
			// name fallback of round m.
			base := filepath.Base(pattern)
			if !strings.ContainsAny(filepath.Dir(pattern), "*?[") && !actionGlobHasLiteral(base) {
				// Only the last component is a pattern, in a directory
				// this process cannot read, and it names nothing (git
				// add *): no directory alias can be selected.
				return false
			}
			for _, name := range append([]string{".ssh"}, AuthorizedKeysFiles[:]...) {
				if actionGlobNameMatch(base, name) {
					return true
				}
			}
			return false
		}
	}
	// The walk (this one, or the client's that sent no answer) stopped at
	// a bound or at a directory it could not read, so an alias of any name
	// may be among the names it did not see: the pattern is unproved,
	// never an allow (GAP-1481).
	return true
}

// actionGlobDotComponentsMatch reports, for a pattern that filepath.Match
// matches to name, that every component of name that starts with a dot is
// matched by a pattern component that starts with a dot (escaped or not),
// as a POSIX shell requires without dotglob.
func actionGlobDotComponentsMatch(pattern, name string) bool {
	separator := string(filepath.Separator)
	patterns, names := strings.Split(pattern, separator), strings.Split(name, separator)
	if len(patterns) != len(names) {
		return false
	}
	for i, component := range names {
		if !strings.HasPrefix(component, ".") {
			continue
		}
		if runtime.GOOS != "windows" {
			patterns[i] = strings.TrimPrefix(patterns[i], "\\")
		}
		if !strings.HasPrefix(patterns[i], ".") {
			return false
		}
	}
	return true
}

// actionGlobs carries the hook client's pathname-pattern answers through
// one target scan, keyed GlobFactPrefix plus the absolute pattern. A
// gateway reads facts; the hook client fills record. A plain scan has none.
type actionGlobs struct {
	facts  map[string]string
	record map[string]string
	// memo is the evaluation's file system answers (TargetMemo); a
	// nested body's scan shares it.
	memo *TargetMemo
	// dots is set when the command may make * and ? match a leading dot
	// (actionCommandMayDotglob).
	dots bool
}

// forCommand returns the scan state of one command, sharing the client's
// facts and record.
func (g *actionGlobs) forCommand(command string) *actionGlobs {
	var scan actionGlobs
	if g != nil {
		scan = *g
	}
	scan.dots = actionCommandMayDotglob(command)
	return &scan
}

func (g *actionGlobs) dotNames() bool { return g != nil && g.dots }

// forCommandWith is forCommand with the evaluation's memo.
func (g *actionGlobs) forCommandWith(command string, memo *TargetMemo) *actionGlobs {
	scan := g.forCommand(command)
	scan.memo = memo
	return scan
}

func (g *actionGlobs) targetMemo() *TargetMemo {
	if g == nil {
		return nil
	}
	return g.memo
}

// actionDotglobSettings are the names (lowercased, without underscores) of a
// shell setting that lets * and ? match a leading dot: bash dotglob or a
// GLOBIGNORE, zsh GLOB_DOTS, or a startup file (BASH_ENV) that may set one;
// actionDotglobQualifier matches a (D) glob qualifier.
var (
	actionDotglobSettings  = []string{"dotglob", "globdots", "globignore", "bashenv"}
	actionDotglobQualifier = lazyregexp.New(`[*?\]]\([^()]*D[^()]*\)`)
)

// actionDotglobSettingIn reports a dotglob setting in text that is lowercased
// without underscores.
func actionDotglobSettingIn(folded string) bool {
	for _, setting := range actionDotglobSettings {
		if strings.Contains(folded, setting) {
			return true
		}
	}
	return false
}

// actionCommandMayDotglob reads the command with plain substring checks
// first: the regular expression is an automaton run over every byte, which
// costs a large heredoc body hundreds of milliseconds, and it can match only
// where a glob character is followed by an opening parenthesis.
func actionCommandMayDotglob(command string) bool {
	if actionDotglobSettingIn(strings.ReplaceAll(strings.ToLower(command), "_", "")) {
		return true
	}
	if !strings.Contains(command, "*(") && !strings.Contains(command, "?(") && !strings.Contains(command, "](") {
		return false
	}
	return actionDotglobQualifier.MatchString(command)
}

// actionShellProfileMayDotglob reports a startup file of the user's or the
// system's shell, or an inherited BASHOPTS or GLOBIGNORE, that may set
// dotglob, or a home this process cannot read.
func actionShellProfileMayDotglob(home string) bool {
	if _, err := pathStat(home); err != nil || strings.Contains(os.Getenv("BASHOPTS"), "dotglob") || os.Getenv("GLOBIGNORE") != "" {
		return true
	}
	files := []string{"/etc/profile", "/etc/bashrc", "/etc/bash.bashrc", "/etc/zshenv", "/etc/zsh/zshenv",
		"/etc/zprofile", "/etc/zsh/zprofile", "/etc/zshrc", "/etc/zsh/zshrc", "/etc/zlogin", "/etc/zsh/zlogin"}
	if profiles, err := filepath.Glob("/etc/profile.d/*.sh"); err == nil {
		files = append(files, profiles...)
	}
	for _, name := range []string{".bashrc", ".bash_profile", ".bash_login", ".bash_aliases", ".profile", ".zshenv", ".zprofile", ".zshrc", ".zlogin"} {
		files = append(files, filepath.Join(home, name))
	}
	for _, name := range files {
		file, err := pathOpen(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return true
		}
		data, err := io.ReadAll(io.LimitReader(file, 1<<20))
		_ = file.Close()
		if err != nil || actionDotglobSettingIn(strings.ReplaceAll(strings.ToLower(string(data)), "_", "")) {
			return true
		}
	}
	return false
}

// maxGlobFacts bounds the patterns the hook client expands for one call. A
// pattern past it has no answer, so the gateway keeps its fallback.
const maxGlobFacts = 32

func (g *actionGlobs) recording() bool { return g != nil && g.record != nil }

func (g *actionGlobs) full() bool { return g.recording() && len(g.record) >= maxGlobFacts }

// note records the client's answer: "1" when a match reaches a protected
// file, "0" when its walk was complete and no match does.
func (g *actionGlobs) note(pattern, answer string) {
	if !g.recording() || len(GlobFactPrefix)+len(pattern) > MaxWriteTargetPathBytes {
		return
	}
	if key := GlobFactPrefix + pattern; g.record[key] != "1" {
		g.record[key] = answer
	}
}

// fromClient reports a scan that carries the hook client's evidence, so a
// pattern it sent no answer for is one its own walk could not prove.
func (g *actionGlobs) fromClient() bool { return g != nil && g.facts != nil }

func (g *actionGlobs) answer(pattern string) string {
	if g == nil || g.facts == nil {
		return ""
	}
	return g.facts[GlobFactPrefix+pattern]
}

// actionGlobFacts expands, as the user, each pathname pattern the action
// target scan of command checks, and returns the answers for the gateway.
func actionGlobFacts(command, cwd, home string) map[string]string {
	// A pathname pattern needs a glob metacharacter or an expansion that
	// can produce one. Fixed brace ranges alone cannot add a glob.
	if !strings.ContainsAny(command, "*?[$`") {
		return nil
	}
	globs := &actionGlobs{record: map[string]string{}}
	actionProtectedTargetMentionDepth(command, cwd, home, 0, false, globs)
	return globs.record
}

// Bounds of actionExpandGlob: directories read and names kept per step.
const (
	actionGlobMaxReads = 64
	actionGlobMaxNames = 4096
	// actionGlobMaxEntries bounds the names one expansion reads in all.
	actionGlobMaxEntries = 1 << 18
)

// actionExpandGlob lists the existing names an absolute pattern selects. A
// literal component is joined without a lookup, so a final file that does
// not exist yet is still a candidate; literal is a prefix of pattern taken
// as written (the cwd of a relative word). complete is false when a bound
// is exceeded or a directory cannot be read; unseen tells the latter. The
// walk keeps every match it found before or beside a directory it could not
// read or past a bound, so such a directory never hides a match (GAP-1481).
//
// userView is set when the process runs as the home's owner (a per-user
// gateway or the hook client): a directory it may not list is one the
// user's shell may not list either, so it holds no match.
//
// hidden is set when the process cannot see the request's cwd or home
// (systemd ProtectHome on a managed gateway): a directory missing from
// that view is not proof the user's shell finds no match (GAP-1460).
//
// A component that starts with * or ? does not match a name with a leading
// dot, as in the shell, unless dots reports a setting that changes that.
func actionExpandGlob(pattern, literal string, hidden, userView bool, dots func() bool) (candidates []string, complete, unseen bool) {
	separator := string(filepath.Separator)
	start := filepath.VolumeName(pattern) + separator
	rest := strings.TrimPrefix(pattern, start)
	if literal != "" && strings.HasPrefix(pattern, literal+separator) {
		start, rest = literal, pattern[len(literal)+1:]
	}
	paths := []string{start}
	reads := 0
	// entries counts the names read from every folder of this expansion.
	entries := 0
	complete = true
	for _, component := range strings.Split(rest, separator) {
		if component == "" {
			continue
		}
		if !strings.ContainsAny(component, "*?[") {
			for i := range paths {
				paths[i] = filepath.Join(paths[i], component)
			}
			continue
		}
		var next []string
		for _, dir := range paths {
			if reads++; reads > actionGlobMaxReads || len(next) >= actionGlobMaxNames {
				complete = false
				break
			}
			directory, err := actionGlobOpenDir(dir)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) && !hidden || errors.Is(err, syscall.ENOTDIR) || actionGlobInvalidName(err) {
					continue
				}
				// A file the previous component matched that cannot be
				// opened (NTUSER.DAT, which Windows holds open in a profile)
				// has no entries either (rel-1-0-6:GAP-0211).
				if !hidden && actionGlobNotDirectory(dir, err) {
					continue
				}
				// A process that runs as the user cannot list what the
				// user's shell cannot list: the shell expands nothing there
				// (GAP-1739). Nor can any account list a Windows folder
				// that denies listing to Everyone (rel-1-0-6:GAP-0211).
				if errors.Is(err, fs.ErrPermission) && (userView || actionGlobDirDeniesEveryoneList(dir)) {
					continue
				}
				// Permission denied, or a home this process cannot see:
				// the user's shell may still expand the pattern there.
				// The siblings are still read.
				complete, unseen = false, true
				continue
			}
			// The directory is read in chunks and matched as it streams, so
			// a busy folder (/tmp, a build cache, node_modules: tens of
			// thousands of names) is expanded like any other. Only a folder
			// past the total read budget is unproved; the old bound counted
			// the folder's names, not the matches, and made every pattern in
			// a folder of more than 4096 names an authorized-keys block
			// (rel-1-0-10:GAP-0018).
			var matched []string
			for {
				chunk, chunkErr := directory.Readdirnames(actionGlobMaxNames)
				entries += len(chunk)
				for _, name := range chunk {
					if actionGlobNameMatch(component, name) && !actionGlobSkipsDotName(component, name, dots) {
						matched = append(matched, name)
					}
				}
				if chunkErr != nil {
					err = chunkErr
					break
				}
				if len(chunk) == 0 || entries > actionGlobMaxEntries {
					break
				}
			}
			_ = directory.Close()
			if err != nil && err != io.EOF && actionGlobNotDirectory(dir, err) {
				// A file the previous component matched has no entries;
				// the shell skips it (*/* in a project with files).
				continue
			}
			if err != nil && err != io.EOF || entries > actionGlobMaxEntries {
				complete = false
			}
			for _, name := range matched {
				next = append(next, filepath.Join(dir, name))
			}
		}
		if len(next) == 0 {
			return nil, complete, unseen
		}
		paths = next
	}
	return paths, complete, unseen
}

// actionGlobOpenDir opens a directory the walk lists. Windows refuses a
// name that holds a character its file names cannot hold (", <, >, |, :
// past the volume, a control character) with ERROR_INVALID_NAME. Git Bash
// (MSYS/Cygwin) stores such a character as U+F000 plus its code, so the
// shell's own expansion reads that spelling: it is tried before the walk
// concludes that the name names no directory (GAP-0781 RV7-1).
func actionGlobOpenDir(dir string) (*os.File, error) {
	directory, err := pathOpen(dir)
	if err == nil || !actionGlobInvalidName(err) {
		return directory, err
	}
	if mapped := actionMSYSMappedPath(dir); mapped != dir {
		if alias, mappedErr := pathOpen(mapped); mappedErr == nil || !errors.Is(mappedErr, fs.ErrNotExist) && !actionGlobInvalidName(mappedErr) {
			return alias, mappedErr
		}
	}
	return nil, err
}

// actionGlobInvalidName reports a Windows refusal of the name itself
// (ERROR_INVALID_NAME): no file or directory can have it, so the user's
// shell expands nothing there either. Such a word is program text that a
// mention scan split at a slash (glob.glob("data/*.csv"), "src"/*.py),
// not a directory that this process failed to see.
func actionGlobInvalidName(err error) bool {
	const errorInvalidName = syscall.Errno(123)
	return runtime.GOOS == "windows" && errors.Is(err, errorInvalidName)
}

// actionMSYSMappedPath spells the components after the volume the way
// Cygwin and MSYS store the characters Windows names cannot hold.
func actionMSYSMappedPath(dir string) string {
	volume := filepath.VolumeName(dir)
	var b strings.Builder
	b.WriteString(volume)
	for _, r := range dir[len(volume):] {
		if r < 0x20 || strings.ContainsRune(`"*:<>?|`, r) {
			r += 0xF000
		}
		b.WriteRune(r)
	}
	return b.String()
}

// actionGlobNotDirectory reports that a listing failed because dir, or the
// file a link there names, is not a directory.
func actionGlobNotDirectory(dir string, err error) bool {
	if errors.Is(err, syscall.ENOTDIR) {
		return true
	}
	info, statErr := pathStat(dir)
	return statErr == nil && !info.IsDir()
}

// actionGlobHasLiteral reports whether a pattern component keeps a literal
// character outside *, ? and bracket expressions.
func actionGlobHasLiteral(component string) bool {
	for i := 0; i < len(component); i++ {
		switch component[i] {
		case '*', '?':
		case '\\':
			return true
		case '[':
			if end := strings.IndexByte(component[i+1:], ']'); end >= 0 {
				i += end + 1
				continue
			}
			return true
		default:
			return true
		}
	}
	return false
}

// actionGlobViewHidden reports whether this process cannot see the cwd or
// the home the hook reported, as a managed gateway behind ProtectHome.
func actionGlobViewHidden(cwd, home string) bool {
	for _, dir := range []string{cwd, home} {
		if dir == "" {
			continue
		}
		if _, err := pathStat(dir); err != nil {
			return true
		}
	}
	return false
}

// actionGlobSkipsDotName reports a leading-dot name that the shell's * or ?
// does not match. A bracket stays a match: the walk keeps the doubt.
func actionGlobSkipsDotName(component, name string, dots func() bool) bool {
	return strings.HasPrefix(name, ".") &&
		(strings.HasPrefix(component, "*") || strings.HasPrefix(component, "?")) && !dots()
}

// actionGlobNameMatch matches one name component; names compare without case
// on macOS and Windows, whose file systems usually ignore it.
func actionGlobNameMatch(pattern, name string) bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	}
	matched, _ := filepath.Match(pattern, name)
	return matched
}

func actionPosixWindowsStatePath(value, cwd, home string) bool {
	resolved := actionPosixWindowsPath(value, cwd, home)
	return actionProtectedStateRelative(strings.TrimPrefix(resolved, path.Clean(home)+"/"))
}

// State protection is scoped to the active home and the security-state names
// owned by the semantic detector. Project-local .defenseclaw files and the
// product's diagnostic logs are ordinary work.
func actionProtectedStateRelative(relative string) bool {
	if !strings.HasPrefix(relative, ".defenseclaw/") {
		return false
	}
	state := strings.TrimPrefix(relative, ".defenseclaw/")
	if slices.Contains(activeStateFiles, state) {
		return true
	}
	for _, tree := range activeStateTrees {
		if strings.HasPrefix(state, tree+"/") && len(state) > len(tree)+1 {
			return true
		}
	}
	return false
}

// activeStateFiles and activeStateTrees are the active security state under
// .defenseclaw. The trees are listed in the order the identity index visits
// them: hooks and policies first, the large scan cache last. The saved
// installer and its previous copy are active state (GAP-1099, instr-protect).
var (
	activeStateFiles = []string{
		".env", "config.yaml", "confidence_policy.yaml", "guardrail_runtime.json",
		"device.key", "picked_connector", "custom-providers.json", "audit.db",
		"audit.db-wal", "audit.db-shm", "judge.db", "judge.db-wal",
		"judge.db-shm", "judge_bodies.db", "judge_bodies.db-wal", "judge_bodies.db-shm",
	}
	activeStateTrees = []string{"hooks", "policies", "installer", "previous/installer", "registries", "receipts", "quarantine", "cache"}
)

// writeTargetWalks counts write-target resolutions, so a test can prove a
// long command resolves each distinct word once (GAP-2279).
var writeTargetWalks atomic.Int64

// actionStateHome resolves the home of one target scan once: every word of
// a long command is placed against the same home (GAP-2279, answer budget).
type actionStateHome struct {
	home     string
	resolved string
	ok, done bool
	// memo, when set, answers the walks of this scan (TargetMemo).
	memo *TargetMemo
}

func (h *actionStateHome) active() (string, bool) {
	if !h.done {
		h.resolved, h.ok = h.memo.resolveWriteTarget(h.home)
		h.done = true
	}
	return h.resolved, h.ok
}

func actionProtectedStatePath(value string, home *actionStateHome) bool {
	resolved, ok := home.memo.resolveWriteTarget(value)
	if !ok {
		return false
	}
	activeHome, ok := home.active()
	if !ok {
		return false
	}
	relative, err := filepath.Rel(activeHome, resolved)
	if err == nil && actionProtectedStateRelative(filepath.ToSlash(relative)) {
		return true
	}
	// The entry itself is state even when it is a link the user made to a
	// file elsewhere: a move or rename onto it replaces the state entry.
	// Its directory is followed and its name kept, so mv a.txt /ext/y/
	// config.yaml with y -> ~/.defenseclaw names the entry when config.yaml
	// links out of the tree, as it does when config.yaml is a file (GAP-2560).
	differ, missing := actionStateEntryMayDiffer(value)
	if differ {
		if name := filepath.Base(value); name != "." && name != ".." && name != string(filepath.Separator) {
			if parent, ok := home.memo.resolveWriteTarget(filepath.Dir(value)); ok {
				relative, err := filepath.Rel(activeHome, filepath.Join(parent, name))
				if err == nil && actionProtectedStateRelative(filepath.ToSlash(relative)) {
					return true
				}
			}
		}
	}
	// Only an existing regular file with a second link can alias the state.
	// A missing entry costs no further read (its Lstat above told), an
	// ordinary target one stat here, not a second walk (GAP-1075).
	if missing {
		return false
	}
	info, err := pathStat(resolved)
	if err != nil || !info.Mode().IsRegular() || linkCount(resolved, info) < 2 {
		return false
	}
	_, same := ResolveActiveStateHardlinkTarget(resolved, home.home)
	return same
}

// ResolveActiveStateHardlinkTarget maps an existing write target back to an
// active DefenseClaw state file with the same file identity. Ordinary aliases
// have one link and avoid the index; a multiply linked target is compared
// with the bounded, shared index of the active state files.
func ResolveActiveStateHardlinkTarget(value, home string) (string, bool) {
	resolved, ok := ResolveWriteTarget(value)
	if !ok {
		return "", false
	}
	info, err := pathStat(resolved)
	if err != nil || !info.Mode().IsRegular() || linkCount(resolved, info) < 2 {
		return "", false
	}
	activeRoot, ok := ResolveWriteTarget(filepath.Join(home, ".defenseclaw"))
	if !ok {
		return "", false
	}
	for _, file := range activeStateIdentities(activeRoot) {
		if !os.SameFile(info, file.info) {
			continue
		}
		// The index can be up to activeStateIndexTTL old: confirm the name
		// still holds this file before mapping the alias to it.
		path := filepath.Join(activeRoot, filepath.FromSlash(file.relative))
		if current, err := pathStat(path); err == nil && os.SameFile(info, current) {
			return filepath.Join(home, ".defenseclaw", filepath.FromSlash(file.relative)), true
		}
	}
	return "", false
}

// The identity index of one active state tree is built at most once per
// activeStateIndexTTL and shared by every shell operand and request in that
// time, so a command naming many ordinary hard links costs one bounded walk.
// The walk stops after activeStateIndexEntries entries or activeStateIndexBudget,
// well inside every hook deadline; a file it did not reach is not mapped (no
// block), which never refuses ordinary shell work. A native patch target is
// judged by ResolveActiveStateIdentity instead, which neither caches nor
// treats an unfinished walk as an answer (GAP-0488, GAP-0073).
var (
	activeStateIndexEntries = 4096
	activeStateIndexBudget  = 250 * time.Millisecond
	activeStateIndexTTL     = 2 * time.Second
	activeStateIndexWalks   atomic.Int64
	activeStateIndex        struct {
		sync.Mutex
		byRoot map[string]activeStateIdentityIndex
	}
	// The identity walk of a patch target has no entry bound and a time bound
	// only: it runs for an existing multiply linked target, never answers
	// from a partial view, and a state too large to read in the time is not
	// proved.
	activeStateExactBudget = 2 * time.Second
)

type activeStateIdentity struct {
	relative string
	info     os.FileInfo
}

type activeStateIdentityIndex struct {
	built time.Time
	files []activeStateIdentity
}

func activeStateIdentities(activeRoot string) []activeStateIdentity {
	activeStateIndex.Lock()
	defer activeStateIndex.Unlock()
	now := time.Now()
	if index, ok := activeStateIndex.byRoot[activeRoot]; ok && now.Sub(index.built) < activeStateIndexTTL {
		return index.files
	}
	for root, index := range activeStateIndex.byRoot {
		if now.Sub(index.built) >= activeStateIndexTTL {
			delete(activeStateIndex.byRoot, root)
		}
	}
	if activeStateIndex.byRoot == nil {
		activeStateIndex.byRoot = make(map[string]activeStateIdentityIndex)
	}
	activeStateIndexWalks.Add(1)
	var files []activeStateIdentity
	walkActiveStateFiles(activeRoot, activeStateIndexEntries, now.Add(activeStateIndexBudget), func(relative string, info os.FileInfo) bool {
		files = append(files, activeStateIdentity{relative: relative, info: info})
		return false
	})
	activeStateIndex.byRoot[activeRoot] = activeStateIdentityIndex{built: now, files: files}
	return files
}

// ResolveActiveStateIdentity reports whether resolved, an existing write
// target the caller has already resolved, is by file identity a file of the
// active DefenseClaw state, and which one. It answers from the whole state,
// read again whenever any directory of it changed (activeStateViewOf), and
// only for a regular file with a second link: any other target cannot alias a
// state file and costs one stat. complete is false when the view could not
// see all of the state before it found the file (a directory it could not
// list, a name it could not stat, or the time bound). What it did not see is
// unknown, and a caller that would otherwise allow must treat that as not
// proved (GAP-0488, GAP-0073).
func ResolveActiveStateIdentity(resolved, home string) (state string, same, complete bool) {
	info, err := pathStat(resolved)
	if err != nil || !info.Mode().IsRegular() || linkCount(resolved, info) < 2 {
		return "", false, true
	}
	activeRoot := filepath.Join(home, ".defenseclaw")
	files, complete := activeStateViewOf(activeRoot)
	for _, file := range files {
		if os.SameFile(info, file.info) {
			return filepath.Join(activeRoot, filepath.FromSlash(file.relative)), true, true
		}
	}
	return "", false, complete
}

// The view of the active state is the regular files of the tree and the
// fingerprint (identity, modification and change time) of every directory and
// link that led to them. A view is kept in memory only when it is complete,
// small, and every fingerprint is older than activeStateViewGuard when the
// walk began: a later change to a directory then moves its change time, which
// no one can set back, so a view whose fingerprints are all unchanged is the
// state as it is now. A directory changed within the guard, a platform
// without change times and a large tree are walked again on every call. The
// hook is a short-lived process, so the kept view serves the reads of one
// call (the proof, the read after the answer, the read after it is written).
const (
	activeStateViewGuard   = 50 * time.Millisecond
	activeStateViewFiles   = 4096
	activeStateViewWatches = 256
)

var activeStateViews struct {
	sync.Mutex
	byRoot map[string]activeStateView
}

type activeStateView struct {
	files   []activeStateIdentity
	watches []activeStateWatch
}

// activeStateWatch is the fingerprint of one path of the walk: info is nil
// for a path that was absent.
type activeStateWatch struct {
	path string
	info os.FileInfo
}

func activeStateViewOf(activeRoot string) (files []activeStateIdentity, complete bool) {
	activeStateViews.Lock()
	view, kept := activeStateViews.byRoot[activeRoot]
	activeStateViews.Unlock()
	if kept {
		if view.unchanged() {
			return view.files, true
		}
		activeStateViews.Lock()
		delete(activeStateViews.byRoot, activeRoot)
		activeStateViews.Unlock()
	}
	started := time.Now()
	settleLimit := activeStateSettleLimit(started)
	walk := &activeStateWalk{
		limit:    math.MaxInt,
		deadline: started.Add(activeStateExactBudget),
		record:   true,
		visit: func(relative string, info os.FileInfo) bool {
			files = append(files, activeStateIdentity{relative: relative, info: info})
			return false
		},
	}
	complete = walk.run(activeRoot)
	if complete && len(files) <= activeStateViewFiles && len(walk.watches) <= activeStateViewWatches && walk.settledBefore(settleLimit) {
		activeStateViews.Lock()
		if activeStateViews.byRoot == nil || len(activeStateViews.byRoot) >= 4 {
			activeStateViews.byRoot = make(map[string]activeStateView)
		}
		activeStateViews.byRoot[activeRoot] = activeStateView{files: files, watches: walk.watches}
		activeStateViews.Unlock()
	}
	return files, complete
}

// activeStateSettleLimit is the instant every fingerprint of a kept view must
// precede. Where the kernel stamps changes from a clock the process can read
// (filesystemClockNow) it is that clock present tick: a path stamped in an
// earlier tick gets a later stamp when it changes again, whatever the delay,
// so the view cannot miss the change. Elsewhere it is the walk start less
// activeStateViewGuard. It is read before the walk, so a path changed after it
// is never kept.
func activeStateSettleLimit(started time.Time) time.Time {
	if tick, ok := filesystemClockNow(); ok && tick.Before(started) {
		return tick
	}
	return started.Add(-activeStateViewGuard)
}

// unchanged reports that every path of the view reads as it did.
func (v activeStateView) unchanged() bool {
	for _, watch := range v.watches {
		now, err := pathStat(watch.path)
		if watch.info == nil {
			if err == nil || !activeStateNameAbsent(err) {
				return false
			}
			continue
		}
		if err != nil || !os.SameFile(watch.info, now) || !watch.info.ModTime().Equal(now.ModTime()) {
			return false
		}
		before, beforeOK := statChangeTime(watch.info)
		after, afterOK := statChangeTime(now)
		if !beforeOK || !afterOK || !before.Equal(after) {
			return false
		}
	}
	return true
}

// maxActiveStateDepth bounds the directories one walk descends into, so a
// link loop in the state ends the walk as not proved instead of running it.
const maxActiveStateDepth = 64

// activeStateWalk is one pass over the regular files of the active state.
type activeStateWalk struct {
	limit    int
	deadline time.Time
	visit    func(relative string, info os.FileInfo) bool
	record   bool // keep the fingerprint of every directory and link read
	watches  []activeStateWatch
	visited  int
	stopped  bool          // visit accepted a file
	over     bool          // the entry or time bound was reached
	partial  bool          // some of the state could not be seen
	linked   []os.FileInfo // directories reached through a link, walked once
}

// walkActiveStateFiles visits the regular files of the active state in the
// order of activeStateFiles and activeStateTrees until visit returns true. A
// link to a directory is followed. It reports whether the view was complete:
// false when it stopped at the entry or time bound, or could not list a
// directory or stat a name, so what it did not see is unknown.
func walkActiveStateFiles(activeRoot string, limit int, deadline time.Time, visit func(relative string, info os.FileInfo) bool) (complete bool) {
	return (&activeStateWalk{limit: limit, deadline: deadline, visit: visit}).run(activeRoot)
}

func (w *activeStateWalk) run(activeRoot string) (complete bool) {
	w.watch(activeRoot)
	for _, name := range activeStateFiles {
		if w.file(filepath.Join(activeRoot, name), name, 0); w.stopped {
			return true
		}
	}
	for _, tree := range activeStateTrees {
		path := filepath.Join(activeRoot, filepath.FromSlash(tree))
		if parent := filepath.Dir(path); parent != activeRoot {
			w.watch(parent)
		}
		if w.directory(path, tree, 0); w.stopped {
			return true
		}
	}
	return !w.partial
}

// watch keeps the fingerprint of path when the walk records them.
func (w *activeStateWalk) watch(path string) {
	if !w.record {
		return
	}
	info, err := pathStat(path)
	w.keep(path, info, err)
}

func (w *activeStateWalk) keep(path string, info os.FileInfo, err error) {
	switch {
	case !w.record:
	case err == nil:
		w.watches = append(w.watches, activeStateWatch{path: path, info: info})
	case activeStateNameAbsent(err):
		w.watches = append(w.watches, activeStateWatch{path: path})
	default:
		w.partial = true
	}
}

// settledBefore reports that every fingerprint kept is of a path last changed
// before limit, with a change time the platform reports.
func (w *activeStateWalk) settledBefore(limit time.Time) bool {
	for _, watch := range w.watches {
		if watch.info == nil {
			continue
		}
		changed, ok := statChangeTime(watch.info)
		if !ok || !changed.Before(limit) || !watch.info.ModTime().Before(limit) {
			return false
		}
	}
	return true
}

// enter counts one entry against the bounds.
func (w *activeStateWalk) enter() bool {
	if w.over || w.stopped {
		return false
	}
	w.visited++
	if w.visited > w.limit || time.Now().After(w.deadline) {
		w.over, w.partial = true, true
		return false
	}
	return true
}

func (w *activeStateWalk) file(path, relative string, depth int) {
	if !w.enter() {
		return
	}
	info, err := pathLstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		// A link is state where it leads, so it is read again with the view.
		info, err = pathStat(path)
		w.keep(path, info, err)
	}
	switch {
	case err != nil:
		if !activeStateNameAbsent(err) {
			w.partial = true
		}
	case info.IsDir():
		for _, seen := range w.linked {
			if os.SameFile(seen, info) {
				return
			}
		}
		w.linked = append(w.linked, info)
		w.directory(path, relative, depth+1)
	case info.Mode().IsRegular():
		if w.visit(relative, info) {
			w.stopped = true
		}
	}
}

func (w *activeStateWalk) directory(path, relative string, depth int) {
	if depth > maxActiveStateDepth {
		w.partial = true
		return
	}
	// The fingerprint is taken before the listing: a change after it moves it.
	w.watch(path)
	// Whatever a failed listing returned is still visited: a file found in it
	// is a positive answer, and the failure makes the rest unknown.
	entries, err := pathReadDir(path)
	if err != nil && !activeStateNameAbsent(err) {
		w.partial = true
	}
	for _, entry := range entries {
		// path is clean and a listed name holds no separator, so joining by
		// hand reads the same path as filepath.Join without cleaning it.
		child, name := path+string(filepath.Separator)+entry.Name(), relative+"/"+entry.Name()
		if entry.IsDir() {
			if w.enter() {
				w.directory(child, name, depth+1)
			}
		} else {
			w.file(child, name, depth)
		}
		if w.over || w.stopped {
			return
		}
	}
}

// activeStateNameAbsent reports an error that says no file is there: a name
// that does not exist, a parent that is no directory, or a link loop. Any
// other error (permission, I/O, a network share) leaves the name unknown.
func activeStateNameAbsent(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP)
}

// actionPosixNestedShellMention scans each static shell -c or env -S body as
// its own command. bodies are the words it scanned without a match.
func actionPosixNestedShellMention(file *syntax.File, cwd, home string, depth int, stateOnly bool, globs *actionGlobs) (bodies []*syntax.Word, found bool) {
	if depth+1 >= 8 {
		return nil, false
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		for i, word := range call.Args {
			program, static := staticProgramWord(word, home)
			if !static {
				continue
			}
			base := programBase(program)
			if base == "env" {
				for j := i + 1; j+1 < len(call.Args); j++ {
					option, optionStatic := StaticWord(call.Args[j], home)
					if !optionStatic || option != "-S" && option != "--split-string" {
						continue
					}
					if child, childStatic := StaticWord(call.Args[j+1], home); childStatic {
						if actionPosixShellBodyMention(child, cwd, home, depth+1, stateOnly, globs) {
							found = true
							return false
						}
						bodies = append(bodies, call.Args[j+1])
					}
				}
			}
			if base == "pwsh" || base == "powershell" {
				// pwsh -Command "<body>" on a POSIX home: a body that only
				// prints (Write-Output, Write-Host, echo) or runs a read-only
				// git command passes a quoted ~ as text, as the same body does
				// on its own (GAP-1473). Any other body keeps the whole-text
				// reading, where a quoted ~ names the home.
				if j, ok := actionPowerShellCommandBodyIndex(call.Args, i, home); ok {
					if child, childStatic := StaticWord(call.Args[j], home); childStatic &&
						actionPowerShellPrintOnlyBody(child, home) {
						if actionProtectedTargetMentionDepth(child, cwd, home, depth+1, stateOnly, globs) {
							found = true
							return false
						}
						bodies = append(bodies, call.Args[j])
					}
				}
				continue
			}
			if !posixShellProgram(base) && base != "ash" {
				continue
			}
			for j := i + 1; j+1 < len(call.Args); j++ {
				option, static := StaticWord(call.Args[j], home)
				if !static || !strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "+") {
					break
				}
				switch option {
				case "-o", "+o", "-O", "+O", "--rcfile", "--init-file":
					j++ // This option consumes the next word (bash -O dotglob -c).
					continue
				}
				if option == "-c" || len(option) > 2 && !strings.HasPrefix(option, "--") &&
					!strings.ContainsAny(option, "=/") && strings.Contains(option[1:], "c") {
					if child, static := StaticWord(call.Args[j+1], home); static {
						if actionPosixShellBodyMention(child, cwd, home, depth+1, stateOnly, globs) {
							found = true
						} else {
							bodies = append(bodies, call.Args[j+1])
						}
					}
					break
				}
			}
		}
		return !found
	})
	return bodies, found
}

// actionPosixShellBodyMention reads the body of a POSIX shell (sh -c, env
// -S) the POSIX reading meets. On a native Windows host that shell is Git
// Bash: a body the POSIX grammar reads alone is read with it, as the shell
// runs it (GAP-1717); any other body keeps every reading.
func actionPosixShellBodyMention(child, cwd, home string, depth int, stateOnly bool, globs *actionGlobs) bool {
	if depth < 8 && actionGitBashReadsAlone(child, home, actionfacts.DialectPOSIX) {
		return actionPosixTargetMention(child, cwd, home, depth, stateOnly, globs)
	}
	return actionProtectedTargetMentionDepth(child, cwd, home, depth, stateOnly, globs)
}

// actionPowerShellCommandBodyIndex returns the index of the -Command body
// of a pwsh or powershell call whose program word is args[at]: only the
// switches that do not change what the body runs may come first (-NoProfile,
// -NoLogo, -NonInteractive, -ExecutionPolicy <policy>), and the body must be
// the last word.
func actionPowerShellCommandBodyIndex(args []*syntax.Word, at int, home string) (int, bool) {
	for j := at + 1; j < len(args); j++ {
		option, static := StaticWord(args[j], home)
		if !static {
			return 0, false
		}
		switch strings.ToLower(option) {
		case "-noprofile", "-nop", "-nologo", "-nol", "-noninteractive", "-noni":
			continue
		case "-executionpolicy", "-ep", "-ex":
			j++
			continue
		case "-command", "-c":
			return j + 1, j+2 == len(args)
		}
		return 0, false
	}
	return 0, false
}

// actionPowerShellPrintOnlyBody reports a PowerShell -Command body, read as
// shell words, whose every command prints its arguments (Write-Output,
// Write-Host, echo) or is a read-only git command (actionLiteralGitWords),
// with no redirect, assignment, function or process substitution. PowerShell
// passes a quoted ~ to them as text; a cmdlet path parameter resolves it.
func actionPowerShellPrintOnlyBody(body, home string) bool {
	file, parsed := parseShell(body)
	if !parsed {
		return false
	}
	printOnly, calls := true, 0
	syntax.Walk(file, func(node syntax.Node) bool {
		if !printOnly {
			return false
		}
		switch node := node.(type) {
		case *syntax.FuncDecl, *syntax.ProcSubst, *syntax.CoprocClause, *syntax.DeclClause, *syntax.Redirect:
			printOnly = false
			return false
		case *syntax.CallExpr:
			if len(node.Assigns) != 0 || len(node.Args) == 0 {
				printOnly = false
				return false
			}
			calls++
			program, static := staticProgramWord(node.Args[0], home)
			if !static {
				printOnly = false
				return false
			}
			switch programBase(program) {
			case "write-output", "write-host", "echo":
			case "git":
				printOnly = actionLiteralGitWords(node.Args[1:], home)
			default:
				printOnly = false
			}
		}
		return printOnly
	})
	return printOnly && calls > 0
}

// actionBlankWords replaces the bytes of each word with spaces.
func actionBlankWords(text string, words []*syntax.Word) string {
	if len(words) == 0 {
		return text
	}
	out := []byte(text)
	for _, word := range words {
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if start < 0 || end > len(out) || start >= end {
			continue
		}
		for i := start; i < end; i++ {
			out[i] = ' '
		}
	}
	return string(out)
}

// actionBlankComments replaces with spaces each comment of command that the
// shell parser finds: a # that starts a word, up to the end of its line. A
// quoted or escaped #, or one inside a word, starts no comment, and a
// here-document body is not one. text is a same-length view of command;
// a command the parser cannot read keeps every byte.
func actionBlankComments(text, command string) string {
	if len(text) != len(command) || !strings.Contains(command, "#") {
		return text
	}
	file, ok := shellparse.ParseWithComments(command)
	if !ok {
		return text
	}
	out := []byte(text)
	syntax.Walk(file, func(node syntax.Node) bool {
		comment, ok := node.(*syntax.Comment)
		if !ok {
			return true
		}
		start := int(comment.Hash.Offset())
		end := start + 1 + len(comment.Text)
		if start < 0 || end > len(out) || out[start] != '#' || !actionPosixCommentStarts(command, start) {
			return true
		}
		for i := start; i < end; i++ {
			out[i] = ' '
		}
		return true
	})
	return string(out)
}

// actionPosixCommentStarts reports a # at i that bash itself reads as the
// start of a comment: at the start of the command or after a blank, a line
// end or an operator character, and not after an escaped character (an
// escaped blank or operator is word text, a backslash-newline joins the
// lines). The parser also skips a carriage return as a blank, but bash keeps it in the word,
// so a # after it is word text and what follows on the line still runs
// (the GAP-1982 corpus row G02).
func actionPosixCommentStarts(command string, i int) bool {
	if i == 0 {
		return true
	}
	if strings.IndexByte(" \t\n;&|()<>", command[i-1]) < 0 {
		return false
	}
	return i < 2 || command[i-2] != '\\'
}

// Quoted or escaped dollar signs and glob characters do not expand in the
// outer shell. Nested shell bodies are checked separately above.
func actionMaskLiteralMetacharacters(command string) string {
	var masked strings.Builder
	masked.Grow(len(command))
	var quote byte
	escaped := false
	for i := 0; i < len(command); i++ {
		c := command[i]
		escapedNow := escaped
		switch {
		case escaped:
			escaped = false
		case c == '\\' && quote != '\'':
			escaped = true
		case c == '\'' && quote == 0:
			quote = '\''
		case c == '\'' && quote == '\'':
			quote = 0
		case c == '"' && quote == 0:
			quote = '"'
		case c == '"' && quote == '"':
			quote = 0
		}
		if c == '$' && (escapedNow || quote == '\'') ||
			strings.ContainsRune("*?[]", rune(c)) && (escapedNow || quote != 0) {
			masked.WriteByte('@')
		} else {
			masked.WriteByte(c)
		}
	}
	return masked.String()
}

func actionWordHasUnquotedGlob(word *syntax.Word, command string) bool {
	start, end := int(word.Pos().Offset()), int(word.End().Offset())
	return start >= 0 && end <= len(command) && start < end &&
		strings.ContainsAny(actionMaskLiteralMetacharacters(command[start:end]), "*?[]")
}

func actionKnownReadOnlyShell(file *syntax.File, home string) bool {
	return actionKnownReadOnlyShellDepth(file, home, 0)
}

func actionKnownReadOnlyShellDepth(file *syntax.File, home string, depth int) bool {
	return actionKnownReadOnlyShellMode(file, home, depth, false)
}

// actionKnownReadOnlyShellMode is actionKnownReadOnlyShellDepth; bodies also
// reads a shell given a literal -c body and an ssh remote command as the
// readers they run, one level deeper. The whole-command rule keeps its
// stricter reading (TestR104StructuralProtectedNamedPOSIX pins sh -c cat
// KEYS as a protected-target); ActionMentionsNoWriteRole asks the wider one.
func actionKnownReadOnlyShellMode(file *syntax.File, home string, depth int, bodies bool) bool {
	if depth >= 8 {
		return false
	}
	seen, safe := false, true
	status := map[string]bool{"?": true}
	neutral := actionFixedTextEchoes(file)
	syntax.Walk(file, func(node syntax.Node) bool {
		if !safe {
			return false
		}
		switch node := node.(type) {
		case *syntax.Redirect:
			// Output sent to /dev/null, or a descriptor copy such as 2>&1,
			// writes no file (rel-1-0-6:GAP-0160).
			if !actionDiscardRedirect(node, home) {
				safe = false
			}
			return false
		case *syntax.FuncDecl, *syntax.DeclClause:
			safe = false
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		if neutral[call] {
			return false
		}
		if len(call.Args) == 0 && actionExitStatusAssignment(call) {
			// status=$? of an agent's exit-status wrapper (GAP-2168).
			for _, assign := range call.Assigns {
				status[assign.Name.Value] = true
			}
			return true
		}
		if len(call.Args) == 0 && len(call.Assigns) != 0 {
			// A fixed scalar assignment does not write a file. It can
			// precede a read-only command such as pat='*'; ls -d $pat.
			for _, assign := range call.Assigns {
				if assign.Name == nil || assign.Append || assign.Array != nil || assign.Index != nil {
					safe = false
					return false
				}
				name := assign.Name.Value
				// Command lookup and shell control variables can change
				// what a later apparent reader actually runs.
				if name == "path" || name == "fpath" || strings.ContainsAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
					safe = false
					return false
				}
				if _, fixed := StaticWord(assign.Value, home); !fixed {
					safe = false
					return false
				}
			}
			return true
		}
		if len(call.Args) == 0 || len(call.Assigns) != 0 {
			safe = false
			return false
		}
		// A privilege or run wrapper in front of a reader (sudo sha256sum
		// FILE, env LC_ALL=C cmp A B, timeout 5 stat FILE) reads as the
		// reader does; it is the wrapped program that decides.
		if wrapped, ok := actionReadOnlyWrappedCall(call, home); ok {
			call = wrapped
		}
		program, known := staticProgramWord(call.Args[0], home)
		if !known {
			safe = false
			return false
		}
		switch programBase(program) {
		case "echo", "printf", "exit":
			// An agent's exit-status report (Codex: cmd; status=$?; printf
			// '\n[exit status] %s\n' "$status"; exit "$status") prints the
			// status to the terminal only: no redirect (checked above), a $?
			// or status word and no protected name in its text. Any other
			// echo stays outside the read-only list.
			if actionStatusReport(call.Args[1:], status) {
				return true
			}
		}
		seen = true
		for _, arg := range call.Args[1:] {
			if option, known := StaticWord(arg, home); known && actionReadOptionMayWrite(option) {
				safe = false
				return false
			}
		}
		switch programBase(program) {
		case "cat", "head", "tail", "ls", "dir", "stat",
			// Search and count programs only read their operands (owner
			// decision 2, TGT-0194; GAP-2168). So do the size and path
			// readers: du reports sizes, readlink and realpath print a
			// resolved name; none has an output option.
			"grep", "egrep", "fgrep", "wc", "du", "readlink", "realpath",
			// Checksum, compare and attribute readers print or compare what
			// they read and have no output file (sha256sum FILE, cmp A B,
			// lsattr FILE): a call that only names a protected file to one of
			// them is not a write to it (rel-1-0-10:GAP-0018). diff is not on
			// the list: TestHomeSpelledAuthorizedKeysWriteBlocks pins a diff of
			// the keys file as a block.
			"sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "md5sum", "b2sum", "cksum", "shasum",
			"cmp", "lsattr", "getfacl", "namei", "od", "hexdump", "strings", "nl", "cut":
		case "echo":
			// The literal */* operand prints expanded names. Every other
			// statement remains subject to the same read-only walk.
			safe = len(call.Args) == 2 && call.Args[0].Lit() == "echo" && call.Args[1].Lit() == "*/*"
		case "ssh-keygen":
			if !actionSSHKeygenListsOnly(call.Args[1:], home) {
				safe = false
			}
		case "cd", "pushd", "popd":
			if len(call.Args) > 3 {
				safe = false
			}
		case "dirs":
			// dirs prints or clears the directory stack (GAP-2552).
		case "less":
			for _, arg := range call.Args[1:] {
				option, known := StaticWord(arg, home)
				if !known || actionLessWritesFile(option) {
					safe = false
					break
				}
			}
		case "uniq", "tar", "gtar", "bsdtar", "find", "gfind":
			words, known := actionStaticWords(call.Args, home)
			safe = known && actionReadsOnlyWords(words)
		case "pwsh", "powershell":
			// pwsh -Command "Get-ChildItem ~/.ssh" lists names, as ls does
			// (rel-1-0-6:GAP-0145).
			body, static := actionPowerShellCommandBody(call.Args, home)
			safe = static && actionPowerShellListOnlyBody(body, home)
		case "ssh":
			// The remote command line runs on another machine; it is judged
			// as if it ran here, which can only be stricter.
			if body, ok := actionSSHRemoteBody(call, home); ok && bodies && depth+1 < 8 {
				child, parsed := parseShell(body)
				safe = parsed && actionKnownReadOnlyShellMode(child, home, depth+1, bodies)
			} else {
				safe = false
			}
		case "sed":
			safe = actionSedPrintsOnly(call, home)
		default:
			base := programBase(program)
			switch {
			case slices.Contains(actionBodyShells, base):
				// A shell given a literal -c (or -lc) body is read-only when
				// the body it runs is (rel-1-0-10:GAP-0018).
				if body, ok := actionShellBodyOfCall(call, home); ok && bodies && depth+1 < 8 {
					child, parsed := parseShell(body)
					safe = parsed && actionKnownReadOnlyShellMode(child, home, depth+1, bodies)
				} else {
					safe = base == "bash" && actionReadOnlyBashCLaunch(call, home, depth)
				}
			case slices.Contains(actionStateProbePrograms, base):
				// test and [ only report the state of a file (-e, -L, -r, -s).
				safe = true
			case base == actionSearchProgram:
				// ripgrep searches its operands; --pre runs a program on every
				// file it opens.
				safe = true
				for _, arg := range call.Args[1:] {
					option, known := StaticWord(arg, home)
					if !known || slices.ContainsFunc(actionSearchHelperFlags, func(flag string) bool { return strings.HasPrefix(option, flag) }) {
						safe = false
						break
					}
				}
			default:
				safe = false
			}
		}
		return safe
	})
	return seen && safe
}

// actionReadOnlyWrappedCall is the call a sudo, doas, env, nohup, command,
// timeout, nice, stdbuf, ionice or setsid wrapper runs, when the wrapper's
// options are all ones the literal-wrapper reader knows (actionLiteralCommandWords).
// A wrapper that starts a shell (sudo -s, sudo -i) has no wrapped command and
// is not unwrapped; the wrapped program is then judged like any other call,
// and a shell or an unknown program stays outside the read-only list.
func actionReadOnlyWrappedCall(call *syntax.CallExpr, home string) (*syntax.CallExpr, bool) {
	program, known := staticProgramWord(call.Args[0], home)
	if !known {
		return nil, false
	}
	switch programBase(program) {
	case "sudo", "doas", "env", "nohup", "command", "timeout", "nice", "stdbuf", "ionice", "setsid":
	default:
		return nil, false
	}
	words, ok := actionLiteralCommandWords(call.Args, home)
	if !ok || len(words) == 0 || len(words) == len(call.Args) {
		return nil, false
	}
	return &syntax.CallExpr{Args: words}, true
}

// actionCallChangesDirectory reports a cd, pushd or popd call: it reads
// nothing, and the directory it enters decides what the statements after it
// write (cd ~/.ssh && cp a.txt note.txt).
func actionCallChangesDirectory(call *syntax.CallExpr, home string) bool {
	program, known := staticProgramWord(call.Args[0], home)
	if !known {
		return false
	}
	switch programBase(program) {
	case "cd", "pushd", "popd":
		return true
	}
	return false
}

func actionReadOnlyBashCLaunch(call *syntax.CallExpr, home string, depth int) bool {
	if len(call.Assigns) != 0 || len(call.Args) != 3 || depth+1 >= 8 {
		return false
	}
	option, optionKnown := StaticWord(call.Args[1], home)
	if !optionKnown || option != "-c" || !actionBashCLiteralBody(call.Args[2]) {
		return false
	}
	body := actionWordLiteralText(call.Args[2])
	if strings.ContainsAny(body, "$`\\%!^\"'\r\n") {
		// The Windows outer shell can expand variables or escapes before
		// bash receives the body, so only a literal cross-shell body qualifies.
		return false
	}
	child, parsed := parseShell(body)
	return parsed && actionKnownReadOnlyShellDepth(child, home, depth+1)
}

func actionBashCLiteralBody(word *syntax.Word) bool {
	if word == nil || len(word.Parts) != 1 {
		return false
	}
	quoted, ok := word.Parts[0].(*syntax.DblQuoted)
	if !ok {
		return false
	}
	for _, part := range quoted.Parts {
		if _, ok := part.(*syntax.Lit); !ok {
			return false
		}
	}
	return true
}

// actionReadOnlyListingCompound recognizes a directory listing followed by
// working-directory prints or fixed-text markers. Every statement must have
// a read-only proof; other commands continue through the target scan.
func actionReadOnlyListingCompound(file *syntax.File, cwd, home string) bool {
	if file == nil || len(file.Stmts) == 0 || len(file.Stmts) > 128 {
		return false
	}
	var statements []*syntax.Stmt
	var collect func(*syntax.Stmt, int) bool
	collect = func(stmt *syntax.Stmt, depth int) bool {
		if depth > 128 || len(statements) >= 128 || stmt == nil || stmt.Background ||
			stmt.Negated || stmt.Coprocess {
			return false
		}
		if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok {
			return len(stmt.Redirs) == 0 && (pair.Op == syntax.AndStmt || pair.Op == syntax.OrStmt) &&
				collect(pair.X, depth+1) && collect(pair.Y, depth+1)
		}
		statements = append(statements, stmt)
		return true
	}
	for _, stmt := range file.Stmts {
		if !collect(stmt, 0) {
			return false
		}
	}
	if len(statements) < 2 {
		return false
	}
	first := statements[0]
	listing, ok := first.Cmd.(*syntax.CallExpr)
	if !ok || len(listing.Assigns) != 0 || len(listing.Args) == 0 ||
		!actionKnownReadOnlyShell(&syntax.File{Stmts: []*syntax.Stmt{first}}, home) {
		return false
	}
	program, known := staticProgramWord(listing.Args[0], home)
	if !known {
		return false
	}
	switch programBase(program) {
	case "ls":
		ssh := filepath.Join(home, ".ssh")
		found := false
		for _, word := range listing.Args[1:] {
			value, known := actionWordValue(word, actionValues{"HOME": home}, cwd, home)
			if known && samePathName(filepath.Clean(OperandPath(value, cwd)), ssh) {
				found = true
			}
		}
		if !found {
			return false
		}
	case "head":
		if len(listing.Args) != 4 || listing.Args[0].Lit() != "head" ||
			listing.Args[1].Lit() != "-n" || listing.Args[2].Lit() != "1" ||
			listing.Args[3].Lit() != "*/*" {
			return false
		}
	case "echo":
		if len(listing.Args) != 2 || listing.Args[0].Lit() != "echo" ||
			listing.Args[1].Lit() != "*/*" {
			return false
		}
	default:
		return false
	}
	hasPWD := false
	for _, stmt := range statements[1:] {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
			return false
		}
		if call.Args[0].Lit() == "pwd" {
			for _, redirect := range stmt.Redirs {
				if !actionDiscardRedirect(redirect, home) {
					return false
				}
			}
			if len(call.Args) == 2 {
				option, fixed := StaticWord(call.Args[1], home)
				if !fixed || option != "-L" && option != "-P" {
					return false
				}
			} else if len(call.Args) != 1 {
				return false
			}
			hasPWD = true
		} else if len(stmt.Redirs) == 0 && actionFixedTextEcho(call) {
			continue
		} else {
			program, known := staticProgramWord(call.Args[0], home)
			if !known {
				return false
			}
			switch programBase(program) {
			case "cat", "head", "tail", "ls", "dir", "stat",
				"grep", "egrep", "fgrep", "wc", "du", "readlink", "realpath":
				if !actionKnownReadOnlyShell(&syntax.File{Stmts: []*syntax.Stmt{stmt}}, home) {
					return false
				}
			default:
				return false
			}
		}
	}
	return hasPWD
}

// actionFixedTextEchoes returns the echo calls of a command that print fixed
// text and do nothing else: a top-level statement, or an operand of && or
// ||, with no redirect, pipe, background or negation, whose words are plain
// text (actionFixedEchoText). Such an echo is verdict-neutral: the command
// gets the verdict of its other statements alone (lead ruling 2026-10-31
// 18:34 EDT, rel-1-0-6:GAP-0225). An echo in a pipeline, a subshell, a
// substitution or a loop body is not one.
func actionFixedTextEchoes(file *syntax.File) map[*syntax.CallExpr]bool {
	neutral := map[*syntax.CallExpr]bool{}
	var list func(stmt *syntax.Stmt)
	list = func(stmt *syntax.Stmt) {
		if stmt == nil || len(stmt.Redirs) != 0 || stmt.Background || stmt.Coprocess || stmt.Negated {
			return
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.BinaryCmd:
			if cmd.Op == syntax.AndStmt || cmd.Op == syntax.OrStmt {
				list(cmd.X)
				list(cmd.Y)
			}
		case *syntax.CallExpr:
			if actionFixedTextEcho(cmd) {
				neutral[cmd] = true
			}
		}
	}
	for _, stmt := range file.Stmts {
		list(stmt)
	}
	return neutral
}

// actionFixedEchoText is the text a verdict-neutral echo word may hold:
// letters, digits, spaces and plain punctuation. A $, a backtick, a glob or
// brace character, a ~, a / (a path), a backslash, a quote character or a !
// is not.
var actionFixedEchoText = lazyregexp.New(`^[A-Za-z0-9 _.,:=+@%-]*$`)

// actionFixedTextEcho reports an echo call whose every word is fixed text:
// unquoted, single-quoted or double-quoted literal parts only, matching
// actionFixedEchoText and naming no SSH file.
func actionFixedTextEcho(call *syntax.CallExpr) bool {
	if len(call.Assigns) != 0 || len(call.Args) == 0 {
		return false
	}
	if lit := call.Args[0].Lit(); lit != "echo" {
		return false
	}
	fixed := func(text string) bool {
		lower := strings.ToLower(text)
		return actionFixedEchoText.MatchString(text) && !strings.Contains(lower, "ssh") && !strings.Contains(lower, "authorized")
	}
	for _, word := range call.Args[1:] {
		for _, part := range word.Parts {
			switch part := part.(type) {
			case *syntax.Lit:
				if !fixed(part.Value) {
					return false
				}
			case *syntax.SglQuoted:
				if part.Dollar || !fixed(part.Value) {
					return false
				}
			case *syntax.DblQuoted:
				if part.Dollar {
					return false
				}
				for _, inner := range part.Parts {
					lit, ok := inner.(*syntax.Lit)
					if !ok || !fixed(lit.Value) {
						return false
					}
				}
			default:
				return false
			}
		}
	}
	return true
}

// actionDiscardRedirect reports a redirect that writes no file: output or
// append to /dev/null, or a copy of a descriptor (2>&1, >&-).
func actionDiscardRedirect(redirect *syntax.Redirect, home string) bool {
	if redirect.Word == nil || redirect.Hdoc != nil {
		return false
	}
	target, static := StaticWord(redirect.Word, home)
	if !static {
		return false
	}
	switch redirect.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.RdrClob:
		return target == "/dev/null"
	case syntax.DplOut:
		return target == "-" || target != "" && strings.Trim(target, "0123456789") == ""
	}
	return false
}

// actionPowerShellListOnly are the PowerShell commands that read names or
// properties and write nothing. On a POSIX host ls and dir run the programs
// of that name, which only list too; sort runs the sort program, which can
// write a file (-o), so it is not one.
var actionPowerShellListOnly = map[string]bool{
	"get-childitem": true, "gci": true, "ls": true, "dir": true, "get-item": true, "gi": true, "test-path": true, "resolve-path": true, "rvpa": true,
	"select-object": true, "select": true, "format-list": true, "fl": true, "format-table": true, "ft": true,
	"format-wide": true, "fw": true, "measure-object": true, "measure": true, "sort-object": true,
	"out-string": true, "write-output": true, "echo": true,
}

// actionPowerShellListOnlyBodyText is the text a list-only body may hold:
// words, paths, wildcards, pipes and statement ends. A variable, a
// subexpression, a script block, a quote, an escape or a redirect is not.
var actionPowerShellListOnlyBodyText = lazyregexp.New(`^[A-Za-z0-9_./~:*?,|; \t-]+$`)

// actionPowerShellListOnlyBody reports a PowerShell -Command body, read as
// shell words, whose every command is a list-only PowerShell command
// (actionPowerShellListOnly) and whose text has no other syntax.
func actionPowerShellListOnlyBody(body, home string) bool {
	if !actionPowerShellListOnlyBodyText.MatchString(body) {
		return false
	}
	file, parsed := parseShell(body)
	if !parsed {
		return false
	}
	listOnly, calls := true, 0
	syntax.Walk(file, func(node syntax.Node) bool {
		if !listOnly {
			return false
		}
		switch node := node.(type) {
		case *syntax.FuncDecl, *syntax.ProcSubst, *syntax.CoprocClause, *syntax.DeclClause, *syntax.Redirect:
			listOnly = false
		case *syntax.CallExpr:
			program, static := "", false
			if len(node.Assigns) == 0 && len(node.Args) > 0 {
				program, static = StaticWord(node.Args[0], home)
			}
			listOnly = static && actionPowerShellListOnly[strings.ToLower(program)]
			calls++
		}
		return listOnly
	})
	return listOnly && calls > 0
}

// actionWindowsLaunchText is the text a list-only PowerShell launch may hold
// on a native Windows host: words, paths, wildcards, double quotes and
// backslashes. No reading of it (Git Bash, PowerShell, cmd) finds a
// variable, a single quote, a backtick, a caret, a percent, a parenthesis,
// a redirect or a background operator in it.
var actionWindowsLaunchText = lazyregexp.New(`^[A-Za-z0-9_./~:*?,|; \t"\\-]+$`)

// actionWindowsPowerShellListOnlyLaunch reports a command that is one pwsh
// or powershell call whose -Command body only lists names
// (actionPowerShellListOnlyBody), as the POSIX read-only list reads it
// (actionKnownReadOnlyShell, rel-1-0-6:GAP-0145). Git Bash, PowerShell and
// cmd pass that body alike, because the text holds nothing only one of them
// reads (actionWindowsLaunchText). PowerShell reads a backslash in a path as
// a separator, never as an escape, so the body is checked with forward
// slashes: a backslash cannot hide a statement end from the check.
func actionWindowsPowerShellListOnlyLaunch(command, home string) bool {
	if len(command) > MaxPayloadBytes || !actionWindowsLaunchText.MatchString(command) {
		return false
	}
	file, parsed := parseShell(command)
	if !parsed || len(file.Stmts) != 1 {
		return false
	}
	stmt := file.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(stmt.Redirs) != 0 || stmt.Background || stmt.Coprocess || stmt.Negated ||
		len(call.Assigns) != 0 || len(call.Args) < 3 {
		return false
	}
	program, static := StaticWord(call.Args[0], home)
	if !static || !strings.EqualFold(program, "pwsh") && !strings.EqualFold(program, "powershell") {
		return false
	}
	body, static := actionPowerShellCommandBody(call.Args, home)
	return static && actionPowerShellListOnlyBody(strings.ReplaceAll(body, `\`, "/"), home)
}

// actionPowerShellCommandBody returns the -Command text pwsh or powershell
// runs: PowerShell joins every argument after -Command with one blank, so
// an unquoted body the shell split into words (pwsh -Command Get-ChildItem
// ~/.ssh, its ~ expanded to the home) is the same text as the quoted body
// (rel-1-0-6:GAP-0310). Every word must be static.
func actionPowerShellCommandBody(args []*syntax.Word, home string) (string, bool) {
	j, single := actionPowerShellCommandBodyIndex(args, 0, home)
	if j == 0 || j >= len(args) {
		return "", false
	}
	if single {
		return StaticWord(args[j], home)
	}
	words := make([]string, 0, len(args)-j)
	for _, arg := range args[j:] {
		word, static := StaticWord(arg, home)
		if !static {
			return "", false
		}
		words = append(words, word)
	}
	return strings.Join(words, " "), true
}

// actionExitStatusAssignment reports a bare NAME=$? assignment: it keeps the
// previous command's exit status and changes no file or program lookup.
func actionExitStatusAssignment(call *syntax.CallExpr) bool {
	if len(call.Assigns) == 0 {
		return false
	}
	for _, assign := range call.Assigns {
		if assign.Name == nil || assign.Append || assign.Naked || assign.Index != nil || assign.Array != nil ||
			assign.Value == nil || len(assign.Value.Parts) != 1 {
			return false
		}
		switch strings.ToUpper(assign.Name.Value) {
		case "PATH", "IFS", "HOME", "ENV", "BASH_ENV", "CDPATH", "SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND":
			return false
		}
		param, ok := assign.Value.Parts[0].(*syntax.ParamExp)
		if !ok || param.Param == nil || param.Param.Value != "?" || param.Excl || param.Length || param.Index != nil ||
			param.Slice != nil || param.Repl != nil || param.Exp != nil || len(param.Modifiers) != 0 {
			return false
		}
	}
	return true
}

// actionStatusReport reports echo, printf or exit words that report an exit
// status: at least one word expands $? or a NAME=$? variable, every
// expansion is such a plain parameter (no command substitution), and the
// literal text names no protected place (.ssh, authorized_keys,
// .defenseclaw) and no home spelling, so printing it is not a mention.
func actionStatusReport(args []*syntax.Word, status map[string]bool) bool {
	if len(args) == 0 || len(args) > 4 {
		return false
	}
	reports, clean := false, true
	for _, arg := range args {
		var text strings.Builder
		syntax.Walk(arg, func(node syntax.Node) bool {
			switch node := node.(type) {
			case nil, *syntax.Word, *syntax.DblQuoted:
				// syntax.Walk calls f(nil) after a node's children.
			case *syntax.Lit:
				text.WriteString(node.Value)
			case *syntax.SglQuoted:
				text.WriteString(node.Value)
			case *syntax.ParamExp:
				if node.Param == nil || !status[node.Param.Value] || node.Exp != nil || node.Repl != nil ||
					node.Slice != nil || node.Index != nil || node.Excl || node.Length {
					clean = false
					return false
				}
				reports = true
				return false
			default:
				clean = false
				return false
			}
			return true
		})
		lower := strings.ToLower(text.String())
		if strings.Contains(lower, ".ssh") || strings.Contains(lower, "authorized_keys") ||
			strings.Contains(lower, ".defenseclaw") || strings.Contains(lower, "~") {
			clean = false
		}
	}
	return reports && clean
}

// actionSSHKeygenListsOnly reports an ssh-keygen call that only lists key
// fingerprints (-l, with -f FILE, -E HASH, -v, -q): it reads the file and
// writes nothing. Any other mode (-R, -t, -p, -y, -s, ...) is not a plain
// read (GAP-2168).
func actionSSHKeygenListsOnly(args []*syntax.Word, home string) bool {
	list := false
	for index := 0; index < len(args); index++ {
		word, known := StaticWord(args[index], home)
		if !known || len(word) < 2 || word[0] != '-' || word[1] == '-' {
			return false
		}
		flags := word[1:]
		for at := 0; at < len(flags); at++ {
			switch flags[at] {
			case 'l':
				list = true
			case 'v', 'q':
			case 'f', 'E':
				if at == len(flags)-1 {
					index++
					if index >= len(args) {
						return false
					}
				}
				at = len(flags)
			default:
				return false
			}
		}
	}
	return list
}

// actionSSHKeygenListsOnlyWords is actionSSHKeygenListsOnly for the words of
// a Windows reading: -l with only -v, -q, -f FILE and -E HASH lists keys.
func actionSSHKeygenListsOnlyWords(args []string) bool {
	list := false
	for index := 0; index < len(args); index++ {
		word := args[index]
		if len(word) < 2 || word[0] != '-' || word[1] == '-' {
			return false
		}
		flags := word[1:]
		for at := 0; at < len(flags); at++ {
			switch flags[at] {
			case 'l':
				list = true
			case 'v', 'q':
			case 'f', 'E':
				if at == len(flags)-1 {
					index++
					if index >= len(args) {
						return false
					}
				}
				at = len(flags)
			default:
				return false
			}
		}
	}
	return list
}

func actionLessWritesFile(option string) bool {
	if option == "-o" || option == "-O" ||
		strings.HasPrefix(option, "-o") && !strings.HasPrefix(option, "--") ||
		strings.HasPrefix(option, "-O") && !strings.HasPrefix(option, "--") {
		return true
	}
	option, _, _ = strings.Cut(strings.ToLower(option), "=")
	return strings.HasPrefix(option, "--") && len(option) > 2 &&
		(strings.HasPrefix("--log-file", option) || strings.HasPrefix(option, "--log-file"))
}

// actionWindowsTargetMention holds when the PowerShell reading or the plain
// reading of the command (actionWindowsPlainGrammar: Git Bash and cmd do not
// read PowerShell comments, smart quotes or the backtick) names a protected
// target (GAP-1500 refix 2).
//
// A dialect hint never drops a reading that may write a protected target
// (lead decision on GAP-1504). It names the reading the shell makes: the
// PowerShell grammar for a PowerShell hint, the POSIX grammar for a POSIX
// hint (ActionCommandDecisionWithDialectAndGlobFacts), whose mention rules
// (TGT-0194) hold as they are. Another reading counts unless it only prints
// or reads and redirects into no protected target
// (actionWindowsReadingWritesNothing): a path that is only printed there is
// not a write, so Git Bash echo \$HOME/.ssh/authorized_keys and a PowerShell
// comment are not blocked by the reading of a shell that does not run them.
func actionWindowsTargetMention(command, cwd, home string, depth int, stateOnly bool, dialect actionfacts.Dialect, memo *TargetMemo) bool {
	if depth == 0 && actionWindowsPowerShellListOnlyLaunch(command, home) {
		return false
	}
	if memo == nil {
		// Both readings and every nested body of this call share one memo.
		memo = NewTargetMemo()
	}
	grammars := []actionWindowsGrammar{0, actionWindowsPlainGrammar}
	if dialect == "" || dialect == actionfacts.DialectPOSIX {
		// Git Bash may run the call: its backslash reading (GAP-0237).
		grammars = append(grammars, actionWindowsPlainGrammar|actionWindowsBackslashEscapes)
	}
	for _, grammar := range grammars {
		if grammar != 0 && (dialect == actionfacts.DialectPowerShell || dialect == actionfacts.DialectPOSIX) {
			grammar |= actionWindowsPlainComments
		}
		if !actionWindowsTargetMentionAs(command, cwd, home, depth, stateOnly, grammar, memo) {
			continue
		}
		hinted := dialect == actionfacts.DialectPOSIX || dialect == actionfacts.DialectPowerShell && grammar != 0
		if !hinted || !actionWindowsReadingWritesNothing(command, cwd, home, grammar, dialect, memo) {
			return true
		}
	}
	return false
}

// actionWindowsReadingWritesNothing holds when, in this reading, every
// statement prints or reads (actionWindowsTextStatement,
// actionKnownReadOnlyWindowsStatement) with no nested command or script
// block, and every output redirect names no protected target.
func actionWindowsReadingWritesNothing(command, cwd, home string, grammar actionWindowsGrammar, dialect actionfacts.Dialect, memo *TargetMemo) bool {
	scan := actionWindowsScan(actionWindowsBlankPatchText(command), grammar|actionWindowsLiteralDollar)
	if !scan.ok || len(scan.words) == 0 {
		// A POSIX-hinted command that the POSIX grammar reads completely
		// runs in that shell; a Windows reading the scanner cannot read is
		// then not a shell that runs it (the GAP-1500 fallback is for
		// commands PowerShell runs).
		if dialect != actionfacts.DialectPOSIX {
			return false
		}
		_, parsed := parseShell(command)
		return parsed
	}
	words := scan.words
	var statement []string
	end := func() bool {
		if len(statement) == 0 {
			return true
		}
		for _, word := range statement {
			// ( and { open a subexpression, subshell or script block. A
			// PowerShell backtick only escapes; in the plain reading a pair
			// of backticks is a Git Bash command substitution.
			if strings.ContainsAny(word, "({") || grammar&actionWindowsPlainGrammar != 0 && strings.Count(word, "`") >= 2 {
				return false
			}
		}
		ok := actionWindowsTextStatement(statement) || actionKnownReadOnlyWindowsStatement(statement)
		statement = statement[:0]
		return ok
	}
	for i := 0; i < len(words); i++ {
		word := words[i]
		switch word {
		case ";", "|", "||", "&", "&&":
			if !end() {
				return false
			}
			continue
		}
		if operator := actionWindowsRedirectOperator(word); operator != "" {
			if i+1 >= len(words) {
				break // A redirect with no target writes no file.
			}
			i++
			if operator[0] == '>' && actionWindowsWordMentionsTarget(words[i], cwd, home, false, memo) {
				return false
			}
			continue
		}
		statement = append(statement, word)
	}
	return end()
}

func actionWindowsTargetMentionAs(command, cwd, home string, depth int, stateOnly bool, grammar actionWindowsGrammar, memo *TargetMemo) bool {
	if depth >= 8 || len(command) > MaxPayloadBytes {
		return false
	}
	command = actionWindowsBlankPatchText(command)
	// The argument to PowerShell -Command is parsed again by the child shell.
	// Quotes that are literal in the outer command do not stop expansion there.
	raw := actionWindowsScan(command, grammar)
	rawWords, rawOK := raw.words, raw.ok
	// printBodies are pwsh/powershell -Command bodies read on their own
	// below that only print or run a read-only git command: their quoted ~
	// is text there, as in the same body on its own (GAP-1473 RV18-1).
	var printBodies map[string]bool
	if rawOK && actionWindowsInvokedTextMention(rawWords, cwd, home, depth, stateOnly, memo) {
		return true
	}
	if rawOK {
		for i := 0; i+2 < len(rawWords); i++ {
			program := programBase(rawWords[i])
			if program == "env" {
				for j := i + 1; j+1 < len(rawWords); j++ {
					if rawWords[j] == ";" || rawWords[j] == "|" || rawWords[j] == "&" {
						break
					}
					if (rawWords[j] == "-S" || rawWords[j] == "--split-string") &&
						actionWindowsTargetMention(rawWords[j+1], cwd, home, depth+1, stateOnly, "", memo) {
						return true
					}
				}
			}
			if posixShellProgram(program) || program == "ash" {
				if actionWindowsPOSIXShellMention(rawWords[i+1:], cwd, home, depth, stateOnly, memo) {
					return true
				}
				continue
			}
			if program != "pwsh" && program != "powershell" {
				continue
			}
			for j := i + 1; j+1 < len(rawWords); j++ {
				if rawWords[j] == ";" || rawWords[j] == "|" || rawWords[j] == "&" {
					break
				}
				if strings.EqualFold(rawWords[j], "-command") || strings.EqualFold(rawWords[j], "-c") {
					body := rawWords[j+1]
					if actionWindowsTargetMention(body, cwd, home, depth+1, stateOnly, actionfacts.DialectPowerShell, memo) {
						return true
					}
					if actionWindowsPrintOnlyCommandBody(body, cwd, home, memo) {
						if printBodies == nil {
							printBodies = make(map[string]bool)
						}
						printBodies[body] = true
					}
					break
				}
			}
		}
	}
	// PowerShell does not expand variables inside single quoted literals:
	// the scanner keeps their $ from reading as a home variable, by the
	// quotes it reads (a quote in a comment or a smart quote no longer flips
	// the state, GAP-1779).
	scan := actionWindowsScan(command, grammar|actionWindowsLiteralDollar)
	words, ok := scan.words, scan.ok
	if !ok {
		// A command the scanner cannot read may still be read differently by
		// the shell that runs it (GAP-1500). Keep the class rule there, as the
		// POSIX text scan does, on the command as written (GAP-1779).
		return actionWindowsUnreadTargetMention(command, cwd, home, stateOnly, memo)
	}
	if len(words) == 0 || depth == 0 && actionKnownReadOnlyWindows(words) {
		return false
	}
	skip := actionWindowsTextWords(scan, depth, strings.ContainsAny(command, "\r\n"))
	for i := 0; i+1 < len(words); i++ {
		if !strings.EqualFold(words[i], "-encodedcommand") && !strings.EqualFold(words[i], "-enc") {
			continue
		}
		encoded, err := base64.StdEncoding.DecodeString(words[i+1])
		if err != nil || len(encoded) == 0 || len(encoded)%2 != 0 {
			continue
		}
		letters := make([]uint16, len(encoded)/2)
		for j := range letters {
			letters[j] = uint16(encoded[2*j]) | uint16(encoded[2*j+1])<<8
		}
		if actionWindowsTargetMention(string(utf16.Decode(letters)), cwd, home, depth+1, stateOnly, actionfacts.DialectPowerShell, memo) {
			return true
		}
	}
	if !stateOnly && actionWindowsInterpreterBuildsKeyPath(words, cwd, home) {
		return true
	}
	// A word checked once in a directory is not checked again: in one call
	// the check depends only on the word and the directory, and on Windows
	// it looks up the file a word names, so a long command that repeats its
	// words paid one round of file system calls per repeat (GAP-2256).
	checked := make(map[[2]string]struct{})
	mentions := func(word, dir string) bool {
		key := [2]string{word, dir}
		if _, seen := checked[key]; seen {
			return false
		}
		checked[key] = struct{}{}
		return actionWindowsWordMentionsTarget(word, dir, home, stateOnly, memo)
	}
	effectiveCWD := cwd
	var directoryStack []string
	// A plain move onto an existing link replaces the link entry and
	// writes nothing it names: its destination is judged by that entry,
	// in the directory the statement runs in and in the request cwd
	// (GAP-2559, actionPlainMoveOntoLink in the POSIX reading).
	powerShell := grammar&actionWindowsPlainGrammar == 0
	var protectedMoveFiles *protectedFiles
	movedEntry := func(statement []string, dir string) (int, bool, bool) {
		if stateOnly {
			return 0, false, false
		}
		index, entry, moved := actionWindowsPlainMoveOntoLink(statement, dir, home, powerShell)
		if !moved {
			return 0, false, false
		}
		if protectedMoveFiles == nil {
			files := newProtectedFiles(home)
			protectedMoveFiles = &files
		}
		return index, protectedEntry(entry, *protectedMoveFiles, filepath.Join(home, ".ssh")), true
	}
	moveSpans := map[int]actionWindowsResolvedSpan{}
	// A plain removal of a link entry removes the link, not the file it
	// names (rel-1-0-4:GAP-2590): the word is judged by its entry, in the
	// statement's directory and in the request cwd, as a plain move onto a
	// link is.
	removedSpans := map[int]actionWindowsResolvedSpan{}
	removedEntry := func(statement []string, dir string) (map[int]bool, bool) {
		if stateOnly {
			return nil, false
		}
		entries := actionWindowsPlainRemovedLinks(statement, dir, home, powerShell)
		if len(entries) == 0 {
			return nil, false
		}
		if protectedMoveFiles == nil {
			files := newProtectedFiles(home)
			protectedMoveFiles = &files
		}
		indexes := make(map[int]bool, len(entries))
		for index, entry := range entries {
			if protectedEntry(entry, *protectedMoveFiles, filepath.Join(home, ".ssh")) {
				return nil, true
			}
			indexes[index] = true
		}
		return indexes, false
	}
	for _, span := range actionWindowsResolvedSpans(words, cwd, home) {
		destination, protectedMove, moved := movedEntry(span.words, effectiveCWD)
		if moved && protectedMove {
			return true
		}
		removed, protectedRemove := removedEntry(span.words, effectiveCWD)
		if protectedRemove {
			return true
		}
		if !stateOnly {
			for _, j := range actionWindowsSSHDirectorySetupWords(span.words, effectiveCWD, home) {
				if removed == nil {
					removed = map[int]bool{}
				}
				removed[j] = true
			}
		}
		for j, word := range span.words {
			if moved && j == destination {
				moveSpans[span.start+j] = span
				continue
			}
			if removed[j] {
				removedSpans[span.start+j] = span
				continue
			}
			if !skip[span.start+j] && !printBodies[word] && mentions(word, effectiveCWD) {
				return true
			}
		}
		actionWindowsAdvanceDirectory(span.words, home, &effectiveCWD, &directoryStack)
	}
	for i, word := range words {
		if span, ok := removedSpans[i]; ok {
			removed, protectedRemove := removedEntry(span.words, cwd)
			if protectedRemove {
				return true
			}
			if removed[i-span.start] || slices.Contains(actionWindowsSSHDirectorySetupWords(span.words, cwd, home), i-span.start) {
				continue
			}
		}
		if span, ok := moveSpans[i]; ok {
			if destination, protectedMove, moved := movedEntry(span.words, cwd); moved && span.start+destination == i {
				if protectedMove {
					return true
				}
				continue
			}
		}
		if !skip[i] && !printBodies[word] && mentions(word, cwd) {
			return true
		}
	}
	return false
}

// actionWindowsPrintOnlyCommandBody reports a pwsh/powershell -Command body
// that only prints or runs a read-only git command in both readings: as
// shell words (actionPowerShellPrintOnlyBody: no redirect, assignment,
// function or substitution) and as PowerShell statements
// (actionWindowsReadingWritesNothing: no subexpression or script block).
// Any writer body keeps the whole-text reading of its outer word.
func actionWindowsPrintOnlyCommandBody(body, cwd, home string, memo *TargetMemo) bool {
	return actionPowerShellPrintOnlyBody(body, home) &&
		actionWindowsReadingWritesNothing(body, cwd, home, 0, actionfacts.DialectPowerShell, memo)
}

// actionWindowsPOSIXShellMention reads the script that a POSIX shell (Git
// Bash, MSYS sh) runs with -c as that shell reads it, on the Windows file
// system (ActionCommandDecisionWithDialectAndGlobFacts): quote removal, ~, $HOME and
// ${HOME}, cd tracking and the MSYS /c/ drive spelling. The Windows reading
// keeps the script's own quotes and operators inside its words, so a key
// target spelled "$HOME"/.ssh/authorized_k*, k>/c/Users/u/.ssh/... or
// cd ~ && cp k .ssh/authorized_k* named no file there (GAP-0781 RV8-1).
// words are the words after the shell program.
func actionWindowsPOSIXShellMention(words []string, cwd, home string, depth int, stateOnly bool, memo *TargetMemo) bool {
	if depth+1 >= 8 {
		return false
	}
	for j := 0; j+1 < len(words); j++ {
		option := words[j]
		if !strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "+") {
			return false
		}
		switch option {
		case "-o", "+o", "-O", "+O", "--rcfile", "--init-file":
			j++ // This option consumes the next word (bash -O dotglob -c).
			continue
		}
		if option == "-c" || len(option) > 2 && !strings.HasPrefix(option, "--") &&
			!strings.ContainsAny(option, "=/") && strings.Contains(option[1:], "c") {
			script := actionWindowsHereStringBody(words[j+1])
			return actionPosixTargetMention(script, cwd, home, depth+1, stateOnly, (*actionGlobs)(nil).forCommandWith(script, memo)) ||
				!stateOnly && actionConcreteProtectedWriteOnWith(script, cwd, home, true, memo)
		}
	}
	return false
}

// actionWindowsInterpreterBuildsKeyPath is actionInterpreterBuildsKeyPath
// for the Windows readings: python -c, node -e/-p, perl -e/-E and ruby -e
// code that names both key-path parts and has an executable writer is a
// protected target however it joins them, unless the binding rules place
// every write of home-call code on an ordinary path. The class rule ran
// only in the POSIX grammar, so PowerShell python -c/node -e key writes
// were allowed (GAP-2005 RV8-2).
func actionWindowsInterpreterBuildsKeyPath(words []string, cwd, home string) bool {
	for i := 0; i+2 < len(words); i++ {
		language := actionInterpreterKind(words[i])
		if language == "" {
			continue
		}
		if code, ok := actionInterpreterInlineCode(words, i); ok &&
			actionInterpreterKeyPathCode(code, language, cwd, home) {
			return true
		}
	}
	return false
}

// actionWindowsInterpreterCodeOption reports the option whose next word is
// the inline code: python -c (or a flag cluster ending in c), node -e,
// --eval, -p, --print, perl -e/-E (or a cluster ending in e/E), ruby -e.
func actionWindowsInterpreterCodeOption(language, option string) bool {
	// A flag cluster (-Ic, -we, -ne) ends in the code option; a cluster that
	// starts with a value option (-Wstatic, -Iinclude, -rjson) does not.
	cluster := len(option) > 2 && !strings.HasPrefix(option, "--") && strings.Trim(option[1:],
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") == ""
	switch language {
	case "python":
		return option == "-c" || cluster && strings.HasSuffix(option, "c") && !strings.ContainsAny(option[1:2], "XWQ")
	case "node", "nodejs":
		return option == "-e" || option == "--eval" || option == "-p" || option == "--print" || option == "-pe"
	case "perl":
		return option == "-e" || option == "-E" || cluster && (strings.HasSuffix(option, "e") || strings.HasSuffix(option, "E")) &&
			!strings.ContainsAny(option[1:2], "IMmxCdD")
	case "ruby":
		return option == "-e" || cluster && strings.HasSuffix(option, "e") && !strings.ContainsAny(option[1:2], "IrCExFK")
	}
	return false
}

// actionWindowsHereStringBody returns the text of an @'...'@ or @"..."@
// word as the scanner keeps it (the @ marks around the body).
func actionWindowsHereStringBody(word string) string {
	if len(word) >= 2 && word[0] == '@' && word[len(word)-1] == '@' && strings.ContainsAny(word, "\r\n") {
		return word[1 : len(word)-1]
	}
	return word
}

// actionWindowsInvokedTextMention runs the scan on the text that
// Invoke-Expression (iex) runs, given as its argument or piped into it: the
// text is parsed again when it runs, so a $HOME that a single-quoted string
// or an @'...'@ here-string kept literal is expanded there (GAP-1523).
func actionWindowsInvokedTextMention(words []string, cwd, home string, depth int, stateOnly bool, memo *TargetMemo) bool {
	invoke := func(word string) bool {
		program := programBase(word)
		return program == "iex" || program == "invoke-expression"
	}
	body := actionWindowsHereStringBody
	for i, word := range words {
		if invoke(word) {
			for j := i + 1; j < len(words); j++ {
				if words[j] == ";" || words[j] == "|" || words[j] == "&" || words[j] == "&&" || words[j] == "||" {
					break
				}
				if strings.HasPrefix(words[j], "-") {
					continue
				}
				if actionWindowsTargetMention(body(words[j]), cwd, home, depth+1, stateOnly, actionfacts.DialectPowerShell, memo) {
					return true
				}
				break
			}
		}
		if i+2 < len(words) && words[i+1] == "|" && invoke(words[i+2]) &&
			actionWindowsTargetMention(body(word), cwd, home, depth+1, stateOnly, actionfacts.DialectPowerShell, memo) {
			return true
		}
	}
	return false
}

// actionWindowsTextWords marks the words the mention scan does not read as
// targets: every word of a top-level list element (between ;, &, && and
// ||) that is a known read pipeline with no redirect, because each
// statement is judged on its own targets (GAP-1799); a location change (cd,
// Push-Location ...) still counts, since it places the writes after it.
// It also rewrites the ~ of a quoted word (no $( subexpression) that is
// printed (Write-Output, echo, Write-Host ...) or given to git, in a
// command with no writer statement: PowerShell passes that text as written,
// and only a cmdlet path parameter or a redirect reads its ~ as the home
// (GAP-1473). An absolute or $HOME path in the same word still counts.
func actionWindowsTextWords(scan actionWindowsScanResult, depth int, multiline bool) []bool {
	words := scan.words
	skip := make([]bool, len(words))
	// The printed ~ is text only in a command whose statements all print,
	// read or run git: a writer elsewhere keeps the TGT-0194 mention rule.
	// The scanner ends a statement at a line end (GAP-0234), but a command
	// of several lines may be one script block or a here-string body, so
	// it is not text only.
	textOnly := !multiline
	for start, i := 0, 0; i <= len(words); i++ {
		if i < len(words) && words[i] != ";" && words[i] != "|" && words[i] != "||" && words[i] != "&" && words[i] != "&&" {
			continue
		}
		if i > start && !actionWindowsTextStatement(words[start:i]) && !actionKnownReadOnlyWindowsStatement(words[start:i]) {
			textOnly = false
		}
		start = i + 1
	}
	start := 0
	for i := 0; i <= len(words); i++ {
		if i < len(words) && words[i] != ";" && words[i] != "&" && words[i] != "&&" && words[i] != "||" {
			continue
		}
		if depth == 0 && i > start && actionKnownReadOnlyWindows(words[start:i]) && !actionWindowsLocationProgram(words[start]) {
			for j := start; j < i; j++ {
				skip[j] = true
			}
		}
		start = i + 1
	}
	start = 0
	for i := 0; i <= len(words); i++ {
		if i < len(words) && words[i] != ";" && words[i] != "|" && words[i] != "||" && words[i] != "&" && words[i] != "&&" {
			continue
		}
		if i > start && actionWindowsTextProgram(words[start]) && actionWindowsNestedArgument(scan, start, i) {
			// PowerShell runs a (...), $(...) or @(...) argument of a
			// print as a nested statement: its words are a command, not
			// text, and its parentheses are no part of a path
			// (rel-1-0-6:GAP-0234, echo (cp a.txt '<pattern>')).
			for j := start + 1; j < i; j++ {
				if scan.paren[j] {
					// ,(cp ...) or x(cp ...): the statement starts after
					// the last unquoted ( of the word.
					words[j] = words[j][strings.LastIndex(words[j], "(")+1:]
				} else if !scan.quoted[j] {
					words[j] = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(words[j], "$("), "@("), "(")
				}
				words[j] = strings.TrimRight(words[j], ")")
			}
			start = i + 1
			continue
		}
		if i > start && (i >= len(words) || words[i] != "|") {
			actionWindowsHereStringText(scan, start, i, skip)
		}
		if i > start && (actionWindowsTextProgram(words[start]) || actionWindowsNativeProgram(words[start])) {
			pattern := start + actionWindowsSearchPatternWord(words[start:i])
			// Text piped into a shell is a script: its quoted patterns are
			// paths there (rel-1-0-6:GAP-0227, for echo as for printf).
			script := actionWindowsPipedIntoShell(words, i) || !actionWindowsPrintOnlyDisplays(scan, start, i)
			// A print only prints: PowerShell has no shell glob and passes
			// echo * a star, cmd prints it as written, and Git Bash prints
			// the names its glob makes (the dot rule keeps .ssh out). So an
			// unquoted pattern of a print selects no file in any Windows
			// reading (rel-1-0-6:GAP-0211: the Codex route on Windows
			// reads a plain echo with no PowerShell hint, so the plain
			// readings count too). A spelled path ($HOME/...) still counts,
			// a redirect target and a print piped into a consumer keep
			// their patterns, and git expands its own pathspecs.
			printsUnquoted := !script && actionWindowsTextStatement(words[start:i]) &&
				programBase(words[start]) != "git"
			for j := start + 1; j < i; j++ {
				if !scan.quoted[j] && !printsUnquoted || strings.Contains(words[j], "$(") || actionWindowsRedirectOperator(words[j-1]) != "" {
					continue
				}
				if !scan.quoted[j] {
					words[j] = actionWindowsLiteralPattern.Replace(words[j])
					continue
				}
				if actionWindowsTextProgram(words[start]) && textOnly {
					words[j] = strings.ReplaceAll(words[j], "~", "tilde-text")
				}
				// A quoted pattern that is printed, given to a git command
				// that keeps it as text (not a -c or config value, RV5-2)
				// or is the pattern of a search tool is text: nothing expands it
				// (GAP-1717: echo "*" and grep -rn "*** Begin Patch" . from
				// the home folder). Other native programs (the MSYS tools
				// of Git for Windows) expand a quoted word of their own
				// argv, so it stays a path pattern (GAP-1984).
				if (actionWindowsTextStatement(words[start:i]) && !script && !actionWindowsGitPathspecWord(words[start:i], j-start)) || j == pattern {
					words[j] = actionWindowsLiteralPattern.Replace(words[j])
				}
			}
		}
		start = i + 1
	}
	return skip
}

// actionWindowsHereStringText marks as text (skip) the here-string words of
// a statement words[start:end] that only prints them (Write-Output, echo,
// Write-Host ...; not git) or only assigns one to a variable no later word
// of the command names ($t = @'...'@): PowerShell writes nothing there, so
// a keys pattern in the body is no target (rel-1-0-6:GAP-0236). The caller
// excludes a statement piped into a later stage, and the nested-argument
// rule runs first. An expandable @"..."@ body with a $( subexpression runs
// a command and keeps being read; a writer that takes the here-string or
// the variable is its own statement and keeps its check.
func actionWindowsHereStringText(scan actionWindowsScanResult, start, end int, skip []bool) {
	words := scan.words
	text := func(j int) bool {
		word := words[j]
		return actionWindowsHereStringBody(word) != word && (scan.literal[j] || !strings.Contains(word, "$("))
	}
	if actionWindowsTextProgram(words[start]) && programBase(words[start]) != "git" &&
		!actionWindowsNestedArgument(scan, start, end) {
		if !actionWindowsPrintOnlyDisplays(scan, start, end) {
			return
		}
		for j := start + 1; j < end; j++ {
			if text(j) {
				skip[j] = true
			}
		}
		return
	}
	if end-start != 3 || words[start+1] != "=" || !text(start+2) {
		return
	}
	name := strings.ToLower(words[start])
	if len(name) < 2 || name[0] != '$' || !actionEvalAssignmentName(name[1:]) {
		return
	}
	// The variable is text only when every later statement prints or
	// reads and none names it, also not as $global:t, $script:t, a
	// variable: drive path or through Get-Variable (rel-1-0-6:GAP-0236
	// review): the assignment then reaches no writer.
	bare := name[1:]
	for k, s := end+1, end+1; k <= len(words); k++ {
		if k < len(words) && words[k] != ";" && words[k] != "|" && words[k] != "||" && words[k] != "&" && words[k] != "&&" {
			continue
		}
		if k > s {
			statement := words[s:k]
			// A later print counts only when no word of it opens a
			// subexpression or a script block: a quoted "$(...)" runs a
			// command that may read the variable by any name
			// (rel-1-0-6:GAP-0236 review round 2).
			if actionWindowsTextStatement(statement) {
				for _, later := range statement {
					if strings.Contains(later, "$(") || strings.Contains(later, "@(") || strings.ContainsAny(later, "{}") {
						return
					}
				}
			} else if !actionKnownReadOnlyWindowsStatement(statement) {
				return
			}
			for _, later := range statement {
				later = strings.ToLower(later)
				if strings.Contains(later, name) || strings.Contains(later, "{"+bare+"}") || strings.Contains(later, ":"+bare) ||
					strings.Contains(later, "variable") || strings.Contains(later, "$executioncontext") {
					return
				}
			}
		}
		s = k + 1
	}
	skip[start+2] = true
}

// actionWindowsDisplaySinks only show or filter what reaches them; they
// pass no item on to a path parameter.
var actionWindowsDisplaySinks = map[string]bool{
	"out-host": true, "oh": true, "out-null": true, "out-string": true, "out-default": true,
	"format-table": true, "ft": true, "format-list": true, "fl": true, "format-wide": true, "fw": true,
	"format-custom": true, "fc": true, "select-string": true, "sls": true, "findstr": true, "grep": true, "more": true,
	"cat": true,
}

// actionWindowsSinkParameters are the parameters a display sink may carry
// and stay a display: layout, width, matching and paging options. A
// -*Variable common parameter, -Tee or -PassThru keeps or forwards the
// text, so it is not here (rel-1-0-6:GAP-0211 review round 2).
var actionWindowsSinkParameters = map[string]bool{
	"-stream": true, "-width": true, "-autosize": true, "-wrap": true, "-property": true, "-groupby": true,
	"-hidetableheaders": true, "-view": true, "-expand": true, "-force": true, "-pattern": true,
	"-simplematch": true, "-casesensitive": true, "-notmatch": true, "-allmatches": true, "-context": true,
	"-quiet": true, "-list": true, "-raw": true, "-encoding": true, "-culture": true, "-paging": true,
	"-i": true, "-v": true, "-n": true, "-c": true, "-e": true, "-f": true, "-r": true, "-w": true, "-x": true,
}

// actionWindowsPrintParameters are the parameters a print may carry and
// stay a print: any other one, such as a -*Variable common parameter
// (-OutVariable, -ov, -PipelineVariable ...), can hand the printed text to
// a later writer.
var actionWindowsPrintParameters = map[string]bool{
	"-nonewline": true, "-noenumerate": true, "-separator": true, "-foregroundcolor": true,
	"-backgroundcolor": true, "-object": true, "-inputobject": true, "-n": true, "-e": true, "-ne": true, "-en": true,
}

// actionWindowsPrintOnlyDisplays reports a print statement words[start:end]
// whose text reaches only the terminal or a display sink: no parameter
// outside actionWindowsPrintParameters, no output redirect except to a
// discard target (a file it writes may be read back as paths, as in
// printf '<keys glob>' > list.txt; cat list.txt | xargs ...), and, when it
// is piped, only display sinks after it (rel-1-0-6:GAP-0211, GAP-0236 and
// rel-1-0-4:GAP-1717 review: Get-Item | Add-Content, Remove-Item and a
// delay-bound -Path {$_} take the printed text as a path).
func actionWindowsPrintOnlyDisplays(scan actionWindowsScanResult, start, end int) bool {
	words := scan.words
	if actionWindowsPipelineShellReader(words, end) {
		return false
	}
	for j := start + 1; j < end; j++ {
		word := words[j]
		if operator := actionWindowsRedirectOperator(word); operator != "" {
			if operator[0] == '>' && (j+1 >= end || !actionWindowsDiscardTarget(words[j+1])) {
				return false
			}
			j++
			continue
		}
		if !scan.quoted[j] && len(word) > 1 && word[0] == '-' {
			name := strings.ToLower(word)
			if colon := strings.IndexByte(name, ':'); colon > 0 {
				name = name[:colon]
			}
			if !actionWindowsPrintParameters[name] {
				return false
			}
		}
	}
	for k := end; k < len(words) && words[k] == "|"; {
		k++
		if k >= len(words) {
			return false
		}
		// env -S can launch a named text display program. Keep this
		// spelling narrow: an explicitly named executable or a different
		// command may interpret its input as a script (GAP-0227).
		if words[k] == "env" && k+2 < len(words) && words[k+1] == "-S" && words[k+2] == "cat -n" &&
			(k+3 == len(words) || words[k+3] == "|" || words[k+3] == ";" || words[k+3] == "&" || words[k+3] == "&&" || words[k+3] == "||") {
			k += 2
		} else if !actionWindowsDisplaySinks[programBase(words[k])] ||
			programBase(words[k]) == "cat" &&
				(!strings.EqualFold(words[k], "cat") || !actionWindowsDisplayBindingStable(words[:start])) {
			// An explicit path or an earlier binding change cannot prove
			// the named display command's behavior.
			return false
		}
		// A sink stage that keeps or forwards what it shows (-OutVariable,
		// -PipelineVariable, -Tee, -PassThru) hands the text on: only the
		// parameters of actionWindowsSinkParameters keep it a display.
		for k++; k < len(words) && words[k] != ";" && words[k] != "|" && words[k] != "||" && words[k] != "&" && words[k] != "&&"; k++ {
			if !scan.quoted[k] && actionWindowsRedirectOperator(words[k]) != "" {
				return false
			}
			if !scan.quoted[k] && len(words[k]) > 1 && words[k][0] == '-' {
				name := strings.ToLower(words[k])
				if colon := strings.IndexByte(name, ':'); colon > 0 {
					name = name[:colon]
				}
				if !actionWindowsSinkParameters[name] {
					return false
				}
			}
		}
	}
	return true
}

// actionWindowsPipelineShellReader identifies a later stage that interprets
// the printed text, including a shell launched through env. Its input must
// remain part of the command reading.
func actionWindowsPipelineShellReader(words []string, end int) bool {
	for i := end; i < len(words) && words[i] == "|"; {
		i++
		if i >= len(words) {
			return false
		}
		program := strings.TrimSuffix(strings.ToLower(programBase(words[i])), ".exe")
		if program == "env" {
			i++
			for i < len(words) && words[i] != "|" && words[i] != ";" && words[i] != "&" && words[i] != "&&" && words[i] != "||" &&
				(strings.Contains(words[i], "=") || strings.HasPrefix(words[i], "-")) {
				// These env options consume the following word.
				if words[i] == "-u" || words[i] == "--unset" || words[i] == "-C" || words[i] == "--chdir" {
					i++
				}
				i++
			}
			if i >= len(words) {
				return false
			}
			program = strings.TrimSuffix(strings.ToLower(programBase(words[i])), ".exe")
		}
		switch program {
		case "sh", "bash", "zsh", "fish", "pwsh", "powershell", "cmd", "iex", "invoke-expression":
			return true
		}
		for i++; i < len(words) && words[i] != "|" && words[i] != ";" && words[i] != "&" && words[i] != "&&" && words[i] != "||"; i++ {
		}
	}
	return false
}

// A named display command keeps its usual meaning only when earlier
// statements in the same call leave command bindings unchanged.
func actionWindowsDisplayBindingStable(words []string) bool {
	start := 0
	for i, word := range words {
		switch word {
		case ";", "|", "||", "&", "&&":
		default:
			continue
		}
		if i > start && !powerShellReadBindingsUnchanged(strings.Join(words[start:i], " ")) {
			return false
		}
		start = i + 1
	}
	return start >= len(words) || powerShellReadBindingsUnchanged(strings.Join(words[start:], " "))
}

// actionWindowsNestedArgument reports a statement words[start:end] with an
// unquoted argument that opens a PowerShell grouping or subexpression:
// (, $( or @( (rel-1-0-6:GAP-0234), anywhere in the word, not only at its
// start (rel-1-0-6:GAP-0237 item 2: PowerShell evaluates ,(...), x(...)
// and -InputObject:(...)).
func actionWindowsNestedArgument(scan actionWindowsScanResult, start, end int) bool {
	for j := start + 1; j < end; j++ {
		word := scan.words[j]
		if scan.paren[j] || !scan.quoted[j] && (strings.HasPrefix(word, "(") || strings.HasPrefix(word, "@(")) || strings.Contains(word, "$(") {
			return true
		}
	}
	return false
}

// actionWindowsPipedIntoShell reports a pipeline stage that ends at end (a
// "|") and feeds a later stage of the same pipeline that runs its input as
// a script: a shell (sh, bash, pwsh, cmd ...) or Invoke-Expression.
func actionWindowsPipedIntoShell(words []string, end int) bool {
	for k := end; k < len(words) && words[k] == "|"; {
		stage := k + 1
		if stage >= len(words) {
			return false
		}
		last := stage
		for last < len(words) && words[last] != ";" && words[last] != "|" && words[last] != "||" && words[last] != "&" && words[last] != "&&" {
			last++
		}
		if actionWindowsPipelineStageReadsScript(words[stage:last]) {
			return true
		}
		k = last
	}
	return false
}

// A plain shell reads stdin, as does one launched by env. Keep the env
// argument grammar here so an assignment after -- and a split string do
// not turn an executable pipeline into display text (GAP-0227).
func actionWindowsPipelineStageReadsScript(stage []string) bool {
	if len(stage) == 0 {
		return false
	}
	if strings.TrimSuffix(strings.ToLower(programBase(strings.ReplaceAll(stage[0], `\`, "/"))), ".exe") != "env" {
		return actionWindowsScriptReader(stage[0])
	}
	options := true
	for i := 1; i < len(stage); i++ {
		word := stage[i]
		if word == "--" {
			options = false
			continue
		}
		if options {
			switch {
			case word == "-i" || word == "--ignore-environment" || word == "-0" || word == "--null" || word == "-v" || word == "--debug":
				continue
			case word == "-u" || word == "--unset" || word == "-C" || word == "--chdir":
				i++
				if i >= len(stage) {
					return false
				}
				continue
			case strings.HasPrefix(word, "--unset=") || strings.HasPrefix(word, "--chdir="):
				continue
			case word == "-S" || word == "--split-string":
				if i+1 >= len(stage) {
					return false
				}
				return actionWindowsEnvSplitReadsScript(stage[i+1])
			case strings.HasPrefix(word, "--split-string="):
				return actionWindowsEnvSplitReadsScript(strings.TrimPrefix(word, "--split-string="))
			}
		}
		if actionWindowsEnvAssignment(word) {
			continue
		}
		return actionWindowsScriptReader(word)
	}
	return false
}

func actionWindowsEnvAssignment(word string) bool {
	name, _, ok := strings.Cut(word, "=")
	if !ok || name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

func actionWindowsEnvSplitReadsScript(value string) bool {
	words := strings.Fields(value)
	return len(words) > 0 && actionWindowsScriptReader(words[0])
}

// actionWindowsScriptReader reports a program that runs the text it reads
// on its input as commands, or turns each item it reads into an argument
// of a command it runs (xargs, ForEach-Object): the printed text is a
// path there (IN-bd-classifier review rows of d60f8a4147).
func actionWindowsScriptReader(word string) bool {
	switch programBase(word) {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "pwsh", "powershell", "cmd", "iex", "invoke-expression",
		"xargs", "%", "foreach", "foreach-object":
		return true
	}
	return false
}

func actionWindowsLocationProgram(word string) bool {
	switch programBase(word) {
	case "cd", "chdir", "sl", "set-location", "pushd", "popd", "push-location", "pop-location":
		return true
	}
	return false
}

// actionWindowsBlankPatchText blanks, for the Windows target scan, the
// envelope text that apply_patch calls read (the POSIX scan does the same,
// actionBlankPatchBodies): content lines, the Begin and End markers and the
// "*** ... File:" directive words, whose *** is no path pattern. The
// directive paths stay and are scanned (GAP-1717: a Git Bash apply_patch
// heredoc from the home folder read *** as a glob that selects .ssh).
func actionWindowsBlankPatchText(command string) string {
	command = actionWindowsBlankHereDocData(command)
	if !strings.Contains(command, patchBeginMarker) ||
		strings.Count(command, "\r") != strings.Count(command, "\r\n") {
		// PowerShell also ends a line at a lone CR, where the line-based
		// feed reading does not (GAP-1500): keep the text.
		return command
	}
	fed := patchFedLines(command)
	lines := strings.Split(command, "\n")
	if fed == nil || len(fed) != len(lines) {
		return command
	}
	for i, line := range lines {
		if fed[i] {
			trimmed := strings.TrimSpace(line)
			blanked := false
			for _, directive := range patchTargetDirectives {
				if strings.HasPrefix(trimmed, directive) {
					lines[i] = strings.Repeat(" ", len(line)-len(trimmed)+len(directive)) + trimmed[len(directive):]
					blanked = true
					break
				}
			}
			if !blanked {
				lines[i] = strings.Repeat(" ", len(line))
			}
			continue
		}
		for _, marker := range []string{patchBeginMarker, patchEndMarker} {
			lines[i] = strings.ReplaceAll(lines[i], marker, strings.Repeat(" ", len(marker)))
		}
	}
	return strings.Join(lines, "\n")
}

var actionWindowsLiteralPattern = strings.NewReplacer("*", "_", "?", "_", "[", "_", "]", "_")

// actionWindowsSearchPatternWord returns the index in words of the pattern
// argument of a search tool (grep, rg, findstr ...): the word after -e or
// --regexp, else the first word that is not an option. It returns -1 for
// any other program (GAP-1984).
func actionWindowsSearchPatternWord(words []string) int {
	if len(words) == 0 {
		return -1
	}
	tool := programBase(words[0])
	switch tool {
	case "grep", "egrep", "fgrep", "rg", "ag", "ack", "findstr":
	default:
		return -1
	}
	for k := 1; k < len(words); k++ {
		switch word := words[k]; {
		case word == "--":
			if k+1 < len(words) {
				return k + 1
			}
			return -1
		case word == "-e" || word == "--regexp":
			if k+1 < len(words) {
				return k + 1
			}
			return -1
		case strings.HasPrefix(word, "--regexp="):
			return k
		case actionSearchOptionTakesValue(tool, word):
			k++ // the option's value (-A 2, -m 5, -g '*.md') is not the pattern (RV5-3)
		case strings.HasPrefix(word, "-") || strings.HasPrefix(word, "/"):
			continue
		default:
			return k
		}
	}
	return -1
}

// actionSearchOptionTakesValue reports an option of a search tool whose
// value is the next word (RV5-3); an attached value (-A2, --glob=x) is one
// word. The short options differ per tool: grep -r and -E take no value,
// rg -r and -E do.
func actionSearchOptionTakesValue(tool, word string) bool {
	switch word {
	case "-A", "-B", "-C", "-m", "-f",
		"--after-context", "--before-context", "--context", "--max-count", "--file":
		return true
	}
	switch tool {
	case "grep", "egrep", "fgrep":
		switch word {
		case "-D", "-d", "--devices", "--directories", "--include", "--exclude", "--exclude-from",
			"--exclude-dir", "--label", "--binary-files", "--group-separator":
			return true
		}
	case "rg":
		switch word {
		case "-E", "-M", "-T", "-d", "-g", "-j", "-r", "-t",
			"--glob", "--iglob", "--type", "--type-not", "--type-add", "--type-clear", "--max-columns",
			"--max-depth", "--max-filesize", "--threads", "--encoding", "--replace", "--sort", "--sortr",
			"--pre", "--pre-glob", "--ignore-file", "--engine", "--context-separator",
			"--field-match-separator", "--path-separator", "--colors", "--dfa-size-limit",
			"--regex-size-limit":
			return true
		}
	case "ag":
		switch word {
		case "-G", "-g", "-p", "--ignore", "--ignore-dir", "--depth", "--path-to-ignore",
			"--file-search-regex":
			return true
		}
	case "ack":
		switch word {
		case "--type", "--ignore-dir", "--ignore-file", "--output":
			return true
		}
	}
	return false
}

// actionWindowsNativeProgram reports a program PowerShell runs as a native
// executable that is neither a shell nor an alias of a cmdlet: it receives a
// quoted word as text (grep, rg, git, python ...). Cmdlets and their aliases
// (cp, rm, ls, cat ...) expand a wildcard path themselves.
func actionWindowsNativeProgram(word string) bool {
	program := programBase(word)
	if program == "" || strings.Contains(program, "-") || strings.ContainsAny(program, "$%&.@({") {
		return false
	}
	switch program {
	case "cp", "copy", "cpi", "mv", "move", "mi", "rm", "del", "erase", "ri", "rd", "rmdir", "ni", "mkdir", "md",
		"sc", "ac", "tee", "cat", "gc", "type", "ls", "dir", "gci", "cd", "sl", "chdir", "pushd", "popd", "ren", "rni",
		"iex", "icm", "start", "saps", "sajb", "select", "where", "foreach", "%", "?", "echo", "write", "set", "sv",
		"ft", "fl", "out", "sort", "measure", "compare", "diff", "curl", "wget", "iwr", "irm", "ii", "clc", "cli", "cpp", "gp", "sp",
		"bash", "sh", "zsh", "dash", "ksh", "wsl", "pwsh", "powershell", "cmd", "busybox", "env", "sudo", "xargs",
		"find", "nohup", "nice", "time", "timeout", "watch", "parallel", "apply_patch", "applypatch":
		return false
	}
	return true
}

func actionWindowsTextProgram(word string) bool {
	switch programBase(word) {
	case "write-output", "echo", "write", "write-host", "write-information", "write-verbose",
		"write-warning", "write-debug", "write-error", "git",
		// printf prints, as echo does (GAP-1717, Codex PowerShell row);
		// printf -v assigns and is no text statement.
		"printf":
		return true
	}
	return false
}

// actionWindowsGitSubcommand returns the index of the subcommand of a git
// statement. It reports false for a statement with no subcommand or with a
// global option that changes what git runs.
func actionWindowsGitSubcommand(words []string) (int, bool) {
	// Global options that only place the command (-C dir, --git-dir,
	// --work-tree) or change its output do not change what git runs; -c,
	// --config-env, --exec-path and any other option do (RV5-4).
	sub := 1
	for sub < len(words) && strings.HasPrefix(words[sub], "-") {
		option := words[sub]
		switch {
		case option == "-C" || option == "--git-dir" || option == "--work-tree" || option == "--namespace":
			sub += 2
			continue
		case option == "-c" && sub+1 < len(words) && actionGitInertConfig(words[sub+1]):
			// An identity or display setting runs nothing (GAP-1473).
			sub += 2
			continue
		case strings.HasPrefix(option, "--git-dir=") || strings.HasPrefix(option, "--work-tree=") ||
			strings.HasPrefix(option, "--namespace="):
		case option == "--no-pager" || option == "-P" || option == "--no-optional-locks" || option == "--bare" ||
			option == "--literal-pathspecs" || option == "--glob-pathspecs" || option == "--noglob-pathspecs" ||
			option == "--icase-pathspecs" || option == "--no-replace-objects" || option == "--no-advice":
		default:
			return 0, false
		}
		sub++
	}
	if sub >= len(words) {
		return 0, false
	}
	return sub, true
}

// actionGitInertConfig reports a git -c NAME=VALUE setting that only names
// the committer or changes the output, so git runs nothing it names: any
// other setting may name a program (an alias, the pager, the editor, a hook
// path, gpg.program) and keeps the statement out of the text reading.
func actionGitInertConfig(setting string) bool {
	name, _, ok := strings.Cut(setting, "=")
	if !ok {
		return false
	}
	switch strings.ToLower(name) {
	case "user.name", "user.email", "author.name", "author.email", "committer.name", "committer.email",
		"color.ui", "core.quotepath", "init.defaultbranch", "advice.detachedhead":
		return true
	}
	return false
}

// actionWindowsGitPathspecWord reports a word of a git text statement that
// git reads as a pathspec of files it rewrites: git stash push (and its
// short form git stash -- ...) saves and then REVERTS the working-tree files
// a pathspec selects, and git expands a pathspec glob itself. Such a word
// stays a path pattern; the -m message stays text (RV6-2).
func actionWindowsGitPathspecWord(words []string, k int) bool {
	sub, ok := actionWindowsGitSubcommand(words)
	if !ok || k <= sub || strings.ToLower(words[sub]) != "stash" {
		return false
	}
	i := sub + 1
	if i < len(words) {
		switch strings.ToLower(words[i]) {
		case "push":
			i++
		case "list", "show", "drop", "pop", "apply", "branch", "clear", "save", "create", "store":
			return false
		}
	}
	for ; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "--":
			return k > i
		case word == "-m" || word == "--message" || word == "--pathspec-from-file":
			if i+1 == k {
				return word == "--pathspec-from-file"
			}
			i++
		case strings.HasPrefix(word, "--pathspec-from-file="):
			if i == k {
				return true
			}
		case strings.HasPrefix(word, "-"):
		default:
			if i == k {
				return true // a pathspec without --
			}
		}
	}
	return false
}

// actionWindowsTextStatement reports a statement that only prints its words
// or gives them to a git command that keeps them as text (a message, a
// pathspec, a search pattern). git runs a configuration value as shell code
// (an alias, the pager, the editor, a hook path), so a git statement with an
// option before its subcommand (-c, --config-env, --exec-path ...), the
// config subcommand, an alias or a subcommand that runs a command it is
// given (rebase --exec, bisect run, submodule foreach ...) is not text
// (GAP-2090).
func actionWindowsTextStatement(words []string) bool {
	if len(words) == 0 || !actionWindowsTextProgram(words[0]) {
		return false
	}
	if len(words) > 1 && strings.HasPrefix(words[1], "-v") &&
		programBase(words[0]) == "printf" {
		return false
	}
	if programBase(words[0]) != "git" {
		return true
	}
	sub, ok := actionWindowsGitSubcommand(words)
	if !ok {
		return false
	}
	switch strings.ToLower(words[sub]) {
	case "commit", "tag", "notes", "stash", "log", "show", "status", "diff", "blame", "add":
		return true
	case "grep":
		for _, word := range words[sub+1:] {
			if strings.HasPrefix(word, "-O") || strings.HasPrefix(word, "--open-files-in-pager") {
				return false
			}
		}
		return true
	}
	return false
}

// actionWindowsUnreadTargetMention is the text scan of a command the Windows
// scanner cannot read. The text is cut at every separator character, quoted
// or not, so a statement that a misread quote hides is still checked. A
// protected-named word counts only in a piece that is not a plain read
// (a known read-only program with no redirect, as on the parsed path), and
// the bare .ssh directory alone does not count: reads and cd/ls/Test-Path of
// ~/.ssh stay allowed (GAP-1500 refix).
func actionWindowsUnreadTargetMention(command, cwd, home string, stateOnly bool, memo *TargetMemo) bool {
	effectiveCWD := cwd
	var directoryStack []string
	for _, piece := range strings.FieldsFunc(command, func(r rune) bool {
		return strings.ContainsRune(";|&\r\n", r)
	}) {
		fields := strings.Fields(piece)
		if len(fields) == 0 {
			continue
		}
		if strings.ContainsAny(piece, "<>") || !actionKnownReadOnlyWindowsStatement(fields) {
			for _, field := range fields {
				if actionWindowsWordNamesTarget(field, effectiveCWD, home, stateOnly, false, memo) ||
					actionWindowsWordNamesTarget(field, cwd, home, stateOnly, false, memo) {
					return true
				}
			}
		}
		actionWindowsAdvanceDirectory(fields, home, &effectiveCWD, &directoryStack)
	}
	return false
}

func actionKnownReadOnlyWindows(words []string) bool {
	words = actionWindowsWithoutDiscardRedirects(words)
	seen, start := false, 0
	for i, word := range words {
		if actionWindowsRedirectOperator(word) != "" {
			return false
		}
		if word != ";" && word != "|" && word != "||" && word != "&" && word != "&&" {
			continue
		}
		if !actionKnownReadOnlyWindowsStatement(words[start:i]) {
			return false
		}
		seen, start = true, i+1
	}
	return (seen || start < len(words)) && actionKnownReadOnlyWindowsStatement(words[start:])
}

// actionWindowsWithoutDiscardRedirects drops the output redirects of words
// whose target only discards (/dev/null, $null, nul) and the 2>&1 stream
// joins: a read that throws its output away writes no file, so uniq <link>
// > /dev/null is still a read (rel-1-0-4:GAP-2590). Any other redirect is
// kept and the statement is not read-only.
func actionWindowsWithoutDiscardRedirects(words []string) []string {
	var out []string
	for i := 0; i < len(words); i++ {
		word := words[i]
		if operator := actionWindowsRedirectOperator(word); operator != "" && operator[0] == '>' &&
			i+1 < len(words) && actionWindowsDiscardTarget(words[i+1]) {
			if out == nil {
				out = append(make([]string, 0, len(words)), words[:i]...)
			}
			i++
			continue
		}
		if len(word) == 4 && (word[0] == '1' || word[0] == '2') && word[1:] == ">&1" || word == "2>&1" {
			if out == nil {
				out = append(make([]string, 0, len(words)), words[:i]...)
			}
			continue
		}
		if out != nil {
			out = append(out, word)
		}
	}
	if out == nil {
		return words
	}
	return out
}

// actionWindowsDiscardTarget reports a redirect target that discards.
func actionWindowsDiscardTarget(word string) bool {
	switch strings.ToLower(word) {
	case "/dev/null", "$null", "nul", `\\.\nul`:
		return true
	}
	return false
}

func actionKnownReadOnlyWindowsStatement(words []string) bool {
	if len(words) == 0 {
		return false
	}
	for _, word := range words {
		if strings.ContainsAny(word, "(`") || strings.Contains(word, "@{") {
			return false // A nested command or escaped syntax is not a plain read.
		}
		for i := 0; i < len(word); i++ {
			if word[i] == '{' && (i == 0 || word[i-1] != '$') {
				return false // Scriptblocks and calculated properties execute commands.
			}
		}
	}
	program := programBase(words[0])
	for _, option := range words[1:] {
		if actionReadOptionMayWrite(option) {
			return false
		}
	}
	switch program {
	case "cat", "get-content", "get-childitem", "resolve-path", "test-path", "head", "tail", "dir", "ls", "stat", "cd", "pushd", "popd", "set-location", "push-location", "pop-location",
		// cmd type, and the search and select filters, only read (GAP-2168).
		"type", "findstr", "select-string", "sls", "select-object", "select",
		// Git Bash search and count programs read their operands as on a
		// POSIX home (actionKnownReadOnlyShell, GAP-2168 Windows leg); so do
		// the size and path readers (GAP-0091).
		"grep", "egrep", "fgrep", "wc", "du", "readlink", "realpath":
		return true
	case "ssh-keygen":
		return actionSSHKeygenListsOnlyWords(words[1:])
	case "less":
		for _, option := range words[1:] {
			if actionLessWritesFile(option) {
				return false
			}
		}
		return true
	case "uniq", "tar", "gtar", "bsdtar", "find", "gfind":
		return actionReadsOnlyWords(words)
	}
	return false
}

// actionStaticWords spells every word of a call, or reports that one is not
// static.
func actionStaticWords(args []*syntax.Word, home string) ([]string, bool) {
	words := make([]string, len(args))
	for i, arg := range args {
		value, known := StaticWord(arg, home)
		if !known {
			return nil, false
		}
		words[i] = value
	}
	return words, true
}

// actionReadsOnlyWords reports a uniq that prints to standard output (at
// most one operand: a second one is the file uniq writes) and a tar listing
// (-t, --list) with only archive, directory, compression and verbosity
// options: both read their operands and write no file, so a link operand to
// a protected file or directory is a read there (GAP-2590); so is a find
// whose actions only read (actionFindListsOnly). words starts with the program.
func actionReadsOnlyWords(words []string) bool {
	if len(words) == 0 {
		return false
	}
	switch programBase(words[0]) {
	case "uniq":
		return actionUniqPrintsOnly(words[1:])
	case "find", "gfind":
		return actionFindListsOnly(words[1:])
	}
	return actionTarListsOnly(words[1:])
}

// actionFindListsOnly reports a find whose actions only read. A child run by
// -exec, -execdir, -ok or -okdir is read-only only when its complete static
// argv names one of the supported readers. Other child commands keep the
// existing conservative verdict. args are the words after the program.
func actionFindListsOnly(args []string) bool {
	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "-delete", "-fprint", "-fprint0", "-fprintf", "-fls":
			return false
		case "-exec", "-execdir", "-ok", "-okdir":
			start := i + 1
			i = start
			for i < len(args) && args[i] != ";" && args[i] != "+" {
				i++
			}
			if i == len(args) || !actionFindReadOnlyChild(args[start:i]) {
				return false
			}
		}
	}
	return true
}

// find invokes its child directly, without shell aliases or functions. Only
// these static programs and arguments are known not to mutate their inputs.
func actionFindReadOnlyChild(words []string) bool {
	if len(words) == 0 {
		return false
	}
	switch words[0] {
	case "ls", "stat", "cat", "wc", "head":
	default:
		return false
	}
	for _, word := range words[1:] {
		if actionReadOptionMayWrite(word) {
			return false
		}
	}
	return true
}

func actionUniqPrintsOnly(args []string) bool {
	operands, options := 0, true
	for i := 0; i < len(args); i++ {
		value := args[i]
		switch {
		case options && value == "--":
			options = false
		case options && strings.HasPrefix(value, "--"):
			name, _, attached := strings.Cut(value, "=")
			if !attached && (name == "--skip-fields" || name == "--skip-chars" || name == "--check-chars") {
				i++ // the number
			}
		case options && len(value) > 1 && value[0] == '-':
			if strings.IndexByte("fsw", value[len(value)-1]) >= 0 {
				i++ // -f N, -s N, -w N
			}
		default:
			operands++
		}
	}
	return operands <= 1
}

var actionTarListLongOptions = map[string]bool{
	"--list": true, "--verbose": true, "--gzip": true, "--gunzip": true, "--bzip2": true, "--xz": true, "--zstd": true,
}

func actionTarListsOnly(args []string) bool {
	list, values, options := false, 0, true
	archive := func(value string) bool { return !strings.Contains(value, ":") } // host:file runs a remote shell
	for i, value := range args {
		if values > 0 {
			values--
			continue
		}
		switch {
		case !options:
		case value == "--":
			options = false
		case strings.HasPrefix(value, "--"):
			name, attached, hasValue := strings.Cut(value, "=")
			switch {
			case name == "--file" || name == "--directory":
				if !hasValue {
					values++
				} else if name == "--file" && !archive(attached) {
					return false
				}
			case !actionTarListLongOptions[name] || hasValue:
				return false
			}
			list = list || name == "--list"
		case strings.HasPrefix(value, "-") || i == 0:
			// A first word without a dash is the old bundled form (tvf).
			letters := strings.TrimPrefix(value, "-")
			for j := 0; j < len(letters); j++ {
				switch letters[j] {
				case 't':
					list = true
				case 'v', 'z', 'j', 'J', 'Z':
				case 'f', 'C':
					if rest := letters[j+1:]; rest != "" && value[0] == '-' {
						if letters[j] == 'f' && !archive(rest) {
							return false
						}
						j = len(letters)
						continue
					}
					values++
				default:
					return false
				}
			}
		}
	}
	return list && values == 0
}

func actionWindowsWordMentionsTarget(word, cwd, home string, stateOnly bool, memo *TargetMemo) bool {
	return actionWindowsWordNamesTarget(word, cwd, home, stateOnly, true, memo)
}

// actionWindowsCandidateChecks counts the candidate checks of Windows target
// scans, so a test can prove a long command checks each distinct candidate
// once (GAP-2279).
var actionWindowsCandidateChecks atomic.Int64

// actionWindowsWordNamesTarget reports a protected-named word; sshDirectory
// also counts the bare .ssh directory. The answer for one candidate depends
// only on the candidate, cwd, home, the two flags and the file system, so
// memo keeps it for the rest of the evaluation: the field 1 of a0=1; a1=1;
// ... was placed once per statement (rel-1-0-2:GAP-0568).
func actionWindowsWordNamesTarget(word, cwd, home string, stateOnly, sshDirectory bool, memo *TargetMemo) bool {
	var check, checkOnce func(candidate string) bool
	check = func(candidate string) bool {
		key := memoWordKey{candidate: candidate, cwd: cwd, home: home, stateOnly: stateOnly, sshDirectory: sshDirectory}
		if answer, ok := memo.word(key); ok {
			return answer
		}
		memo.noteCandidateWork()
		answer := checkOnce(candidate)
		memo.storeWord(key, answer)
		return answer
	}
	checkOnce = func(candidate string) bool {
		actionWindowsCandidateChecks.Add(1)
		candidate = strings.ReplaceAll(candidate, "`", "")
		if strings.ContainsAny(candidate, "\r\n") {
			// A word of several lines (a here-string body, such as the
			// script of bash -lc @'...'@) is no single path: Windows names
			// hold no line break. Each line is read as a candidate. As one
			// glob pattern, the whole body named a directory that does not
			// exist, which counts as a possibly protected expansion, so any
			// body with a / and a * was a protected target (GAP-0781).
			for _, line := range strings.FieldsFunc(candidate, func(r rune) bool { return r == '\r' || r == '\n' }) {
				if line = strings.TrimSpace(line); line != "" && check(line) {
					return true
				}
			}
			return false
		}
		if strings.ContainsAny(candidate, "*?[]") {
			return !stateOnly && (actionWindowsProtectedGlobReach(candidate, cwd, home) ||
				actionWindowsDynamicKeyPath(candidate))
		}
		resolved, ok := actionWindowsPath(candidate, cwd, home)
		if !ok {
			if stateOnly {
				return false
			}
			return actionWindowsUnresolvedUnderSSH(candidate, cwd, home) ||
				actionWindowsDynamicKeyPath(candidate)
		}
		root, ok := actionWindowsPath(home, cwd, home)
		if !ok {
			return false
		}
		if stateOnly {
			if strings.HasPrefix(resolved, root+"/") &&
				actionProtectedStateRelative(strings.TrimPrefix(resolved, root+"/")) {
				return true
			}
			if runtime.GOOS == "windows" {
				// The word's links and junctions are followed, as for the
				// keys files (actionWindowsLinkReachesKeyFile): a write
				// through a disk link to ~\.defenseclaw writes the state
				// (rel-1-0-6:GAP-0213). A hard link is still matched.
				return actionProtectedStatePath(filepath.FromSlash(resolved), memo.stateHome(home))
			}
			return false
		}
		if resolved == root+"/.ssh" {
			return sshDirectory
		}
		protected, _ := actionWindowsProtected(candidate, cwd, home, false)
		return protected || actionWindowsLinkReachesKeyFile(resolved, home, memo)
	}
	if check(word) {
		return true
	}
	for _, field := range strings.FieldsFunc(word, func(r rune) bool {
		return strings.ContainsRune(" \t\r\n'\"(),;|&<>{}=", r)
	}) {
		if check(field) {
			return true
		}
		if colon := strings.IndexByte(field, ':'); colon > 1 && field[0] == '-' && check(field[colon+1:]) {
			return true
		}
	}
	return false
}

// actionWindowsLinkReachesKeyFile follows, on a native Windows host, the
// symbolic links and junctions of a resolved word (an alias in the cwd of
// authorized_keys, or a junction to ~\.ssh): the write lands in the file the
// links name (GAP-1515). Elsewhere the Windows file system is not there to
// read.
func actionWindowsLinkReachesKeyFile(resolved, home string, memo *TargetMemo) bool {
	if runtime.GOOS != "windows" || resolved == "" {
		return false
	}
	physical, ok := memo.resolveWriteTarget(filepath.FromSlash(resolved))
	if !ok || samePathName(physical, filepath.FromSlash(resolved)) {
		return false
	}
	for _, key := range memo.ProtectedAuthorizedKeysPaths(home) {
		if samePathName(physical, key) {
			return true
		}
	}
	return false
}

// A dynamic Windows word names a key only when the component after a .ssh
// directory is a key file name or a pattern that can select one; a longer
// literal name such as authorized_keys.bak is another file.
func actionWindowsDynamicKeyPath(value string) bool {
	value = strings.ToLower(strings.ReplaceAll(value, `\`, "/"))
	if !strings.ContainsAny(value, "$%`") {
		return false
	}
	value = actionWindowsDynamicPart.ReplaceAllString(value, "\x00")
	for rest := value; ; {
		index := strings.Index(rest, "/.ssh/")
		if index < 0 {
			return false
		}
		rest = rest[index+len("/.ssh/"):]
		end := strings.IndexAny(rest, "/\"' ;|&,)")
		if end < 0 {
			end = len(rest)
		}
		var component actionKeyComponent
		for i := 0; i < end; i++ {
			switch rest[i] {
			case 0, '*':
				component.wildcard("*")
			case '?':
				component.wildcard("?")
			default:
				component.literal(rest[i])
			}
		}
		if component.selects(false) {
			return true
		}
	}
}

var actionWindowsDynamicPart = lazyregexp.New(`\$\{[^}]*\}|\$\([^)]*\)|\$[a-z_][a-z0-9_]*(:[a-z_][a-z0-9_]*)?|%[^%/]*%`)

func actionWindowsProtectedGlobReach(pattern, cwd, home string) bool {
	pattern = strings.ReplaceAll(pattern, `\`, "/")
	lower := strings.ToLower(pattern)
	for _, prefix := range []string{"%userprofile%", "%homedrive%%homepath%", "$env:userprofile", "${env:userprofile}", "$home", "${home}", "~"} {
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") {
			pattern = strings.ReplaceAll(home, `\`, "/") + pattern[len(prefix):]
			break
		}
	}
	if !actionWindowsHome(pattern) {
		pattern = strings.TrimRight(strings.ReplaceAll(cwd, `\`, "/"), "/") + "/" + pattern
	}
	pattern = strings.ToLower(path.Clean(pattern))
	root, ok := actionWindowsPath(home, cwd, home)
	if !ok {
		return false
	}
	ssh := root + "/.ssh"
	if matched, _ := path.Match(pattern, ssh); matched {
		return true
	}
	for _, name := range AuthorizedKeysFiles {
		if matched, _ := path.Match(pattern, ssh+"/"+name); matched {
			return true
		}
	}
	parent, base := path.Split(pattern)
	if parent == "" {
		parent = "."
	}
	if _, err := path.Match(base, ""); err != nil {
		return false
	}
	// On the host, expand every component through junctions and links
	// (GAP-1445).
	if runtime.GOOS == "windows" && filepath.IsAbs(filepath.FromSlash(pattern)) && actionProtectedFileGlobReachAs(
		filepath.FromSlash(pattern), cwd, newProtectedFiles(home), filepath.Join(home, ".ssh"), home, nil, true) {
		return true
	}
	if strings.ContainsAny(parent, "*?[") {
		return false
	}
	resolved, ok := actionWindowsPath(strings.TrimSuffix(parent, "/"), cwd, home)
	if !ok {
		return false
	}
	if resolved != ssh {
		return false
	}
	for _, name := range AuthorizedKeysFiles {
		if matched, _ := path.Match(strings.ToLower(base), name); matched {
			return true
		}
	}
	return false
}

// An unresolved leaf under .ssh is still a protected-directory use. Keep
// this lexical fallback scoped to that directory; other unknown paths audit.
func actionWindowsUnresolvedUnderSSH(value, cwd, home string) bool {
	value = strings.ReplaceAll(strings.TrimSpace(value), `\`, "/")
	lower := strings.ToLower(value)
	for _, prefix := range []string{"%userprofile%", "%homedrive%%homepath%", "$env:userprofile", "${env:userprofile}", "$home", "${home}", "~"} {
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") {
			value = strings.ReplaceAll(home, `\`, "/") + value[len(prefix):]
			break
		}
	}
	if !actionWindowsHome(value) {
		value = strings.TrimRight(strings.ReplaceAll(cwd, `\`, "/"), "/") + "/" + value
	}
	root := strings.ToLower(path.Clean(strings.ReplaceAll(home, `\`, "/"))) + "/.ssh/"
	return strings.HasPrefix(strings.ToLower(path.Clean(value)), root)
}

// actionWindowsLiteralHereDocumentTarget reads the literal body of a POSIX
// here-document under a Windows home. Git Bash passes that body through
// unchanged, backslashes of an absolute Windows path included, while the
// POSIX text scan reads those backslashes as escapes (GAP-1504).
func actionWindowsLiteralHereDocumentTarget(command, home string, memo *TargetMemo) bool {
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	// The key files are listed at the first here-document: a command
	// with none pays no walk.
	var targets []string
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		redirect, ok := node.(*syntax.Redirect)
		if !ok || redirect.Hdoc == nil || redirect.Op != syntax.Hdoc && redirect.Op != syntax.DashHdoc {
			return true
		}
		if targets == nil {
			for _, target := range memo.ProtectedAuthorizedKeysPaths(home) {
				targets = append(targets, strings.ToLower(strings.ReplaceAll(target, "\\", "/")))
			}
		}
		for _, part := range redirect.Hdoc.Parts {
			literal, ok := part.(*syntax.Lit)
			if !ok {
				continue
			}
			body := strings.ToLower(strings.ReplaceAll(literal.Value, "\\", "/"))
			for _, target := range targets {
				for start := 0; start < len(body); {
					index := strings.Index(body[start:], target)
					if index < 0 {
						break
					}
					index += start
					end := index + len(target)
					before, _ := utf8.DecodeLastRuneInString(body[:index])
					after, _ := utf8.DecodeRuneInString(body[end:])
					singleQuoted := before == '\'' && after == '\''
					if (index == 0 || actionWindowsHereDocDelimiter(before) || singleQuoted) &&
						(end == len(body) || actionWindowsHereDocDelimiter(after) || singleQuoted) {
						found = true
						return false
					}
					start = index + 1
				}
			}
		}
		return true
	})
	return found
}

// actionWindowsHereDocDelimiter: a Windows file name may hold punctuation and
// Unicode, so only white space and the characters a name cannot hold end an
// unquoted path in a here-document body.
func actionWindowsHereDocDelimiter(value rune) bool {
	return unicode.IsSpace(value) || strings.ContainsRune("\"<>|?*", value)
}

// actionSpelledWindowsTarget judges a POSIX-reading value under a Windows
// home by its spelling. The POSIX parser has already expanded HOME and the
// unquoted tildes: a value that still holds $, % or a backtick, or a quoted
// ~, is literal text in the POSIX shell, and the Windows expansion of it
// would name a protected path the shell never reaches (GAP-1504).
func actionSpelledWindowsTarget(value string, tilde bool, base, home string, stateOnly bool) bool {
	if strings.ContainsAny(value, "$%`") || !tilde && (value == "~" || strings.HasPrefix(value, "~/")) {
		return false
	}
	if strings.ContainsAny(value, "*?[]") {
		return !stateOnly && actionWindowsProtectedGlobReach(value, base, home)
	}
	resolved, ok := actionWindowsPathFromPOSIX(value, base, home)
	if !ok {
		return false
	}
	root, ok := actionWindowsPath(home, base, home)
	if !ok {
		return false
	}
	if stateOnly {
		return strings.HasPrefix(resolved, root+"/") &&
			actionProtectedStateRelative(strings.TrimPrefix(resolved, root+"/"))
	}
	if resolved == root+"/.ssh" {
		return true
	}
	for _, name := range AuthorizedKeysFiles {
		if resolved == root+"/.ssh/"+name {
			return true
		}
	}
	return false
}

// actionStateEntryMayDiffer reports that the entry reading of value (its
// directory followed, its name kept) can name another file than its full
// walk: only when the last name is itself a link. An absolute value whose
// last name is missing or not a link costs one Lstat, not a second walk
// (GAP-2279 answer budget); a relative value is always read. missing reports
// an absolute value that Lstat found not to exist.
func actionStateEntryMayDiffer(value string) (differ, missing bool) {
	if !filepath.IsAbs(value) {
		return true, false
	}
	info, err := pathLstat(value)
	if err != nil {
		return !os.IsNotExist(err), os.IsNotExist(err)
	}
	return info.Mode()&os.ModeSymlink != 0, false
}

// actionSSHSetupMode reports a mode that only tightens the .ssh folder to
// its owner, as ssh needs it (chmod 700 ~/.ssh).
func actionSSHSetupMode(mode string) bool {
	switch mode {
	case "700", "0700", "go-rwx", "og-rwx", "go=", "og=", "u=rwx,go=", "u=rwx,og=":
		return true
	}
	return false
}

// actionSSHDirectorySetupArgs reads a mkdir (options only among -p, -v,
// --parents, --verbose and a -m/--mode of actionSSHSetupMode) or a chmod
// (only -v, --verbose; a mode of actionSSHSetupMode; no -R) and returns the
// indexes of its operands, or false for any other call or option.
func actionSSHDirectorySetupArgs(words []string) ([]int, bool) {
	if len(words) < 2 {
		return nil, false
	}
	var operands []int
	switch program := programBase(words[0]); program {
	case "mkdir", "gmkdir", "md":
		for i := 1; i < len(words); i++ {
			word := words[i]
			switch {
			case word == "-m" || word == "--mode":
				if i+1 >= len(words) || !actionSSHSetupMode(words[i+1]) {
					return nil, false
				}
				i++
			case strings.HasPrefix(word, "--mode="):
				if !actionSSHSetupMode(strings.TrimPrefix(word, "--mode=")) {
					return nil, false
				}
			case strings.HasPrefix(word, "-m") && len(word) > 2:
				if !actionSSHSetupMode(word[2:]) {
					return nil, false
				}
			case word == "--parents" || word == "--verbose" || strings.EqualFold(word, "-force"):
			case len(word) > 1 && strings.HasPrefix(word, "-"):
				if strings.Trim(word[1:], "pv") != "" {
					return nil, false
				}
			default:
				operands = append(operands, i)
			}
		}
	case "chmod", "gchmod":
		mode := false
		for i := 1; i < len(words); i++ {
			word := words[i]
			switch {
			case word == "-v" || word == "--verbose":
			case !mode:
				if !actionSSHSetupMode(word) {
					return nil, false
				}
				mode = true
			case strings.HasPrefix(word, "-"):
				return nil, false
			default:
				operands = append(operands, i)
			}
		}
	default:
		return nil, false
	}
	return operands, len(operands) > 0
}

// actionSSHDirectorySetupWords returns the operand words of a POSIX mkdir
// or tightening chmod whose every operand is exactly the home's .ssh folder
// (rel-1-0-6:GAP-0298: mkdir -p ~/.ssh && chmod 700 ~/.ssh is the usual step
// before ssh-keygen). Making or tightening the folder writes no keys file;
// a path under the folder, a recursive chmod or another mode keeps the
// target rule.
func actionSSHDirectorySetupWords(call *syntax.CallExpr, values actionValues, cwd, home string) []*syntax.Word {
	if call == nil || len(call.Assigns) != 0 || len(call.Args) < 2 {
		return nil
	}
	words := make([]string, len(call.Args))
	for i, arg := range call.Args {
		value, fixed := actionWordValue(arg, values, cwd, home)
		if !fixed || value == "" {
			return nil
		}
		words[i] = value
	}
	operands, ok := actionSSHDirectorySetupArgs(words)
	if !ok {
		return nil
	}
	ssh := filepath.Clean(filepath.Join(home, ".ssh"))
	resolvedSSH, sshKnown := ResolveWriteTarget(ssh)
	var out []*syntax.Word
	for _, i := range operands {
		// The value reader cleans a ~/ path, so the word is checked as
		// written too.
		var raw strings.Builder
		if syntax.NewPrinter().Print(&raw, call.Args[i]) != nil || actionPathHasDotComponent(raw.String()) ||
			actionPathHasDotComponent(words[i]) {
			return nil
		}
		operand := filepath.Clean(OperandPath(words[i], cwd))
		if !samePathName(operand, ssh) {
			resolved, known := ResolveWriteTarget(operand)
			if !known || !sshKnown || !samePathName(resolved, resolvedSSH) {
				return nil
			}
		}
		out = append(out, call.Args[i])
	}
	return out
}

// actionWindowsSSHDirectorySetupWords is actionSSHDirectorySetupWords for a
// statement of the Windows scan (mkdir, md, the Git Bash chmod): the
// indexes of its operands when every one names exactly the home's .ssh
// folder (rel-1-0-6:GAP-0298).
func actionWindowsSSHDirectorySetupWords(statement []string, dir, home string) []int {
	operands, ok := actionSSHDirectorySetupArgs(statement)
	if !ok {
		return nil
	}
	root, known := actionWindowsPath(home, dir, home)
	if !known {
		return nil
	}
	for _, i := range operands {
		if actionPathHasDotComponent(statement[i]) {
			return nil
		}
		resolved, known := actionWindowsPath(strings.TrimRight(statement[i], `/\`), dir, home)
		if !known || resolved != root+"/.ssh" {
			return nil
		}
	}
	return operands
}

// actionSSHSetupAndReadsOnly reports a command whose every top-level
// statement (joined by ;, && or ||) is a known read-only statement or a
// mkdir or tightening chmod of exactly the home's .ssh folder, with no
// redirect, pipeline, background or subshell: mkdir -p ~/.ssh && ls -la
// ~/.ssh writes no keys file (rel-1-0-6:GAP-0298).
func actionSSHSetupAndReadsOnly(file *syntax.File, cwd, home string) bool {
	setup := false
	var statement func(*syntax.Stmt) bool
	statement = func(stmt *syntax.Stmt) bool {
		if stmt == nil || stmt.Background || stmt.Negated || stmt.Coprocess {
			return false
		}
		if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok {
			return len(stmt.Redirs) == 0 && (pair.Op == syntax.AndStmt || pair.Op == syntax.OrStmt) &&
				statement(pair.X) && statement(pair.Y)
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(stmt.Redirs) != 0 {
			return false
		}
		if words := actionSSHDirectorySetupWords(call, actionValues{"HOME": home}, cwd, home); len(words) > 0 {
			setup = true
			return true
		}
		return actionKnownReadOnlyShell(&syntax.File{Stmts: []*syntax.Stmt{stmt}}, home)
	}
	for _, stmt := range file.Stmts {
		if !statement(stmt) {
			return false
		}
	}
	return setup
}

// actionPathHasDotComponent reports a path word with a . or .. component:
// mkdir -p ~/.ssh/authorized_keys/.. makes the keys name a folder, so the
// operand is judged as written, not after Clean (rel-1-0-6:GAP-0298 review).
func actionPathHasDotComponent(word string) bool {
	for _, part := range strings.FieldsFunc(word, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == "." || part == ".." {
			return true
		}
	}
	return false
}

// actionWordMayBePattern reports a word with an unquoted pattern character: the
// shell expands it to the names it selects, which may be a protected file.
func actionWordMayBePattern(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	for _, part := range word.Parts {
		if lit, ok := part.(*syntax.Lit); ok && strings.ContainsAny(lit.Value, "*?[") {
			return true
		}
	}
	return false
}
