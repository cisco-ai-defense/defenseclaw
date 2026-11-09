// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"unicode"
)

// hermesKeptHookEvents lists the hook events Setup registers that still hold an
// entry DefenseClaw does not own (hermesHookEntryOwned) and that names a
// DefenseClaw hook (hermesCommandNamesDefenseClawHook). Such an entry is the
// user content Setup, repair and teardown keep, and it may be a hand-edited
// copy of a DefenseClaw hook. A user's own unrelated hook is kept without a
// word: the notice tells the user to remove entries that run a DefenseClaw
// hook, and that is no advice for a hook of theirs (GAP-0940).
func hermesKeptHookEvents(hooks map[string]interface{}, hookScript string, recognizedCommands map[string]struct{}) []string {
	required := hermesHookEventSet()
	var events []string
	for event, raw := range hooks {
		if _, ok := required[event]; !ok {
			continue
		}
		entries, _ := hermesHookList(raw)
		for _, entry := range entries {
			if command, hasCommand := hermesHookEntryCommand(entry); hasCommand &&
				!hermesHookEntryOwned(entry, hookScript, recognizedCommands) &&
				hermesCommandNamesDefenseClawHook(command, hookScript) {
				events = append(events, event)
				break
			}
		}
	}
	sort.Strings(events)
	return events
}

// hermesDefenseClawLauncherFlag finds the native launcher Hermes flag as a
// whole word: a character that can continue a name before or after it means
// another command.
var hermesDefenseClawLauncherFlag = regexp.MustCompile(
	`(?:^|[^A-Za-z0-9._-])` + regexp.QuoteMeta(nativeHookFlag+"hermes") + `(?:$|[^A-Za-z0-9._-])`)

// hermesWindowsCommands says Hermes runs the command the Windows way: every
// backslash separates folders. On Linux and macOS a POSIX shell reads the
// command, and a backslash there is an escape (hermesCommandWords).
var hermesWindowsCommands = runtime.GOOS == "windows"

// hermesCommandWords splits a command into the words the platform's shell
// reads, honouring single and double quotes, and breaks unquoted words at the
// shell operators and at "=" so a path after VAR= or after && is a word of its
// own. On Linux and macOS a backslash outside quotes escapes the next
// character (my\ hermes-hook.sh is the one word "my hermes-hook.sh" and
// my\hermes-hook.sh the word "myhermes-hook.sh", both files of the user);
// inside double quotes it escapes only a double quote, "$", a backtick or a
// backslash, and inside single quotes nothing, and a backslash that stays is
// read again when the quoted text is a shell -c argument. On Windows every
// backslash is a path separator and reads as "/".
func hermesCommandWords(command string) []string {
	const singleQuote, doubleQuote = rune(0x27), rune(0x22)
	var words []string
	var word strings.Builder
	started := false
	var quote rune
	flush := func() {
		if started {
			words = append(words, word.String())
		}
		word.Reset()
		started = false
	}
	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case r == '\\':
			started = true
			following := rune(0)
			if i+1 < len(runes) {
				following = runes[i+1]
			}
			switch {
			case hermesWindowsCommands:
				word.WriteRune('/')
			case quote == singleQuote || following == 0 ||
				(quote == doubleQuote && !strings.ContainsRune(string(doubleQuote)+"$`\\", following)):
				word.WriteRune('\\')
			default:
				i++
				if following != '\n' { // a backslash before a newline continues the line
					word.WriteRune(following)
				}
			}
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
		case r == singleQuote || r == doubleQuote:
			quote, started = r, true
		case unicode.IsSpace(r) || strings.ContainsRune(";&|<>()=", r):
			flush()
		default:
			word.WriteRune(r)
			started = true
		}
	}
	flush()
	return words
}

// hermesWordNamesDefenseClawHook reports whether one word of a command is a
// path DefenseClaw owns after the path is cleaned: the generated script (or an
// edited copy of it, hermes-hook.sh.off), or anything in the hooks folder,
// spelled absolute, with ~, with $HOME or relative. The clean path decides,
// so .defenseclaw/hooks/../user-hook.sh is a file of the user and
// hermes-hook.sh-audit or my-hermes-hook.sh is another name.
func hermesWordNamesDefenseClawHook(word, hooksDir string) bool {
	clean := path.Clean(word)
	if hooksDir != "" && (clean == hooksDir || strings.HasPrefix(clean, hooksDir+"/")) {
		return true
	}
	const folder = ".defenseclaw/hooks"
	if clean == folder || strings.HasPrefix(clean, folder+"/") ||
		strings.HasSuffix(clean, "/"+folder) || strings.Contains(clean, "/"+folder+"/") {
		return true
	}
	base := path.Base(clean)
	return base == hermesHookScriptName || strings.HasPrefix(base, hermesHookScriptName+".")
}

// hermesCommandNamesDefenseClawHook reports whether a kept entry command
// names a DefenseClaw hook: a word that is the generated script or a file in
// the hooks folder (see hermesWordNamesDefenseClawHook), the argument of a
// shell -c read the same way, or the native launcher Hermes flag. It only
// picks which kept entries are listed; ownership never reads the command, so
// no entry is changed, claimed or removed because of it.
func hermesCommandNamesDefenseClawHook(command, hookScript string) bool {
	hooksDir := ""
	if hookScript != "" {
		hooksDir = path.Clean(filepath.ToSlash(filepath.Dir(hookScript)))
	}
	if hermesDefenseClawLauncherFlag.MatchString(command) {
		return true
	}
	previous := ""
	for _, word := range hermesCommandWords(command) {
		if hermesWordNamesDefenseClawHook(word, hooksDir) ||
			(previous == "-c" && word != command && hermesCommandNamesDefenseClawHook(word, hookScript)) {
			return true
		}
		previous = word
	}
	return false
}

// warnHermesKeptHookEntries says once, after Setup or teardown (operation),
// which events keep hook entries DefenseClaw did not write.
func warnHermesKeptHookEntries(operation, path string, hooks map[string]interface{}, hookScript string, recognizedCommands map[string]struct{}) {
	if kept := hermesKeptHookEvents(hooks, hookScript, recognizedCommands); len(kept) > 0 {
		fmt.Fprintf(hermesSetupWarningOutput, "[connector] hermes %s: kept hook entries in %s (events: %s) that DefenseClaw did not write; remove any that runs a DefenseClaw hook by hand\n", operation, path, strings.Join(kept, ", "))
	}
}
