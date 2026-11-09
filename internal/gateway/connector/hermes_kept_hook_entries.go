// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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

// hermesDefenseClawHookWord finds, in a command, the generated script name, the
// hooks folder (.defenseclaw/hooks) or the native launcher flag, each as a whole
// word: a character that can continue a file or folder name (letter, digit, dot,
// underscore, hyphen) before or after it means a different name, such as
// .defenseclaw/hooks-backup or my-hermes-hook.sh. An edited copy of the script
// (hermes-hook.sh.off) keeps its place, so nothing follows the script name.
var hermesDefenseClawHookWord = regexp.MustCompile(
	`(?:^|[^A-Za-z0-9._-])(?:` + regexp.QuoteMeta(hermesHookScriptName) +
		`|\.defenseclaw/hooks(?:$|[^A-Za-z0-9._-])` +
		`|` + regexp.QuoteMeta(nativeHookFlag+"hermes") + `(?:$|[^A-Za-z0-9._-]))`)

// hermesCommandNamesDefenseClawHook reports whether a kept entry command
// names a DefenseClaw hook: the generated script, a file in the hooks folder
// (spelled absolute, with ~ or with $HOME) or the native launcher Hermes
// flag. It only picks which kept entries are listed; ownership never reads the
// command, so no entry is changed, claimed or removed because of it.
func hermesCommandNamesDefenseClawHook(command, hookScript string) bool {
	command = strings.ReplaceAll(command, `\`, "/")
	if hookScript != "" && strings.Contains(command, filepath.ToSlash(filepath.Dir(hookScript))+"/") {
		return true
	}
	return hermesDefenseClawHookWord.MatchString(command)
}

// warnHermesKeptHookEntries says once, after Setup or teardown (operation),
// which events keep hook entries DefenseClaw did not write.
func warnHermesKeptHookEntries(operation, path string, hooks map[string]interface{}, hookScript string, recognizedCommands map[string]struct{}) {
	if kept := hermesKeptHookEvents(hooks, hookScript, recognizedCommands); len(kept) > 0 {
		fmt.Fprintf(hermesSetupWarningOutput, "[connector] hermes %s: kept hook entries in %s (events: %s) that DefenseClaw did not write; remove any that runs a DefenseClaw hook by hand\n", operation, path, strings.Join(kept, ", "))
	}
}
