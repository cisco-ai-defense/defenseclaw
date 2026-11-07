// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// hermesEditedHooksBackupSuffix names the copy teardown keeps of a Hermes
// config.yaml before it removes entries that only name the managed hooks
// directory (hookCommandNamesHookDir).
const hermesEditedHooksBackupSuffix = ".defenseclaw-edited-hooks.bak"

// hookCommandNamesHookDir reports whether the text of a hook command names a
// file in the managed hooks directory of hookScript (a POSIX script path): the
// directory, written absolute or as ~ / $HOME / ${HOME} when it lies in the
// home directory, followed by a path below it. The word is read as text and
// cleaned as a path, so a ".." step that leaves the directory does not count,
// and a directory that only starts with the same letters does not either. No
// shell is run or interpreted: a command that reaches a managed file through a
// link, a variable or a relative path does not name the directory.
func hookCommandNamesHookDir(command, hookScript string) bool {
	hookScript = strings.TrimSpace(hookScript)
	if runtime.GOOS == "windows" || !strings.HasPrefix(hookScript, "/") {
		return false
	}
	dir := path.Dir(hookScript)
	if dir == "/" || dir == "." {
		return false
	}
	spellings := []string{dir}
	if home, err := os.UserHomeDir(); err == nil {
		if rest, ok := strings.CutPrefix(dir, filepath.ToSlash(filepath.Clean(home))+"/"); ok {
			spellings = append(spellings, "~/"+rest, "$HOME/"+rest, "${HOME}/"+rest)
		}
	}
	for _, spelling := range spellings {
		for from := 0; from < len(command); {
			at := strings.Index(command[from:], spelling)
			if at < 0 {
				break
			}
			at += from
			from = at + 1
			if at > 0 && !strings.ContainsRune(" \t\n'\"=;&|()<>`:{", rune(command[at-1])) {
				continue
			}
			word := command[at:]
			if end := strings.IndexAny(word, " \t\n'\";&|()<>`"); end >= 0 {
				word = word[:end]
			}
			if strings.HasPrefix(path.Clean(word), spelling+"/") {
				return true
			}
		}
	}
	return false
}

// hermesDirNamedEntryCount counts the entries of a Hermes hooks mapping that
// are DefenseClaw owned only because their command names the managed hooks
// directory: not a command Setup writes and not the generated script.
func hermesDirNamedEntryCount(hooks map[string]interface{}, hookScript string) int {
	recognized := hermesRecognizedHookCommands(hermesConfiguredHookCommand(hookScript, ""))
	count := 0
	for _, raw := range hooks {
		entries, _ := hermesHookList(raw)
		for _, entry := range entries {
			command, _ := hermesHookEntryCommand(entry)
			if _, exact := recognized[command]; exact || containsHookScript(entry, hookScript) ||
				editedDefenseClawHookEntry(entry, hookScriptBaseName(hookScript)) {
				continue
			}
			if hookCommandNamesHookDir(command, hookScript) {
				count++
			}
		}
	}
	return count
}

// hermesKeptDefenseClawEvents lists the events that still hold an entry whose
// command mentions DefenseClaw after teardown removed the owned ones. Such an
// entry is not one DefenseClaw wrote, so teardown keeps it and says so.
func hermesKeptDefenseClawEvents(hooks map[string]interface{}) []string {
	var events []string
	for event, raw := range hooks {
		entries, _ := hermesHookList(raw)
		for _, entry := range entries {
			command, _ := hermesHookEntryCommand(entry)
			if strings.Contains(strings.ToLower(command), "defenseclaw") {
				events = append(events, event)
				break
			}
		}
	}
	sort.Strings(events)
	return events
}
