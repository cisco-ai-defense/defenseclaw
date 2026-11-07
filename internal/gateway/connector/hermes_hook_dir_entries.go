// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"io/fs"
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
// file in the managed hooks directory of hookScript (a POSIX script path). A
// path word is read as text: quotes and a backslash before a space are
// dropped, ~/ and $HOME/ and ${HOME}/ stand for the account home this
// connector is bound to (userHomeDir), a word may hold spaces, and the word is
// cleaned as a path, so "/./", "//" and "other/../" steps count as the
// directory they lead to and a ".." step that leaves it does not. A directory
// that only starts with the same letters does not count either. No shell is
// run or interpreted: a command that reaches a managed file through a link, a
// variable or a relative path does not name the directory.
func hookCommandNamesHookDir(command, hookScript string) bool {
	hookScript = strings.TrimSpace(hookScript)
	if runtime.GOOS == "windows" || !strings.HasPrefix(hookScript, "/") {
		return false
	}
	dir := path.Dir(hookScript)
	if dir == "/" || dir == "." {
		return false
	}
	home := ""
	if h := strings.TrimSpace(userHomeDir()); h != "" {
		home = path.Clean(filepath.ToSlash(h))
	}
	text := hermesCommandTextReplacer.Replace(command)
	for at := 0; at < len(text); at++ {
		if at > 0 && !strings.ContainsRune(" \t\n=;&|()<>`:{[,", rune(text[at-1])) {
			continue
		}
		rest := text[at:]
		prefix, skip := "", 0
		switch {
		case rest[0] == '/':
		case home != "" && strings.HasPrefix(rest, "~/"):
			prefix, skip = home, 1
		case home != "" && strings.HasPrefix(rest, "$HOME/"):
			prefix, skip = home, len("$HOME")
		case home != "" && strings.HasPrefix(rest, "${HOME}/"):
			prefix, skip = home, len("${HOME}")
		default:
			continue
		}
		if stop := strings.IndexAny(rest, "\n;&|()<>`"); stop >= 0 {
			rest = rest[:stop]
		}
		for end := 0; end <= len(rest); end++ {
			if end < len(rest) && rest[end] != ' ' && rest[end] != '\t' {
				continue
			}
			if strings.HasPrefix(path.Clean(prefix+rest[skip:end]), dir+"/") {
				return true
			}
		}
	}
	return false
}

// hermesCommandTextReplacer drops the quote characters of a hook command and
// reads a backslash-escaped space as a space, so a quoted or escaped path with
// spaces in it is one path word.
var hermesCommandTextReplacer = strings.NewReplacer("'", "", "\"", "", "\\ ", " ")

// keepHermesEditedHooksCopy saves data as a new file next to configPath and
// returns its path. It never writes through, replaces or reuses a file or
// link that is already there: the first free name among the edited-hooks copy
// suffix and numbered ones is created exclusively.
func keepHermesEditedHooksCopy(configPath string, data []byte) (string, error) {
	if err := confineAtomicWritePath(configPath); err != nil {
		return "", err
	}
	for n := 0; n < 100; n++ {
		name := configPath + hermesEditedHooksBackupSuffix
		if n > 0 {
			name = fmt.Sprintf("%s.%d", name, n)
		}
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		_, err = f.Write(data)
		if err == nil {
			err = f.Sync()
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(name)
			return "", err
		}
		return name, nil
	}
	return "", fmt.Errorf("no free name for a copy of %s", configPath)
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
