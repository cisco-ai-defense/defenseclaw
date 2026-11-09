// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
)

// hermesHookEntryRecord is what Setup remembers of the entry it wrote on one
// required Hermes event, in the Hermes home record (hermesHomeSetUp.Hooks).
// It is the only thing the kept-entry notice reads: the notice never looks at
// what a command says, because a command that merely mentions a DefenseClaw
// hook name (as data, in a comment) runs no DefenseClaw hook (GAP-0940).
type hermesHookEntryRecord struct {
	// Shape is the hash of the entry Setup wrote without its command (timeout,
	// matcher and the other fields), so the entry a person edited in place is
	// told from a hook that is theirs.
	Shape string `json:"shape"`
	// Kept lists the hashes of the commands of entries Setup found in the place
	// of its own edited entry and kept. They stay listed for as long as the
	// same command stays in the file.
	Kept []string `json:"kept,omitempty"`
	// Seen lists the hashes of the commands of the other entries the event
	// held when Setup last wrote it: hooks that belong to a person, whatever
	// shape they have. An entry listed here is never taken for the entry Setup
	// wrote.
	Seen []string `json:"seen,omitempty"`
}

func hermesCommandHash(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

// hermesEntryShape hashes every field of a hook entry except its command.
func hermesEntryShape(entry map[string]interface{}) string {
	rest := make(map[string]interface{}, len(entry))
	for key, value := range entry {
		if key != "command" {
			rest[key] = value
		}
	}
	data, _ := json.Marshal(rest)
	return hermesCommandHash(string(data))
}

// hermesRecordDir is the data directory that holds the record, read from the
// generated script <data dir>/hooks/hermes-hook.sh. Windows and any other
// command have no record: the notice is then not printed.
func hermesRecordDir(hookScript string) string {
	dir := filepath.Dir(hookScript)
	if runtime.GOOS == "windows" || filepath.Base(dir) != "hooks" {
		return ""
	}
	return filepath.Dir(dir)
}

// hermesKeptCommands lists the hashes of the entries of one event that Setup
// keeps as the place of an entry DefenseClaw wrote and a person has edited: an
// entry DefenseClaw does not own that was kept before and is still there, or,
// when the event no longer holds an entry DefenseClaw owns, the one entry that
// has the shape of the entry Setup wrote and is not a hook Setup saw there
// already (record.Seen). Setup wrote one entry, so more than one candidate
// means one of them is not an edit of it, and none is listed. Without a record
// of the event nothing is listed.
func hermesKeptCommands(prior hermesHomeSetUp, event string, raw interface{}, hookScript string, recognizedCommands map[string]struct{}) []string {
	record, ok := prior.Hooks[event]
	if !ok {
		return nil
	}
	entries, _ := hermesHookList(raw)
	ownedLeft := false
	for _, entry := range entries {
		ownedLeft = ownedLeft || hermesHookEntryOwned(entry, hookScript, recognizedCommands)
	}
	var kept, candidates []string
	for _, entry := range entries {
		command, hasCommand := hermesHookEntryCommand(entry)
		if !hasCommand || hermesHookEntryOwned(entry, hookScript, recognizedCommands) {
			continue
		}
		hash := hermesCommandHash(command)
		switch {
		case slices.Contains(kept, hash) || slices.Contains(candidates, hash):
		case slices.Contains(record.Kept, hash):
			kept = append(kept, hash)
		case !ownedLeft && !slices.Contains(record.Seen, hash) && record.Shape == hermesEntryShape(entry.(map[string]interface{})):
			candidates = append(candidates, hash)
		}
	}
	if len(candidates) == 1 {
		kept = append(kept, candidates...)
	}
	sort.Strings(kept)
	return kept
}

// hermesSeenCommands lists the hashes of the commands of the entries of one
// event that DefenseClaw does not own and Setup did not just keep: the hooks
// that belong to a person.
func hermesSeenCommands(entries []interface{}, hookScript string, recognizedCommands map[string]struct{}, kept []string) []string {
	var seen []string
	for _, entry := range entries {
		command, hasCommand := hermesHookEntryCommand(entry)
		if !hasCommand || hermesHookEntryOwned(entry, hookScript, recognizedCommands) {
			continue
		}
		if hash := hermesCommandHash(command); !slices.Contains(kept, hash) && !slices.Contains(seen, hash) {
			seen = append(seen, hash)
		}
	}
	sort.Strings(seen)
	return seen
}

// hermesRecordedKeptEvents lists, for teardown, the required events whose file
// still holds an entry the record says Setup kept.
func hermesRecordedKeptEvents(prior hermesHomeSetUp, hooks map[string]interface{}, hookScript string, recognizedCommands map[string]struct{}) []string {
	var events []string
	for event := range hermesHookEventSet() {
		record := prior.Hooks[event]
		entries, _ := hermesHookList(hooks[event])
		for _, entry := range entries {
			if command, hasCommand := hermesHookEntryCommand(entry); hasCommand &&
				slices.Contains(record.Kept, hermesCommandHash(command)) &&
				!hermesHookEntryOwned(entry, hookScript, recognizedCommands) {
				events = append(events, event)
				break
			}
		}
	}
	sort.Strings(events)
	return events
}

// warnHermesKeptHookEntries says once, after Setup or teardown (operation),
// which events keep an entry DefenseClaw wrote and a person edited.
func warnHermesKeptHookEntries(operation, path string, events []string) {
	if len(events) > 0 {
		fmt.Fprintf(hermesSetupWarningOutput, "[connector] hermes %s: kept hook entries in %s (events: %s) that DefenseClaw did not write; remove any that runs a DefenseClaw hook by hand\n", operation, path, strings.Join(events, ", "))
	}
}
