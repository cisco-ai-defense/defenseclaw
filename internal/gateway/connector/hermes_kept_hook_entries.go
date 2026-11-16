// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/sha256"
	"encoding/hex"
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
	// Wrote lists the hashes of the commands Setup itself wrote on the event,
	// the newest last. It is the only identity the notice accepts: an entry is
	// written by DefenseClaw only if Setup recorded writing its exact command.
	// An entry whose command was edited, or a hook of a person that Setup never
	// wrote, is not in it and gets no notice (an unprovable notice is omitted).
	Wrote []string `json:"wrote,omitempty"`
	// Kept lists the hashes of the commands of entries that Setup wrote
	// earlier and that DefenseClaw no longer owns (for example the launcher
	// moved), so Setup leaves them in the file. They stay listed for as long
	// as the same command stays in the file.
	Kept []string `json:"kept,omitempty"`
}

// hermesWroteLimit bounds Wrote: the newest commands Setup wrote on an event.
const hermesWroteLimit = 8

func hermesCommandHash(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

// hermesWroteWith is the Wrote list of record with the command Setup writes now.
func hermesWroteWith(record hermesHookEntryRecord, command string) []string {
	hash := hermesCommandHash(command)
	wrote := slices.DeleteFunc(slices.Clone(record.Wrote), func(other string) bool { return other == hash })
	wrote = append(wrote, hash)
	if len(wrote) > hermesWroteLimit {
		wrote = wrote[len(wrote)-hermesWroteLimit:]
	}
	return wrote
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
// leaves in the file although DefenseClaw no longer owns them: entries whose
// exact command the record says Setup wrote (record.Wrote) or kept before
// (record.Kept). Nothing else is listed, whatever shape an entry has. Without a
// record of the event nothing is listed.
func hermesKeptCommands(prior hermesHomeSetUp, event string, raw interface{}, hookScript string, recognizedCommands map[string]struct{}) []string {
	record, ok := prior.Hooks[event]
	if !ok {
		return nil
	}
	entries, _ := hermesHookList(raw)
	var kept []string
	for _, entry := range entries {
		command, hasCommand := hermesHookEntryCommand(entry)
		if !hasCommand || hermesHookEntryOwned(entry, hookScript, recognizedCommands) {
			continue
		}
		hash := hermesCommandHash(command)
		if (slices.Contains(record.Wrote, hash) || slices.Contains(record.Kept, hash)) && !slices.Contains(kept, hash) {
			kept = append(kept, hash)
		}
	}
	sort.Strings(kept)
	return kept
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
