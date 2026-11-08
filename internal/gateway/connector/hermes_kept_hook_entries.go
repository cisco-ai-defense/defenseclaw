// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"sort"
	"strings"
)

// hermesKeptHookEvents lists the hook events Setup registers that still hold an
// entry DefenseClaw does not own (hermesHookEntryOwned). Such an entry is the
// user content Setup, repair and teardown keep. Nothing is read from its
// command: whether it runs a DefenseClaw hook cannot be told from the text, so
// every kept entry on these events is listed and the user decides.
func hermesKeptHookEvents(hooks map[string]interface{}, hookScript string, recognizedCommands map[string]struct{}) []string {
	required := hermesHookEventSet()
	var events []string
	for event, raw := range hooks {
		if _, ok := required[event]; !ok {
			continue
		}
		entries, _ := hermesHookList(raw)
		for _, entry := range entries {
			if _, hasCommand := hermesHookEntryCommand(entry); hasCommand && !hermesHookEntryOwned(entry, hookScript, recognizedCommands) {
				events = append(events, event)
				break
			}
		}
	}
	sort.Strings(events)
	return events
}

// warnHermesKeptHookEntries says once, after Setup or teardown (operation),
// which events keep hook entries DefenseClaw did not write.
func warnHermesKeptHookEntries(operation, path string, hooks map[string]interface{}, hookScript string, recognizedCommands map[string]struct{}) {
	if kept := hermesKeptHookEvents(hooks, hookScript, recognizedCommands); len(kept) > 0 {
		fmt.Fprintf(hermesSetupWarningOutput, "[connector] hermes %s: kept hook entries in %s (events: %s) that DefenseClaw did not write; remove any that runs a DefenseClaw hook by hand\n", operation, path, strings.Join(kept, ", "))
	}
}
