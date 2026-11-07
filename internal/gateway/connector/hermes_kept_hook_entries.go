// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"sort"
	"strings"
)

// hermesKeptDefenseClawEvents lists the events that still hold an entry whose
// command mentions DefenseClaw after teardown removed the owned ones. Such an
// entry is not one DefenseClaw wrote (its command is not a string Setup
// records), so teardown keeps it as the user's and says so.
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
