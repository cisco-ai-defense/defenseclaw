// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

// until 1.1: what the teardown of a removed connector (OmniGent) leaves for
// the user to remove by hand. The maintenance gateway's `connector teardown
// --json` lists it; Setup shows it at the end: in the wizard, in the setup
// log and, in quiet mode, on stdout. Delete with the removed connectors.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

type removedConnectorLeftover struct {
	Path string `json:"path"`
	What string `json:"what"`
	Step string `json:"step"`
}

var removedConnectorNotes struct {
	sync.Mutex
	byConnector map[string][]removedConnectorLeftover
	order       []string
}

// recordRemovedConnectorLeftovers keeps the leftovers a teardown's JSON
// output lists. The latest teardown of a connector wins: it lists what is
// left after it.
func recordRemovedConnectorLeftovers(connectorName string, output []byte) {
	var leftovers []removedConnectorLeftover
	found := false
	for _, line := range bytes.Split(output, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var payload struct {
			Leftovers *[]removedConnectorLeftover `json:"leftovers"`
		}
		if json.Unmarshal(line, &payload) == nil && payload.Leftovers != nil {
			leftovers, found = *payload.Leftovers, true
		}
	}
	if !found {
		return
	}
	removedConnectorNotes.Lock()
	defer removedConnectorNotes.Unlock()
	if removedConnectorNotes.byConnector == nil {
		removedConnectorNotes.byConnector = map[string][]removedConnectorLeftover{}
	}
	if _, seen := removedConnectorNotes.byConnector[connectorName]; !seen {
		removedConnectorNotes.order = append(removedConnectorNotes.order, connectorName)
	}
	removedConnectorNotes.byConnector[connectorName] = leftovers
}

// removedConnectorNotesText renders the recorded leftovers ("" for none).
func removedConnectorNotesText() string {
	removedConnectorNotes.Lock()
	defer removedConnectorNotes.Unlock()
	var b strings.Builder
	for _, name := range removedConnectorNotes.order {
		leftovers := removedConnectorNotes.byConnector[name]
		if len(leftovers) == 0 {
			continue
		}
		label := name
		switch name {
		case "omnigent":
			label = "OmniGent"
		case "openhands":
			label = "OpenHands"
		}
		fmt.Fprintf(&b, "%s support was removed in DefenseClaw 1.0.4. Left for you to remove by hand:\r\n", label)
		for _, item := range leftovers {
			fmt.Fprintf(&b, "  - %s: %s. To remove: %s.\r\n", item.Path, item.What, item.Step)
		}
	}
	return b.String()
}
