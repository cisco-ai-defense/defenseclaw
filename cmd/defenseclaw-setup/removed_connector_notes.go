// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

// until 1.1: what the teardown of OpenHands or OmniGent could not remove,
// listed as information under the one removal notice. The maintenance gateway's `connector teardown
// --json` lists it; Setup shows it at the end: in the wizard, in the setup
// log and, in quiet mode, on stdout. Delete with the removed connectors.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// removedConnectorNotice is connector.RemovedConnectorNotice.
const removedConnectorNotice = "OpenHands/OmniGent support was removed in 1.0.5; DefenseClaw no longer guards it."

type removedConnectorLeftover struct {
	Path string `json:"path"`
	What string `json:"what"`
	Step string `json:"step"`
}

var removedConnectorNotes struct {
	sync.Mutex
	byConnector map[string][]removedConnectorLeftover
	order       []string
	// moved maps a connector_backups/<connector> folder to where
	// removeDataRootKeepingRemovedConnectorBackups moved it; dataRemoved is
	// the data folder it removed.
	moved       map[string]string
	dataRemoved string
}

// removedConnectorNames are the connectors whose backups a data removal
// keeps (removeDataRootKeepingRemovedConnectorBackups).
var removedConnectorNames = []string{"omnigent", "openhands"}

// removedConnectorBackupsKeptRoot is where DELETEUSERDATA=1 moves the removed
// connectors' backups: beside the data folder, the same name the CLI's
// `defenseclaw uninstall --all` uses (removed_connectors.kept_backups_root).
func removedConnectorBackupsKeptRoot(dataRoot string) string {
	return filepath.Clean(dataRoot) + "-removed-connector-backups"
}

// removeDataRootKeepingRemovedConnectorBackups removes dataRoot with remove,
// after it moved each removed connector's connector_backups/<connector>
// folder out of it: that folder holds the only copy of the files as they
// were before an older setup changed them, and the leftover list tells the
// user to copy back what they need from it. A link or reparse point there is
// not DefenseClaw's copy and goes with the data. When a folder cannot be
// moved, nothing is removed. The notes then name the moved folders and
// leave out what the removal took.
func removeDataRootKeepingRemovedConnectorBackups(dataRoot string, remove func() error) error {
	if err := moveRemovedConnectorBackupsOut(dataRoot); err != nil {
		return err
	}
	if err := remove(); err != nil {
		return err
	}
	removedConnectorNotes.Lock()
	removedConnectorNotes.dataRemoved = filepath.Clean(dataRoot)
	removedConnectorNotes.Unlock()
	return nil
}

// moveRemovedConnectorBackupsOut moves each removed connector's backups to
// removedConnectorBackupsKeptRoot, under a new name when an earlier removal
// left one there, and records where for the notes.
func moveRemovedConnectorBackupsOut(dataRoot string) error {
	root := removedConnectorBackupsKeptRoot(dataRoot)
	for _, name := range removedConnectorNames {
		path := filepath.Join(dataRoot, "connector_backups", name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		reparse, err := isReparsePoint(path)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if !info.IsDir() || reparse {
			continue
		}
		if err := rejectReparseAncestors(path); err != nil {
			return err
		}
		if info, err := os.Lstat(root); err == nil {
			if reparse, rerr := isReparsePoint(root); !info.IsDir() || reparse || rerr != nil {
				return fmt.Errorf("%s is in the way and is not a folder", root)
			}
		}
		if err := os.MkdirAll(root, 0o700); err != nil {
			return fmt.Errorf("keep %s: %w", path, err)
		}
		target := filepath.Join(root, name)
		for count := 2; ; count++ {
			if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
				break
			}
			target = filepath.Join(root, fmt.Sprintf("%s-%d", name, count))
		}
		if err := os.Rename(path, target); err != nil {
			return fmt.Errorf("keep %s (your files as they were before DefenseClaw's setup) by moving it to %s: %w", path, target, err)
		}
		removedConnectorNotes.Lock()
		if removedConnectorNotes.moved == nil {
			removedConnectorNotes.moved = map[string]string{}
		}
		removedConnectorNotes.moved[path] = target
		removedConnectorNotes.Unlock()
	}
	return nil
}

// removedConnectorNotePath is where a leftover is now: a moved backup is
// named at its new place; "" when the data removal took it.
func removedConnectorNotePath(path string) string {
	for old, now := range removedConnectorNotes.moved {
		if rel, ok := removedPathUnder(path, old); ok {
			return filepath.Join(now, rel)
		}
	}
	if root := removedConnectorNotes.dataRemoved; root != "" {
		if _, ok := removedPathUnder(path, root); ok {
			return ""
		}
	}
	return path
}

// removedPathUnder reports whether path is root or under it (case-blind, as
// Windows paths are), with the rest of the path.
func removedPathUnder(path, root string) (string, bool) {
	path, root = filepath.Clean(path), filepath.Clean(root)
	if strings.EqualFold(path, root) {
		return "", true
	}
	prefix := root + string(filepath.Separator)
	if len(path) > len(prefix) && strings.EqualFold(path[:len(prefix)], prefix) {
		return path[len(prefix):], true
	}
	return "", false
}

// removedDataGoneNote follows the notes when the data removal took some of
// the leftovers.
const removedDataGoneNote = "  DefenseClaw's data folder was removed, so a hook or policy listed above names a file that no longer exists, and the agent fails on it: remove it from the agent's config.\r\n"

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
	gone := false
	for _, name := range removedConnectorNotes.order {
		var leftovers []removedConnectorLeftover
		for _, item := range removedConnectorNotes.byConnector[name] {
			if item.Path = removedConnectorNotePath(item.Path); item.Path == "" {
				gone = true
				continue
			}
			leftovers = append(leftovers, item)
		}
		if len(leftovers) == 0 {
			continue
		}
		if b.Len() == 0 {
			b.WriteString(removedConnectorNotice + "\r\n")
		}
		for _, item := range leftovers {
			fmt.Fprintf(&b, "  - %s: %s. To remove: %s.\r\n", item.Path, item.What, item.Step)
		}
	}
	if gone && b.Len() > 0 {
		b.WriteString(removedDataGoneNote)
	}
	return b.String()
}
