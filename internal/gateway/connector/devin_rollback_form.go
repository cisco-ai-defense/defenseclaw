// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Releases before 1.0.9 own the per-user Windows Devin command only in the
// direct form (windowsDevinBashHookCommand) and match their entries by exact
// command. After a rollback to one of them, its setup added its own entry
// beside this release's guarded start (windowsDevinGuardedHookCommand), and
// its teardown left the guarded start behind, which then ran a guard with no
// launcher beside it and blocked every Devin prompt and tool call
// (rel-1-0-6 GAP-0676, the GAP-1284 rule). The rollback converter rewrites
// this release's guarded starts into the direct form first, and the restore
// of an aborted rollback puts them back.

// devinWindowsHookFormPairs are, per Devin event, this release's guarded
// start of each launcher paired with the direct start releases before 1.0.9
// wrote. withGuardOnly keeps only launchers whose guard program is there
// (windowsSiblingLauncherGuard): a restore never writes a guarded start
// without its guard.
func devinWindowsHookFormPairs(launchers []string, withGuardOnly bool) map[string][][2]string {
	pairs := map[string][][2]string{}
	for _, launcher := range uniqueNonEmptyStrings(launchers) {
		direct := windowsDevinBashHookCommand(launcher)
		guard := windowsSiblingGuardPath(launcher)
		if withGuardOnly {
			guard = windowsSiblingLauncherGuard(launcher)
		}
		if direct == "" || guard == "" {
			continue
		}
		for _, event := range devinHookEvents {
			if !hookguard.DevinBlockEvent(event) {
				continue
			}
			if guarded := windowsDevinGuardedHookCommand(guard, event); guarded != "" {
				pairs[event] = append(pairs[event], [2]string{guarded, direct})
			}
		}
	}
	return pairs
}

// convertDevinHookForms rewrites, in the hooks object of a Devin hooks file,
// each handler whose command is exactly one form of pairs for the event it
// is registered under into its other form: this release's into the earlier
// one (toEarlier), or back. Other events, foreign and edited handlers keep
// their commands. It returns how many handlers it rewrote.
func convertDevinHookForms(hooks map[string]interface{}, pairs map[string][][2]string, toEarlier bool) int {
	changed := 0
	for event, eventPairs := range pairs {
		groups, _ := hooks[event].([]interface{})
		for _, rawGroup := range groups {
			group, _ := rawGroup.(map[string]interface{})
			handlers, _ := group["hooks"].([]interface{})
			for _, rawHandler := range handlers {
				handler, ok := rawHandler.(map[string]interface{})
				if !ok {
					continue
				}
				command, _ := handler["command"].(string)
				command = strings.TrimSpace(command)
				for _, pair := range eventPairs {
					from, to := pair[0], pair[1]
					if !toEarlier {
						from, to = to, from
					}
					if command == from {
						handler["command"] = to
						changed++
						break
					}
				}
			}
		}
	}
	return changed
}

// convertDevinHooksFile applies convertDevinHookForms to one Devin hooks
// file under its lock, keeps a copy of it before a rollback conversion, and
// returns how many handlers it rewrote. A file that holds exactly the bytes
// DefenseClaw last committed keeps its exact restore
// (holdManagedExactRestoreOverRead): the converted bytes are recorded as the
// committed output, so a rollback that finds the file unedited puts the saved
// pre-setup bytes back. An edit that lands while the conversion runs keeps
// the file out of the exact restore.
func convertDevinHooksFile(path, dataDir, connectorName string, pairs map[string][][2]string, toEarlier bool, keepCopy func(dataDir, name string, data []byte) error) (int, error) {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return 0, nil
	}
	converted := 0
	err := withFileLockMode(path, false, func() error {
		var err error
		// A save that lands while the conversion runs makes the writer refuse
		// to replace the file (errManagedTargetMoved); the conversion starts
		// again from the saved bytes, which no longer match the record. The
		// copy is kept once, from the first read.
		for attempt := 0; attempt < devinConversionAttempts; attempt++ {
			converted, err = convertDevinHooksOnce(path, dataDir, connectorName, pairs, toEarlier, keepCopy)
			if !errors.Is(err, errManagedTargetMoved) {
				return err
			}
			keepCopy = nil
		}
		return err
	})
	return converted, err
}

// devinConversionAttempts bounds how often a conversion starts again after the
// file was saved under it.
const devinConversionAttempts = 3

func convertDevinHooksOnce(path, dataDir, connectorName string, pairs map[string][][2]string, toEarlier bool, keepCopy func(dataDir, name string, data []byte) error) (int, error) {
	data, err := safefile.ReadRegularFileBounded(path, devinConfigReadLimit)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	cfg, err := readDevinJSONObject(path)
	if err != nil {
		return 0, err
	}
	converted := convertDevinHookForms(devinHooksObject(path, cfg), pairs, toEarlier)
	if converted == 0 {
		return 0, nil
	}
	if keepCopy != nil {
		sum := sha256.Sum256([]byte(strings.ToLower(path)))
		if err := keepCopy(dataDir, "devin-"+hex.EncodeToString(sum[:6])+".before-rollback.json", data); err != nil {
			return converted, fmt.Errorf("keep a copy of the Devin hooks: %w", err)
		}
	}
	// The writer reads the file again to keep the comments of the operator,
	// so the bytes read above do not bind what it consumed: the hold follows
	// its writes instead.
	hold := holdManagedExactRestoreOverRead(dataDir, connectorName, path, data)
	after, err := writeDevinHooksFileBytes(path, cfg)
	if err != nil {
		_ = hold(nil)
		return converted, err
	}
	return converted, hold(after)
}
