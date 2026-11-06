// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
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
