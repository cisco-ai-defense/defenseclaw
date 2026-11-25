// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
)

// The watch loop cancels a running pass for a change to an owned file, so a
// changed file in another account is inspected promptly, but never for a
// write the pass made itself. The standalone Unix guardian runs each
// account's targets in a worker and marks the account's rows active for as
// long as the worker runs. The in-process reconcile (the standalone Windows
// guardian) marks the account it works on the same way, and also records
// what that work left in the account's owned files: Windows can deliver the
// event of the pass's own write after the work moved on to the next target.
//
// Without the marks a first enrollment (a returned Hermes row) cancelled the
// pass that made it: the install writes the account's contract lock, a file
// the account's other rows own. The standalone guardian publishes nothing
// from a cancelled pass, and the next pass made the same first enrollment
// again, so state, activation and ledger stayed frozen until a restart
// (GAP-2176, GAP-1798). A change made by anyone else still counts: during the
// account's work it is replayed right after the pass, and after the work it
// cancels the pass as before.

func (w *enterpriseHookWatchActiveWorkers) start(keys []string) {
	w.mu.Lock()
	if w.active == nil {
		w.active = make(map[string]int)
	}
	for _, key := range keys {
		w.active[key]++
	}
	w.mu.Unlock()
}

func (w *enterpriseHookWatchActiveWorkers) finish(keys, repairedKeys []string) {
	w.mu.Lock()
	if len(repairedKeys) > 0 && w.repaired == nil {
		w.repaired = make(map[string]bool)
	}
	for _, key := range repairedKeys {
		w.repaired[key] = true
	}
	for _, key := range keys {
		if w.active[key] <= 1 {
			delete(w.active, key)
		} else {
			w.active[key]--
		}
	}
	w.mu.Unlock()
}

// enterpriseHookWatchAccountID folds an account's home the way the platform
// compares paths.
func enterpriseHookWatchAccountID(home string) string {
	home = strings.TrimSpace(home)
	if home == "" {
		return ""
	}
	home = filepath.Clean(home)
	if runtime.GOOS == "windows" {
		home = strings.ToLower(home)
	}
	return home
}

// enterpriseHookWatchAccountWork marks the account of home as worked on by
// the running pass until the returned function is called. Outside a watch
// pass it does nothing.
func enterpriseHookWatchAccountWork(ctx context.Context, home string) func() {
	active, _ := ctx.Value(enterpriseHookWatchActiveWorkersKey{}).(*enterpriseHookWatchActiveWorkers)
	if active == nil {
		return func() {}
	}
	return active.accountWork(home)
}

// accountWork marks every row the last pass had for home's account active.
// The returned function records the fingerprint each of those rows' owned
// files has when the work ends, then clears the mark.
func (w *enterpriseHookWatchActiveWorkers) accountWork(home string) func() {
	id := enterpriseHookWatchAccountID(home)
	keys := w.accounts[id]
	if id == "" || len(keys) == 0 {
		return func() {}
	}
	w.start(keys)
	return func() {
		mine := make(map[string]struct{}, len(keys))
		for _, key := range keys {
			mine[key] = struct{}{}
		}
		left := map[string]string{}
		for path, owners := range w.owners {
			for _, owner := range owners {
				if _, ok := mine[owner]; ok {
					left[path] = enterpriseHookOwnedFileFingerprint(path)
					break
				}
			}
		}
		w.mu.Lock()
		if w.workLeft == nil {
			w.workLeft = make(map[string]string, len(left))
		}
		for path, fingerprint := range left {
			w.workLeft[path] = fingerprint
		}
		w.mu.Unlock()
		w.finish(keys, nil)
	}
}

// workTail reports an event on path that is the tail of this pass's own
// account work: the file still holds what that work left there.
func (w *enterpriseHookWatchActiveWorkers) workTail(path string) bool {
	path = filepath.Clean(path)
	w.mu.RLock()
	left, ok := w.workLeft[path]
	w.mu.RUnlock()
	return ok && enterpriseHookOwnedFileFingerprint(path) == left
}
