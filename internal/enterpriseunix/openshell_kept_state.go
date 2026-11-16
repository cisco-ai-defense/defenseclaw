// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Only settleOpenShell reads this name. Status, verify and a later purge of
// an uninstalled deployment must not treat it as the active state.
const openshellKeptStateFile = managed.StandaloneKeptOpenShellStateFile

func (e *Env) openshellKeptStatePath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), openshellKeptStateFile)
}

// keptOpenShellSetup returns a usable kept setup, not an empty or untrusted file.
func (e *Env) keptOpenShellSetup() *openshellState {
	state := e.loadKeptOpenShellState()
	if state != nil && (state.Applied != nil || len(state.Pending) > 0) {
		return state
	}
	return nil
}

// uninstallOpenShellState uses the active setup when it has content. A failed
// uninstall can leave its deployment record after moving that setup to the
// kept name; only then may a retry use the kept setup to find sandbox accounts.
// A purge after a completed uninstall has no deployment record and ignores it.
func (l *lifecycle) uninstallOpenShellState() *openshellState {
	state := l.env.loadOpenShellState()
	if state.Applied != nil || len(state.Pending) > 0 {
		return state
	}
	if exists(l.env.deploymentPath()) {
		if kept := l.env.keptOpenShellSetup(); kept != nil {
			return kept
		}
	}
	return state
}

// keepOpenShellState moves the applied setup without copying its contents or
// changing its mode. If a failed uninstall already moved it, a retry keeps a
// valid nonempty record; an invalid or empty kept file is removed.
func (e *Env) keepOpenShellState() (bool, error) {
	active, kept := e.openshellStatePath(), e.openshellKeptStatePath()
	info, err := os.Lstat(active)
	if os.IsNotExist(err) {
		if e.keptOpenShellSetup() != nil {
			return true, nil
		}
		return false, removeFile(kept)
	}
	if err != nil {
		return false, fmt.Errorf("could not keep the record of the sandbox setup the kept sandboxes were made under: %w; the next activation will not report a change of that setup", err)
	}
	uid, _, ownerErr := e.OwnerOf(active)
	if !info.Mode().IsRegular() || ownerErr != nil || uid != 0 || info.Mode().Perm() != 0o600 {
		return false, fmt.Errorf("could not keep the record of the sandbox setup the kept sandboxes were made under: %s is not a root-owned regular 0600 file, so the next activation will not report a change of that setup", active)
	}
	if err := os.Rename(active, kept); err != nil {
		return false, fmt.Errorf("could not keep the record of the sandbox setup the kept sandboxes were made under: %w; the next activation will not report a change of that setup", err)
	}
	// Rename preserves ownership on the host. This also records the new path
	// for the injectable owner reader used by the lifecycle tests.
	if err := e.Lchown(kept, 0, 0); err != nil {
		_ = removeFile(kept)
		return false, fmt.Errorf("could not keep the record of the sandbox setup the kept sandboxes were made under: %w; the next activation will not report a change of that setup", err)
	}
	return true, nil
}

func (e *Env) loadKeptOpenShellState() *openshellState {
	path := e.openshellKeptStatePath()
	data, err := readBounded(path, maxInputBytes)
	if err != nil {
		return nil
	}
	uid, _, err := e.OwnerOf(path)
	if err != nil || uid != 0 {
		return nil
	}
	var state openshellState
	if decodeStrict(data, &state) != nil || state.Version != 1 {
		return nil
	}
	if state.Pending == nil {
		state.Pending = map[string]pending{}
	}
	return &state
}

// openShellAppliedForPlan is the applied setup the plan compares with: the
// one settleOpenShell adopts (openShellStateForSettle). After a non-purge
// uninstall that kept sandboxes only the kept record holds it, and a plan that
// read the active state alone rendered no 1.0.1 upgrade bridge on the
// reinstall, so the kept default-namespace sandboxes of 1.0.1 were stranded
// (GAP-0666).
func (l *lifecycle) openShellAppliedForPlan() *openshellApplied {
	state := l.env.loadOpenShellState()
	if state.Applied != nil || len(state.Pending) != 0 {
		return state.Applied
	}
	if kept := l.env.keptOpenShellSetup(); kept != nil {
		return kept.Applied
	}
	return nil
}

// openShellStateForSettle adopts the kept record only when the active state
// has no applied or pending change. A populated active state makes it stale.
func (l *lifecycle) openShellStateForSettle() (*openshellState, bool) {
	env := l.env
	state := env.loadOpenShellState()
	if state.Applied != nil || len(state.Pending) != 0 {
		if err := removeFile(env.openshellKeptStatePath()); err != nil {
			l.result.AddWarning(codeState, "could not remove the stale kept sandbox setup record: "+err.Error())
		}
		return state, false
	}
	if _, err := os.Lstat(env.openshellKeptStatePath()); os.IsNotExist(err) {
		return state, false
	}
	if kept := env.loadKeptOpenShellState(); kept != nil {
		// The gateway binary the record saw is gone with the uninstall. A
		// reinstalled binary can reuse its inode, and the LaunchAgents of the
		// kept accounts would then not be reloaded onto it.
		kept.GatewayIdentity = ""
		return kept, true
	}
	// An unreadable or malformed record is ignored. A successful save of the
	// new active state below disposes of it; a failed save leaves it intact.
	return state, true
}

// settleOpenShell defers this from its first lines. The active file must
// contain exactly the state it tried to save; an early return or a failed
// atomic save leaves the kept record for another run.
func (l *lifecycle) discardKeptOpenShellStateAfterSave(state *openshellState, hadContent bool) {
	env := l.env
	if state.Applied == nil && len(state.Pending) == 0 {
		// An empty candidate with the subsystem off returns from settle
		// before saveOpenShellState. Keep it for an enabled retry.
		if !hadContent {
			return
		}
		if _, err := os.Lstat(env.openshellStatePath()); !os.IsNotExist(err) {
			return
		}
	} else {
		want, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return
		}
		got, err := readBounded(env.openshellStatePath(), maxInputBytes)
		if err != nil || !bytes.Equal(got, append(want, '\n')) {
			return
		}
	}
	if err := removeFile(env.openshellKeptStatePath()); err != nil {
		l.result.AddWarning(codeState, "could not remove the adopted sandbox setup record: "+err.Error())
	}
}
