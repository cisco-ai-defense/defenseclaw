// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RemoveUnusedSharedHookRuntime removes the hook scripts every connector
// shares (inspect-*.sh, _hardening.sh), the shared runtime record and the
// hook contract lock from dataDir once no connector uses them: the lock
// names no connector, and the hooks folder holds no connector's runtime
// record. A managed account whose last connector was removed kept them
// (r102 GAP-0430), and so did the connectors' own leftovers
// (removeIdleConnectorLeftovers). Anything else in dataDir stays, and so
// does a hooks folder that is not empty after it.
func RemoveUnusedSharedHookRuntime(dataDir string) error {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil
	}
	lockPath := filepath.Join(dataDir, hookContractLockFile)
	if data, err := readConnectorStateFile(lockPath); err == nil {
		var lock hookContractLock
		if json.Unmarshal(data, &lock) != nil || len(lock.Connectors) > 0 {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read hook contract lock: %w", err)
	}
	hookDir := filepath.Join(dataDir, "hooks")
	entries, err := os.ReadDir(hookDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read hook runtime folder: %w", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), hookConfigSidecarName+".") {
			return nil // a connector's runtime record: still in use
		}
	}
	if data, err := readConnectorStateFile(filepath.Join(hookDir, hookConfigSidecarName)); err == nil {
		var state hookConfigSidecar
		if json.Unmarshal(data, &state) != nil || len(state.FailModes) > 0 {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read hook config sidecar: %w", err)
	}
	names := append(append([]string{hookConfigSidecarName, ".gateway-helper"}, genericHookScripts...), hookHelperScripts...)
	var errs []error
	for _, name := range names {
		if err := os.Remove(filepath.Join(hookDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := os.RemoveAll(filepath.Join(hookDir, ".outage-warnings")); err != nil {
		errs = append(errs, err)
	}
	errs = append(errs, removeIdleConnectorLeftovers(dataDir, hookDir)...)
	if len(errs) == 0 {
		if err := os.Remove(lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	_ = os.Remove(hookDir) // only an empty folder goes
	return errors.Join(errs...)
}

// connectorStateLeftovers are the files a connector's setup leaves in the
// data directory that mean nothing once no connector is registered: its
// empty lifecycle lock and the record of where Setup last registered it.
var connectorStateLeftovers = []string{".hermes-lifecycle.lock", hermesHomeSetUpFileName}

// agentProcessMayRun reports whether a process of the data directory's
// account may still run agent (tests replace it).
var agentProcessMayRun = accountAgentProcessMayRun

// removeIdleConnectorLeftovers removes, from an account no connector uses
// any more, what a connector's setup and teardown leave behind (r102
// GAP-0430: hermes-hook.sh, .hermes-lifecycle.lock, hermes-home-setup.json
// and an empty connector_backups/hermes stayed after Hermes left the
// managed config): the plain exit-0 hook tombstones, the connector state
// files and empty backup folders. A tombstone stays while a process of the
// account may still run that agent: such a process can have the hook
// command cached, and Hermes 0.21 registers it fail closed, so a missing
// script would block every tool of the running session until the agent
// restarts. A tombstone that blocks on purpose (Devin's, the failed-setup
// placeholder), any other script and a backup folder that holds a receipt
// stay.
func removeIdleConnectorLeftovers(dataDir, hookDir string) []error {
	var errs []error
	remove := func(path string) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	entries, err := os.ReadDir(hookDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return []error{fmt.Errorf("read hook runtime folder: %w", err)}
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		path := filepath.Join(hookDir, entry.Name())
		body, err := readConnectorStateFile(path)
		if err != nil {
			continue
		}
		if agent, ok := plainDisabledHookTombstoneAgent(string(body)); ok && !agentProcessMayRun(dataDir, agent) {
			remove(path)
		}
	}
	for _, name := range connectorStateLeftovers {
		path := filepath.Join(dataDir, name)
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			remove(path)
		}
	}
	backups := filepath.Join(dataDir, "connector_backups")
	if folders, err := os.ReadDir(backups); err == nil {
		for _, folder := range folders {
			if folder.IsDir() {
				_ = os.Remove(filepath.Join(backups, folder.Name())) // only an empty folder goes
			}
		}
		_ = os.Remove(backups)
	}
	return errs
}

// plainDisabledHookTombstoneAgent returns the agent of a hook script that is
// exactly the exit-0 tombstone writeDisabledHookTombstone writes.
func plainDisabledHookTombstoneAgent(body string) (string, bool) {
	lines := strings.SplitN(body, "\n", 4)
	if len(lines) < 3 {
		return "", false
	}
	agent, ok := strings.CutPrefix(lines[2], "# ")
	if !ok {
		return "", false
	}
	agent, ok = strings.CutSuffix(agent, " connector was torn down. Existing host processes may")
	if !ok || agent == "" || body != disabledHookTombstone(agent) {
		return "", false
	}
	return agent, true
}
