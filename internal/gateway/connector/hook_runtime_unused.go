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
	dataRoot, hooks, err := openPinnedHookRuntime(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open hook runtime folder: %w", err)
	}
	defer dataRoot.Close()
	defer hooks.Close()
	// The runtime writer uses this lock for sidecars and shared scripts.
	// Keep it held while checking use and removing the unused runtime.
	err = withFileLock(filepath.Join(dataDir, "hooks", hookConfigSidecarName), func() error {
		return removeUnusedSharedHookRuntimeLocked(dataRoot, hooks)
	})
	RemoveIdleFileLockSentinels()
	if err == nil {
		bound, statErr := dataRoot.Lstat("hooks")
		opened, openErr := hooks.Stat(".")
		if statErr == nil && openErr == nil && os.SameFile(bound, opened) {
			_ = dataRoot.Remove("hooks") // only an empty folder goes
		}
	}
	return err
}

func removeUnusedSharedHookRuntimeLocked(dataRoot, hooks *os.Root) error {
	bound, err := dataRoot.Lstat("hooks")
	if err != nil {
		return err
	}
	opened, err := hooks.Stat(".")
	if err != nil || !os.SameFile(bound, opened) {
		return fmt.Errorf("hook runtime folder changed before removal")
	}
	if data, err := readPinnedRegularFile(dataRoot, hookContractLockFile, hookContractLockMaxBytes); err == nil {
		var lock hookContractLock
		if json.Unmarshal(data, &lock) != nil || len(lock.Connectors) > 0 {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read hook contract lock: %w", err)
	}
	dir, err := hooks.Open(".")
	if err != nil {
		return fmt.Errorf("read hook runtime folder: %w", err)
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return fmt.Errorf("read hook runtime folder: %w", err)
	}
	for _, entry := range entries {
		if entry.Name() != hookConfigSidecarName+".lock" && strings.HasPrefix(entry.Name(), hookConfigSidecarName+".") {
			return nil // a connector's runtime record: still in use
		}
	}
	if data, err := readPinnedRegularFile(hooks, hookConfigSidecarName, hookRuntimeRenderMaxBytes); err == nil {
		var state hookConfigSidecar
		if json.Unmarshal(data, &state) != nil || len(state.FailModes) > 0 {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read hook config sidecar: %w", err)
	}
	names := append(append(append([]string{hookConfigSidecarName, ".gateway-helper"}, genericHookScripts...), hookHelperScripts...), outageModeLookFiles...)
	var errs []error
	for _, name := range names {
		info, err := hooks.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil && !info.Mode().IsRegular() {
			err = fmt.Errorf("hook runtime file is not regular: %s", name)
		}
		if err == nil {
			err = removePinnedRegularFile(hooks, name, info)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if err := hooks.RemoveAll(".outage-warnings"); err != nil {
		errs = append(errs, err)
	}
	errs = append(errs, removeIdleConnectorLeftovers(dataRoot, hooks)...)
	if len(errs) == 0 {
		if err := dataRoot.Remove(hookContractLockFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
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
// managed config): recognized hook tombstones, the connector state files
// and empty backup folders. A tombstone stays while a process of the
// account may still run that agent: such a process can have the hook
// command cached, and Hermes 0.21 registers it fail closed, so a missing
// script would block every tool of the running session until the agent
// restarts. A failed-setup placeholder, any other script and a backup folder
// that holds a receipt stay.
func removeIdleConnectorLeftovers(dataDir, hookDir *os.Root) []error {
	var errs []error
	remove := func(root *os.Root, name string) {
		if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	dir, err := hookDir.Open(".")
	if err != nil {
		return []error{fmt.Errorf("read hook runtime folder: %w", err)}
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return []error{fmt.Errorf("read hook runtime folder: %w", err)}
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		body, err := readPinnedRegularFile(hookDir, entry.Name(), hookRuntimeRenderMaxBytes)
		if err != nil {
			continue
		}
		agent, ok := plainDisabledHookTombstoneAgent(string(body))
		if !ok && entry.Name() == "devin-hook.sh" && string(body) == devinDisabledHookTombstone() {
			agent, ok = "devin", true
		}
		if ok && !agentProcessMayRun(dataDir.Name(), hookAgentProcessName(agent)) {
			remove(hookDir, entry.Name())
		}
	}
	for _, name := range connectorStateLeftovers {
		if info, err := dataDir.Lstat(name); err == nil && info.Mode().IsRegular() {
			remove(dataDir, name)
		}
	}
	if info, err := dataDir.Lstat("connector_backups"); err == nil && info.IsDir() {
		backups, err := dataDir.OpenRoot("connector_backups")
		if err == nil {
			folder, openErr := backups.Open(".")
			if openErr == nil {
				entries, readErr := folder.ReadDir(-1)
				_ = folder.Close()
				if readErr == nil {
					for _, entry := range entries {
						if entry.IsDir() {
							_ = backups.Remove(entry.Name()) // only an empty folder goes
						}
					}
				}
			}
			_ = backups.Close()
		}
		_ = dataDir.Remove("connector_backups")
	}
	return errs
}

func hookAgentProcessName(name string) string {
	if strings.EqualFold(name, "claudecode") || strings.EqualFold(name, "Claude Code") {
		return "claude"
	}
	return name
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

// outageModeLookFiles are the files defenseclaw-hook-user keeps in the hooks
// folder to share one outage-mode look among the late calls of an account
// (cmd/defenseclaw-hook-user/outage_shared.go): DefenseClaw files, removed
// with the hook runtime and owned by the account state.
var outageModeLookFiles = []string{".outage-mode.lock", ".outage-mode.result", ".outage-mode.result.tmp"}
