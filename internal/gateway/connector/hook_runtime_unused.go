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

// connectorLifecycleLocks are the empty lock files a connector's setup and
// teardown take in the data directory.
var connectorLifecycleLocks = map[string]string{"hermes": ".hermes-lifecycle.lock"}

// agentProcessMayRun reports whether a process of the data directory's
// account may still run agent (tests replace it).
var agentProcessMayRun = accountAgentProcessMayRun

// removeIdleConnectorLeftovers removes, from an account no connector uses
// any more, the disabled hook tombstones and lifecycle locks a connector's
// teardown leaves (r102 GAP-0430: hermes-hook.sh and .hermes-lifecycle.lock
// stayed after Hermes left the managed config). A tombstone stays while a
// process of the account may still run that agent: such a process can have
// the hook command cached, and Hermes 0.21 registers it fail closed, so a
// missing script would block every tool of the running session until the
// agent restarts. Only the plain exit-0 tombstone goes; one that blocks on
// purpose (Devin's, the failed-setup placeholder) stays.
func removeIdleConnectorLeftovers(dataDir, hookDir string) []error {
	var errs []error
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
		agent, ok := plainDisabledHookTombstoneAgent(string(body))
		if !ok || agentProcessMayRun(dataDir, agent) {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	for agent, name := range connectorLifecycleLocks {
		path := filepath.Join(dataDir, name)
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Size() != 0 ||
			agentProcessMayRun(dataDir, agent) {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
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
