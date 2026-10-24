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
// (r102 GAP-0430). Anything else in dataDir stays, and so does a hooks
// folder that is not empty after it.
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
	names := append(append([]string{hookConfigSidecarName}, genericHookScripts...), hookHelperScripts...)
	var errs []error
	for _, name := range names {
		if err := os.Remove(filepath.Join(hookDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		if err := os.Remove(lockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	_ = os.Remove(hookDir) // only an empty folder goes
	return errors.Join(errs...)
}
