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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// SharedHookSidecarRefusal returns why `defenseclaw setup` must not save a
// connector of a per-user data directory whose shared hook config
// (hooks/.hookcfg) is malformed, or nil. Every DefenseClaw hook of the data
// directory closes on such a file, and a writer refuses to carry it into a
// rewrite (carryableHookConfigSidecar), so a setup that saved its change
// reported success while the file stayed as it was and the hooks kept
// closing (GAP-1325). It reads the file with the writer's own contract and
// changes nothing. A managed sidecar is guardian-owned and replaced by the
// next reconcile, so it is not asked.
func SharedHookSidecarRefusal(opts SetupOpts) error {
	if opts.ManagedEnterprise || opts.DataDir == "" {
		return nil
	}
	path := filepath.Join(opts.DataDir, "hooks", hookConfigSidecarName)
	reason := sharedHookSidecarMalformed(path)
	if reason == nil {
		return nil
	}
	if errors.Is(reason, ErrSharedHookSidecarRestartRepairs) {
		return refuseForAgentConfig(fmt.Errorf(
			"the shared hook config %s has a null fail_modes map (%w), so every DefenseClaw hook of this data directory closes on it; "+
				"a gateway restart rebuilds the map from the flat hook records: run the same setup command without --no-restart, "+
				"or run defenseclaw-gateway restart first",
			path, reason,
		))
	}
	return refuseForAgentConfig(fmt.Errorf(
		"the shared hook config %s is malformed (%v), so every DefenseClaw hook of this data directory closes on it; "+
			"move the file aside and restart the gateway (defenseclaw-gateway restart), which writes it again from config.yaml",
		path, reason,
	))
}

// ErrSharedHookSidecarRestartRepairs marks a malformed shared hook config
// the gateway's own writer repairs when setup restarts it: a v2 sidecar
// whose fail_modes is null and whose flat records rebuild the map
// (writeHookConfigSidecarLocked, GAP-0512). Setup with a restart goes ahead;
// only a setup that will not restart is refused (GAP-1815).
var ErrSharedHookSidecarRestartRepairs = errors.New("a gateway restart rebuilds it from the flat hook records")

// sharedHookSidecarMalformed returns why the sidecar at path is state a
// writer refuses to rewrite, or nil when it is absent or carryable.
func sharedHookSidecarMalformed(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errHookConfigSidecarNotRegular
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, HookSidecarMaxBytes+1))
	if err != nil {
		return err
	}
	if len(data) > HookSidecarMaxBytes {
		return errors.New("parse hook config sidecar: larger than 64 KiB")
	}
	prior, err := carryableHookConfigSidecar(data)
	if errors.Is(err, errHookSidecarNullFailModes) {
		if _, recoverErr := recoverFlatHookFailModes(filepath.Dir(path), prior.FailModeSources); recoverErr != nil {
			return fmt.Errorf("%w, and its flat records cannot rebuild it: %v", err, recoverErr)
		}
		return fmt.Errorf("%w; %w", err, ErrSharedHookSidecarRestartRepairs)
	}
	return err
}
