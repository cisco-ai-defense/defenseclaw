//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// windowsClaudeFloorTransaction runs a version floor change under the Claude
// Code managed policy transaction lock the Windows lifecycle and its
// per-target installer hold: they own C:\Program Files\ClaudeCode, so the
// floor never races their 90-defenseclaw.json writes. Tests replace it.
var windowsClaudeFloorTransaction claudeFloorTransaction = enterprisehooks.WithWindowsClaudeManagedPolicyTransaction

// PublishWindowsClaudeVersionFloor keeps DefenseClaw's Claude Code version
// floor drop-in in line with the standalone config on Windows: written while
// claudecode is published through machine policy, version_floor is enforce
// and no administrator source sets requiredMinimumVersion; withdrawn
// otherwise. The guardian runs it every reconcile. It never reads or writes
// 90-defenseclaw.json or its ownership sidecar.
func PublishWindowsClaudeVersionFloor(opts Options, connectors []string) (State, error) {
	state := State{Connector: claudeConnector, Route: RouteMachinePolicy}
	if err := opts.Validate(); err != nil {
		return state, err
	}
	if opts.goos() != "windows" {
		return state, errors.New("PublishWindowsClaudeVersionFloor applies only to Windows")
	}
	err := reconcileClaudeVersionFloorFor(opts, normalizeConnectors(connectors), windowsClaudeFloorTransaction, &state)
	return state, err
}

// RemoveWindowsClaudeVersionFloor removes the floor drop-in DefenseClaw
// recorded writing (uninstall), restoring its preimage. A drop-in without a
// DefenseClaw record is the administrator's and stays.
func RemoveWindowsClaudeVersionFloor(opts Options) (State, error) {
	state := State{Connector: claudeConnector, Route: RouteMachinePolicy}
	if opts.goos() != "windows" {
		return state, errors.New("RemoveWindowsClaudeVersionFloor applies only to Windows")
	}
	err := removeClaudeVersionFloorWith(opts, windowsClaudeFloorTransaction, &state)
	return state, err
}

// PurgeWindowsUnrecordedClaudeVersionFloor is the uninstall-with-purge pass
// for a floor drop-in whose ownership record DefenseClaw lost (see
// purgeUnrecordedClaudeVersionFloor). It reports whether it removed one.
func PurgeWindowsUnrecordedClaudeVersionFloor(opts Options) (bool, error) {
	if opts.goos() != "windows" {
		return false, errors.New("PurgeWindowsUnrecordedClaudeVersionFloor applies only to Windows")
	}
	return purgeUnrecordedClaudeVersionFloor(opts, windowsClaudeFloorTransaction)
}
