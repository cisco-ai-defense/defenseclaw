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
	"fmt"
)

// connectorAmp has no machine policy target; on Windows the guardian holds
// its machine folder (reserveWindowsAmpMachineDir).
const connectorAmp = "amp"

// windowsGoOwnedTargets are the machine policy targets the Go guardian owns
// on the Windows standalone profile. The Windows lifecycle already owns the
// Codex requirements, the Claude Code managed settings and the Cursor
// enterprise hooks, with their own ownership records and transactions; a
// second writer would race them, so the guardian never reconciles those.
var windowsGoOwnedTargets = map[string]bool{
	ConnectorCopilot:      true,
	ConnectorOpenCode:     true,
	ConnectorDevinCascade: true,
}

// windowsGoOwnedNames are windowsGoOwnedTargets in retire and remove order.
var windowsGoOwnedNames = []string{ConnectorCopilot, ConnectorDevinCascade, ConnectorOpenCode}

// IsWindowsGoOwned reports whether the Go guardian owns connector's Windows
// machine policy.
func IsWindowsGoOwned(connector string) bool {
	return windowsGoOwnedTargets[connector]
}

// PublishWindowsGoOwned installs the managed OpenCode plugin the payload
// ships, reconciles only the Go-owned Windows machine policy targets among
// connectors and writes the public summary for every connector, so the
// hook-side foreign-hook guard sees the whole policy.
func PublishWindowsGoOwned(opts Options, connectors []string) (Result, error) {
	if err := opts.Validate(); err != nil {
		return Result{}, err
	}
	if opts.goos() != "windows" {
		return Result{}, errors.New("PublishWindowsGoOwned applies only to Windows")
	}
	connectors = normalizeConnectors(connectors)
	result := Result{}
	var errs []error
	if opts.OpenCodePluginPath != "" {
		// The Windows Setup payload is the signed or hash-pinned binaries;
		// the plugin they carry is written here, before OpenCode's managed
		// config names it. A failure leaves OpenCode on the per-user route.
		changed, err := InstallOpenCodeManagedPlugin(opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ConnectorOpenCode, err))
		}
		result.Changed = result.Changed || changed
	}
	// Amp's machine folder is held whatever the Amp policy says: every
	// account's Amp reads it.
	if amp, err := reserveWindowsAmpMachineDir(opts); err != nil {
		errs = append(errs, fmt.Errorf("%s machine folder: %w", connectorAmp, err))
	} else {
		result.Changed = result.Changed || amp.Changed
	}
	for _, name := range withCompanions(connectors) {
		if !windowsGoOwnedTargets[name] {
			continue
		}
		state, err := reconcileOne(opts, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
		result.Changed = result.Changed || state.Changed
		result.States = append(result.States, state)
	}
	result.MachinePolicyConnectors = reconciledConnectors(result.States)
	intended := []string{}
	for _, name := range MachinePolicyConnectors(opts, withCompanions(connectors)) {
		if windowsGoOwnedTargets[name] {
			intended = append(intended, name)
		}
	}
	retired, err := retireUnpublished(opts, intended, windowsGoOwnedNames)
	if err != nil {
		errs = append(errs, err)
	}
	result.Retired = retired
	for _, state := range retired {
		result.Changed = result.Changed || state.Changed
	}
	if opts.PublicPolicyPath != "" {
		changed, err := WritePublicPolicy(opts, connectors)
		if err != nil {
			errs = append(errs, fmt.Errorf("public machine policy summary: %w", err))
		}
		result.Changed = result.Changed || changed
	}
	return result, errors.Join(errs...)
}

// RemoveWindowsGoOwned removes the DefenseClaw entries of the Go-owned
// Windows targets, the public summary and the managed OpenCode plugin.
// Administrator files are left byte-identical.
func RemoveWindowsGoOwned(opts Options) (Result, error) {
	if opts.goos() != "windows" {
		return Result{}, errors.New("RemoveWindowsGoOwned applies only to Windows")
	}
	result := Result{}
	var errs []error
	openCodeUnpublished := false
	for _, name := range windowsGoOwnedNames {
		target, ok := TargetFor(name)
		if !ok {
			continue
		}
		state, err := target.RemoveOwned(opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		} else if name == ConnectorOpenCode {
			openCodeUnpublished = true
		}
		result.Changed = result.Changed || state.Changed
		result.States = append(result.States, state)
	}
	if opts.PublicPolicyPath != "" {
		if err := removePolicyFile(opts, opts.PublicPolicyPath); err != nil {
			errs = append(errs, err)
		}
	}
	// Only once OpenCode's managed config no longer names the plugin, so
	// the config never points every user's OpenCode at a missing file.
	if openCodeUnpublished {
		if err := RemoveOpenCodeManagedPlugin(opts); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ConnectorOpenCode, err))
		}
	}
	return result, errors.Join(errs...)
}
