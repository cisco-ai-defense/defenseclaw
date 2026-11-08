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
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// windowsGoOwnedFolderUse is how the vendor of a Go-owned Windows target
// uses the folder that holds its policy file: Copilot loads every *.json
// file in it and OpenCode two config names, so another account that can add
// a file there changes the policy; Devin reads only hooks.json, in both of its folders.
func windowsGoOwnedFolderUse(name string) policyFolderUse {
	switch name {
	case ConnectorCopilot:
		return copilotFolderUse
	case ConnectorOpenCode:
		return opencodeFolderUse
	}
	return policyFolderUse{}
}

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

// PublishWindowsSecureClientCopilot is the Windows Secure Client guardian's
// GitHub Copilot machine policy. With enabled it reconciles DefenseClaw's
// policy.d drop-in, which the Copilot CLI and the GitHub Copilot app (it runs
// the same CLI) load for every user; otherwise it removes the drop-in this
// deployment recorded, and leaves a host it never published to untouched. A
// Secure Client config has no enterprise.machine_policy, so the drop-in
// carries the default policy, and the profile writes no VS Code device
// policy, Copilot managed setting or public summary.
func PublishWindowsSecureClientCopilot(opts Options, enabled bool) (State, error) {
	if opts.goos() != "windows" {
		return State{}, errors.New("PublishWindowsSecureClientCopilot applies only to Windows")
	}
	if !opts.CopilotCLIPolicyOnly {
		return State{}, errors.New("the Secure Client Copilot policy is CLI-only")
	}
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	target := copilotTarget{}
	if enabled {
		return reconcileTarget(target, opts)
	}
	return RemoveWindowsSecureClientCopilot(opts)
}

// RemoveWindowsSecureClientCopilot removes the GitHub Copilot drop-in a
// Secure Client deployment recorded (teardown, or Copilot turned off). A host
// without that record is left as found.
func RemoveWindowsSecureClientCopilot(opts Options) (State, error) {
	if opts.goos() != "windows" {
		return State{}, errors.New("RemoveWindowsSecureClientCopilot applies only to Windows")
	}
	record, err := loadRecord(opts, copilotConnector)
	if err != nil || record == nil {
		return State{Connector: copilotConnector, Route: RouteMachinePolicy}, err
	}
	target := copilotTarget{}
	unprotected, err := takeBackWindowsGoOwnedForRemoval(opts, target)
	if err != nil {
		return State{}, fmt.Errorf("%s: %w", copilotConnector, err)
	}
	return removeTargetOwned(target, opts.removingFrom(unprotected))
}

// takeBackWindowsGoOwnedForRemoval takes back a target's vendor folders that
// a standard user created first, as a reconcile does, before the removal
// reads them. A user-created C:\ProgramData\GitHub\Copilot\policy.d made the
// administrator's and the MDM's uninstall fail 1603 on its owner although
// Copilot was never configured, while the install had gone through
// (GAP-0898); install and uninstall now treat the folder the same way. A
// file a standard user left in Copilot's policy.d is moved aside too.
//
// On a standalone install a vendor folder DefenseClaw did not create that
// holds a file DefenseClaw recorded (case c) is never taken over, and the
// removal does not fail closed on one that does not protect that file
// either: protecting nothing is all a refusal would buy once DefenseClaw no
// longer claims the connector. Such folders are returned, and the removal
// then strips DefenseClaw's entry only from a recorded file it can still
// trust (restoreOrStripUnprotected). Every target walks each folder it
// removes a recorded file from, so Devin (both folders), OpenCode and Copilot
// behave the same (g582 review 7 S1).
func takeBackWindowsGoOwnedForRemoval(opts Options, target Target) ([]unprotectedVendorFolder, error) {
	paths, err := target.Paths(opts)
	if err != nil || len(paths) == 0 {
		return nil, nil
	}
	walk := paths[:1]
	use := windowsGoOwnedFolderUse(target.Name())
	use.removal = true
	switch target.Name() {
	case ConnectorDevinCascade:
		// The pre-rename Devin file is removed as well when DefenseClaw
		// recorded writing it. Kept for the supported 1.0.5-1.0.8 to 1.0.9
		// upgrade only, until the Cascade withdrawal goes in 1.1 (the reason
		// is at weakVendorFolders, g877b review S6).
		if len(paths) > 1 {
			if record, err := loadRecord(opts, devinCascadeLegacyRecord); err == nil && record != nil {
				walk = paths[:2]
			}
		}
	}
	var state State
	var unprotected []unprotectedVendorFolder
	for index, path := range walk {
		// A link kept at this path is not read, taken back or created
		// behind (GAP-0758); Devin's other folder is still walked.
		if opts.linkKept(path) {
			continue
		}
		_, found, err := takeBackPolicyPathFor(opts, path, use, &state)
		if err != nil {
			return unprotected, err
		}
		unprotected = append(unprotected, found...)
		if index == 0 && len(found) == 0 && target.Name() == ConnectorCopilot {
			displaceUntrustedPolicyFiles(opts, platformPath(opts, dirFor(opts, path)), DefenseClawDropInName, &state)
		}
	}
	return unprotected, nil
}

// keepLinkedGoOwnedForRemoval looks at every policy path of target. It clears
// a link a standard user planted (the link only; what it points at is
// untouched), and returns the paths on which a link an administrator owns, or
// one it could not remove, stays, with the reason in the state's details:
// the removal then reads nothing through those paths, and they are named
// (WindowsGoOwnedLinkedFolders). Each path is decided on its own, so a link
// at one of Devin's two folders keeps that folder alone. cleared reports that
// a planted link was removed.
func keepLinkedGoOwnedForRemoval(opts Options, target Target) (kept map[string]bool, cleared bool, state State) {
	state = State{Connector: target.Name(), Route: RouteMachinePolicy}
	paths, err := target.Paths(opts)
	if err != nil {
		return nil, false, state
	}
	for _, path := range paths {
		before := len(state.Details)
		link, why := clearOrKeepLinkedPolicyPath(opts, platformPath(opts, path), &state)
		if link == "" {
			cleared = cleared || len(state.Details) > before
			continue
		}
		state.detail("kept %s: %s", link, why)
		managed.EmitResilienceEvent(managed.MarkerBoundary, map[string]string{
			"path":   link,
			"reason": why,
		})
		if kept == nil {
			kept = map[string]bool{}
		}
		kept[keptLinkKey(opts, path)] = true
	}
	return kept, cleared, state
}

func keptLinkKey(opts Options, path string) string {
	return strings.ToLower(platformPath(opts, path))
}

// linkKept reports whether RemoveWindowsGoOwned kept a link on path.
func (o Options) linkKept(path string) bool {
	return o.keptLinks[keptLinkKey(o, path)]
}

// WindowsGoOwnedLinkedFolders lists, sorted, the paths on the Go-owned
// policy paths (Copilot, OpenCode, Devin) that are links now. It is
// read-only. A teardown that kept one names it in machine_state_remaining
// (path: kept: reason).
func WindowsGoOwnedLinkedFolders(opts Options) []string {
	seen := map[string]bool{}
	var out []string
	for _, name := range windowsGoOwnedNames {
		target, ok := TargetFor(name)
		if !ok {
			continue
		}
		paths, err := target.Paths(opts)
		if err != nil {
			continue
		}
		for _, path := range paths {
			if link := linkedPolicyComponent(opts, platformPath(opts, path)); link != "" && !seen[link] {
				seen[link] = true
				out = append(out, link)
			}
		}
	}
	sort.Strings(out)
	return out
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
		// A link on the target path is cleared or kept before anything is
		// taken back, created or read (GAP-0758): the removal never fails on
		// it and never creates a folder in its place.
		// Each path is decided on its own: a link at one path keeps that path
		// only, and the target's entry at its other paths is still removed.
		kept, cleared, linkState := keepLinkedGoOwnedForRemoval(opts, target)
		if len(linkState.Details) > 0 {
			result.States = append(result.States, linkState)
			result.Changed = result.Changed || linkState.Changed || cleared
		}
		if paths, err := target.Paths(opts); err == nil && len(kept) != 0 && len(kept) == len(paths) {
			continue
		}
		targetOpts := opts
		targetOpts.keptLinks = kept
		unprotected, err := takeBackWindowsGoOwnedForRemoval(targetOpts, target)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		state, err := removeTargetOwned(target, targetOpts.removingFrom(unprotected))
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
