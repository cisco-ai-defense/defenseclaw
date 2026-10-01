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
	"os"
	"sort"
	"strings"
)

// Result is the aggregate lifecycle outcome.
type Result struct {
	States []State `json:"states"`
	// MachinePolicyConnectors lists the machine-policy connectors whose
	// DefenseClaw entries are actually in place after this pass; the
	// lifecycle records exactly this set in the runtime descriptor.
	MachinePolicyConnectors []string `json:"machine_policy_connectors"`
	// Retired reports the connectors whose earlier DefenseClaw entries this
	// pass removed because they are no longer published through machine
	// policy (disabled, ownership: off, or moved off the route).
	Retired []State `json:"retired,omitempty"`
	Changed bool    `json:"changed"`
}

// Complete reports whether every machine-policy connector is covered.
func (r Result) Complete() bool {
	for _, state := range r.States {
		if state.Route == RouteMachinePolicy && !state.Covered {
			return false
		}
	}
	return true
}

func normalizeConnectors(connectors []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, name := range connectors {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Publish reconciles machine policy for every enabled connector that has a
// machine policy route and writes the public foreign-hook guard summary.
// Connectors on other routes are reported with their route so status shows
// every connector.
func Publish(opts Options, connectors []string) (Result, error) {
	if err := opts.Validate(); err != nil {
		return Result{}, err
	}
	connectors = normalizeConnectors(connectors)
	result := Result{}
	var errs []error
	for _, name := range connectors {
		state, err := reconcileOne(opts, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
		result.Changed = result.Changed || state.Changed
		result.States = append(result.States, state)
	}
	result.MachinePolicyConnectors = reconciledConnectors(result.States)
	retired, err := retireUnpublished(opts, MachinePolicyConnectors(opts, connectors), targetNames())
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

func targetNames() []string {
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// retireUnpublished removes DefenseClaw's entries from every candidate
// target that still holds an ownership record but is no longer intended,
// so disabling a connector or setting ownership: off takes DefenseClaw's
// hooks and lock out of the vendor policy at once instead of leaving them
// until uninstall. verify_only connectors stay intended (DefenseClaw still
// verifies them), so their record and entries are kept.
func retireUnpublished(opts Options, intended, candidates []string) ([]State, error) {
	if opts.StateDir == "" {
		return nil, nil
	}
	keep := map[string]bool{}
	for _, name := range intended {
		keep[name] = true
	}
	var retired []State
	var errs []error
	for _, name := range candidates {
		if keep[name] {
			continue
		}
		target, ok := TargetFor(name)
		if !ok {
			continue
		}
		recorded, err := hasOwnershipRecord(opts, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		if !recorded {
			continue
		}
		state, err := target.RemoveOwned(opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("retire %s machine policy: %w", name, err))
		}
		state.detail("%s is no longer published through machine policy; removed DefenseClaw's entries", name)
		retired = append(retired, state)
	}
	return retired, errors.Join(errs...)
}

// hasOwnershipRecord reports whether DefenseClaw recorded writing
// connector's machine policy.
func hasOwnershipRecord(opts Options, connector string) (bool, error) {
	for _, name := range ownershipRecordNames(opts, connector) {
		path, err := recordPath(opts, name)
		if err != nil {
			return false, err
		}
		if _, err := os.Lstat(path); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

func reconcileOne(opts Options, name string) (State, error) {
	route := opts.Route(name)
	policy := opts.PolicyFor(name)
	if route != RouteMachinePolicy {
		state := State{Connector: name, Route: route, ForeignHooks: policy.ForeignHooks}
		if route == RoutePerUser {
			state.detail("per-user registration of the admin hook binary, repaired by the guardian")
		}
		if name == "kiro" {
			kiroRouteDetail(route, &state)
		}
		if name == ConnectorOpenCode && opts.OpenCodePluginPath != "" {
			openCodePerUserFallback(opts, policy, &state)
		}
		return state, nil
	}
	target, _ := TargetFor(name)
	return target.Reconcile(opts)
}

// kiroRouteDetail says where Kiro's hook lives on its route and that the
// ACP guard stays available.
func kiroRouteDetail(route string, state *State) {
	switch route {
	case RoutePerUser:
		state.detail("kiro: the guardian writes each enrolled user's ~/.kiro/hooks/defenseclaw.json (Kiro IDE, kiro-cli --v3) and the CLI 2.x defenseclaw agent; `defenseclaw-gateway enterprise acp` stays available for editors that start Kiro over ACP")
	}
}

// VerifyAll inspects every connector without writing.
func VerifyAll(opts Options, connectors []string) (Result, error) {
	if err := opts.Validate(); err != nil {
		return Result{}, err
	}
	connectors = normalizeConnectors(connectors)
	result := Result{}
	var errs []error
	for _, name := range connectors {
		route := opts.Route(name)
		if route != RouteMachinePolicy {
			state := State{Connector: name, Route: route, ForeignHooks: opts.PolicyFor(name).ForeignHooks}
			if name == "kiro" {
				kiroRouteDetail(route, &state)
			}
			if name == ConnectorOpenCode && opts.OpenCodePluginPath != "" {
				// Say why OpenCode is not on its machine policy route.
				openCodePerUserFallback(opts, opts.PolicyFor(name), &state)
			}
			if name == connectorAmp && opts.goos() == "windows" {
				state.Conflicts = append(state.Conflicts, InspectWindowsAmpMachineFolder(opts)...)
			}
			result.States = append(result.States, state)
			continue
		}
		target, _ := TargetFor(name)
		state, err := target.Verify(opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		} else if state.Route == RouteMachinePolicy {
			verifyPublishedFiles(opts, name, &state)
		}
		result.States = append(result.States, state)
	}
	// A connector whose entries drifted from what a publish writes (a file
	// mode, a floor drop-in to withdraw) is not in place: the lifecycle
	// compares this set with the one it recorded and re-applies.
	var inPlace []State
	for _, state := range result.States {
		if !state.Drift {
			inPlace = append(inPlace, state)
		}
	}
	result.MachinePolicyConnectors = reconciledConnectors(inPlace)
	return result, errors.Join(errs...)
}

// RemoveAll removes DefenseClaw's machine policy for every connector with a
// machine policy target (whether or not it is still enabled) and deletes
// the public summary.
func RemoveAll(opts Options) (Result, error) {
	names := targetNames()
	result := Result{}
	var errs []error
	for _, name := range names {
		state, err := targets[name].RemoveOwned(opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
		result.Changed = result.Changed || state.Changed
		result.States = append(result.States, state)
	}
	if opts.PublicPolicyPath != "" {
		if err := removePolicyFile(opts, opts.PublicPolicyPath); err != nil {
			errs = append(errs, err)
		}
	}
	return result, errors.Join(errs...)
}
