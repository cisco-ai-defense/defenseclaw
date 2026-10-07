// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
)

// CleanupResult is what a retire or cleanup pass did.
type CleanupResult struct {
	// Removed are recorded names that were loaded and are now deleted.
	Removed []string `json:"removed,omitempty"`
	// Missing are recorded names Tetragon no longer has (it restarted, or an
	// operator deleted them).
	Missing []string `json:"missing,omitempty"`
	// Kept are recorded names that could not be deleted; they stay recorded
	// so the next pass retries.
	Kept []string `json:"kept,omitempty"`
	// Foreign are loaded names with the DefenseClaw shape that this helper
	// never recorded: a customer's own policy, or one from tetragon.tp.d.
	// They are reported and never touched.
	Foreign []string `json:"foreign,omitempty"`
}

// Cleanup is the retire step and the whole of `--tetragon-cleanup`. It
// deletes only names that are both in the helper's own record and shaped
// defenseclaw-(observe|connect|controls|controls-burnin)-<8 hex>, calling
// nothing but ListTracingPolicies and DeleteTracingPolicy. It runs with the
// binary that loaded the policies, before binaries or state go away.
//
// An error from Tetragon leaves the record as it was for the names it could
// not delete.
func Cleanup(ctx context.Context, client Client, dirs Dirs) (CleanupResult, error) {
	var result CleanupResult
	recorded, err := readLoaded(dirs)
	if err != nil {
		return result, err
	}
	known := map[string]bool{}
	for _, name := range recorded {
		known[name] = true
	}
	g := guard(client, ModeOff, func(name string) bool { return known[name] })
	listed, err := g.ListTracingPolicies(ctx)
	if err != nil {
		return result, fmt.Errorf("list tracing policies: %w", err)
	}
	present := map[string]bool{}
	for _, policy := range listed {
		present[policy.Name] = true
		if IsDefenseClawName(policy.Name) && !known[policy.Name] {
			result.Foreign = append(result.Foreign, policy.Name)
		}
	}
	sort.Strings(result.Foreign)
	var errs []error
	for _, name := range recorded {
		switch {
		case !present[name]:
			result.Missing = append(result.Missing, name)
		default:
			if err := g.DeleteTracingPolicy(ctx, name); err != nil {
				result.Kept = append(result.Kept, name)
				errs = append(errs, fmt.Errorf("delete %s: %w", name, err))
				continue
			}
			result.Removed = append(result.Removed, name)
		}
	}
	if err := writeLoaded(dirs, result.Kept); err != nil {
		errs = append(errs, err)
	}
	for _, name := range append(append([]string(nil), result.Removed...), result.Missing...) {
		removePolicyCopy(dirs, name)
	}
	forgetApplied(dirs, result)
	return result, errors.Join(errs...)
}

// Recorded returns the names this helper recorded as loaded.
func Recorded(dirs Dirs) ([]string, error) { return readLoaded(dirs) }

// forgetApplied drops retired names from the published state, so status does
// not list policies that are gone. Best effort: the state is advisory.
func forgetApplied(dirs Dirs, result CleanupResult) {
	var state FileState
	if err := readJSON(dirs.StateFile(), &state); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return
		}
		return
	}
	gone := map[string]bool{}
	for _, name := range result.Removed {
		gone[name] = true
	}
	for _, name := range result.Missing {
		gone[name] = true
	}
	for name := range gone {
		delete(state.Applied, name)
	}
	kept := state.Policies[:0]
	for _, policy := range state.Policies {
		if !gone[policy.Name] {
			kept = append(kept, policy)
		}
	}
	state.Policies = kept
	_ = writeJSON(dirs.StateFile(), state)
}
