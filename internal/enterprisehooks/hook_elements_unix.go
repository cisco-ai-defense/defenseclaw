// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// HookElements says which protected elements of a target match what
// DefenseClaw renders for it. The registration check also reads the hook
// runtime files, so a registration is judged only once every one of them
// matches: while a runtime element is broken, Entry is not judged and reads
// true.
type HookElements struct {
	Entry bool
	// BrokenRuntime names the runtime file elements that do not match, in a
	// fixed order; HookElementRuntime stands for a fault of the runtime as a
	// whole.
	BrokenRuntime []string
}

// Broken names the elements that do not match, in a fixed order.
func (e HookElements) Broken() []string {
	var broken []string
	if !e.Entry {
		broken = append(broken, HookElementEntry)
	}
	return append(broken, e.BrokenRuntime...)
}

// Matches says whether the element name is one the guardian knows and it
// matches. An unknown name never matches.
func (e HookElements) Matches(name string) bool {
	switch {
	case !KnownHookElement(name):
		return false
	case name == HookElementEntry:
		return e.Entry
	}
	return !slices.Contains(e.BrokenRuntime, name)
}

// ProbeHookElements checks each protected element of one target on its own,
// as Verify does for the standalone per-user worker, without changing
// anything. An element that cannot be checked does not match. An error means
// the target could not be resolved, so nothing is known about either element.
// It runs in the worker of the account only.
func ProbeHookElements(ctx context.Context, opts InstallOptions) (HookElements, error) {
	target, err := newVerifyTarget(opts, "probe")
	if err != nil {
		return HookElements{}, err
	}
	if !standalonePerUserRepair(target.uid) {
		return HookElements{}, errors.New("enterprise hooks: hook elements are probed for the standalone per-user worker only")
	}
	conn, setupOpts := target.conn, target.setupOpts
	var elements HookElements
	err = connector.WithUserHomeDir(target.home, func() error {
		platformPrepareAgentPolicy(ctx, conn.Name(), target.home, target.dataDir, target.uid, target.gid, &setupOpts)
		return withOwnerCredentials(target.uid, target.gid, func() error {
			lock, lockErr := connector.LoadHookContractLockEntryForMode(target.dataDir, conn.Name(), false)
			if lockErr != nil || lock.Connector != conn.Name() {
				elements.BrokenRuntime = []string{HookElementRuntime}
			} else {
				for _, fault := range standaloneHookRuntimeFaults(conn, setupOpts, opts.GuardrailMode, lock, target.uid, true) {
					if !slices.Contains(elements.BrokenRuntime, fault.element) {
						elements.BrokenRuntime = append(elements.BrokenRuntime, fault.element)
					}
				}
			}
			if len(elements.BrokenRuntime) > 0 {
				elements.Entry = true
				return nil
			}
			present, presentErr := connector.OwnedHooksPresentContext(ctx, conn, setupOpts)
			elements.Entry = presentErr == nil && present
			return nil
		})
	})
	if err != nil {
		return HookElements{}, fmt.Errorf("enterprise hooks: probe the hook elements: %w", err)
	}
	return elements, nil
}
