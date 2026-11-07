// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The protected elements of a target hook install, as the guardian counts a
// restore: it reports an element that did not match what DefenseClaw renders
// before a repair and matches it after (GAP-0754). A write to a file the agent
// also writes for its own settings is not a restore, so the evidence is the
// element and never the file.
const (
	// HookElementEntry is the DefenseClaw hook entry in the agent config.
	HookElementEntry = "hook entry"
	// HookElementRuntime is the hook runtime files DefenseClaw renders in the
	// data folder of the account: the hook script, the shared scripts and
	// records, or the managed plugin.
	HookElementRuntime = "hook runtime files"
)

// HookElements says which protected elements of a target match what
// DefenseClaw renders for it. The registration check also reads the hook
// runtime files, so a registration is judged only once they match: while
// Runtime is false, Entry is not judged and reads true.
type HookElements struct {
	Entry   bool
	Runtime bool
}

// Broken names the elements that do not match, in a fixed order.
func (e HookElements) Broken() []string {
	var broken []string
	if !e.Entry {
		broken = append(broken, HookElementEntry)
	}
	if !e.Runtime {
		broken = append(broken, HookElementRuntime)
	}
	return broken
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
			elements.Runtime = lockErr == nil && lock.Connector == conn.Name() &&
				verifyStandaloneHookRuntime(conn, setupOpts, opts.GuardrailMode, lock, target.uid) == nil
			if !elements.Runtime {
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
