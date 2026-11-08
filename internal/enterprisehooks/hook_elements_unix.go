// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// HookElements says which protected elements of a target match what
// DefenseClaw renders for it. The hook entry is judged on the agent config
// alone, so an entry damaged together with a runtime file is told apart from
// that file (GAP-0754); only for a connector whose registration is proved
// together with its runtime does a broken runtime leave the entry unjudged,
// reading true.
type HookElements struct {
	Entry bool
	// BrokenRuntime names the runtime file elements that do not match, in a
	// fixed order; HookElementRuntime stands for a fault of the runtime as a
	// whole.
	BrokenRuntime []string
	// Files says which files an element is read from: the agent configs for
	// the hook entry and the runtime file itself for a runtime file element.
	// The runtime as a whole has none.
	Files map[string][]string
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
				// Without a usable lock the runtime as a whole is broken, but
				// every runtime file is still read against what DefenseClaw
				// renders for it, so a file put back is told apart from the
				// lock that stays missing.
				lock = connector.HookContractLockEntry{}
				elements.BrokenRuntime = []string{HookElementRuntime}
			}
			for _, fault := range standaloneHookRuntimeFaults(conn, setupOpts, opts.GuardrailMode, lock, target.uid, true) {
				if !slices.Contains(elements.BrokenRuntime, fault.element) {
					elements.BrokenRuntime = append(elements.BrokenRuntime, fault.element)
				}
			}
			elements.Files = map[string][]string{HookElementEntry: connector.HookConfigPathsForConnector(conn, setupOpts)}
			for _, element := range elements.BrokenRuntime {
				if base, ok := strings.CutPrefix(element, hookElementFilePrefix); ok {
					elements.Files[element] = hookRuntimeFilePaths(conn, setupOpts, target.dataDir, base)
				}
			}
			if len(elements.BrokenRuntime) > 0 {
				// The registration check runs the hook, so it cannot tell a
				// broken entry from a broken script: read the entry from the
				// config alone where the connector allows it.
				judged, present, entryErr := connector.OwnedHookEntriesPresent(conn, setupOpts)
				elements.Entry = !judged || (entryErr == nil && present)
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

// hookRuntimeFilePaths returns where the runtime file named base is read from:
// the hooks folder of the data directory and the managed plugin files of the
// connector with that name.
func hookRuntimeFilePaths(conn connector.Connector, opts connector.SetupOpts, dataDir, base string) []string {
	paths := []string{filepath.Join(filepath.Clean(dataDir), "hooks", base)}
	for _, path := range connector.ManagedPluginArtifacts(conn, opts) {
		if filepath.Base(path) == base && !slices.Contains(paths, path) {
			paths = append(paths, path)
		}
	}
	return paths
}
