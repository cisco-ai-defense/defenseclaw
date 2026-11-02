// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RemovePerUserConnectorHookFiles removes the connector's hook-directory
// scripts after its agent registration has been torn down. Setup and this
// cleanup both obtain their script names from HookScriptOwner through
// hookScriptNamesForConnector. Shared scripts are handled separately by
// RemoveUnusedSharedHookRuntime after the contract lock is cleared.
func RemovePerUserConnectorHookFiles(opts SetupOpts, removed Connector, peers []Connector) error {
	if opts.ManagedEnterprise || strings.TrimSpace(opts.DataDir) == "" || removed == nil ||
		len(ManagedPluginArtifacts(removed, opts)) != 0 {
		return nil
	}
	if _, ok := removed.(HookScriptOwner); !ok {
		return nil
	}
	data, hooks, err := openPinnedHookRuntime(opts.DataDir)
	if errors.Is(err, os.ErrNotExist) {
		return revokePerUserHookAPIToken(opts, removed.Name())
	}
	if err != nil {
		return fmt.Errorf("open hook runtime folder: %w", err)
	}
	defer data.Close()
	defer hooks.Close()
	return withFileLock(filepath.Join(opts.DataDir, "hooks", hookConfigSidecarName), func() error {
		return removePerUserConnectorHookFilesLocked(opts, removed, peers, data, hooks)
	})
}

func removePerUserConnectorHookFilesLocked(opts SetupOpts, removed Connector, peers []Connector, data, hooks *os.Root) error {
	bound, err := data.Lstat("hooks")
	if err != nil {
		return err
	}
	opened, err := hooks.Stat(".")
	if err != nil || !os.SameFile(bound, opened) {
		return fmt.Errorf("hook runtime folder changed before connector cleanup")
	}
	shared := make(map[string]bool, len(genericHookScripts))
	for _, name := range genericHookScripts {
		shared[name] = true
	}
	usedByPeer := map[string]bool{}
	for _, peer := range peers {
		if peerOwner, ok := peer.(HookScriptOwner); ok && len(ManagedPluginArtifacts(peer, opts)) == 0 {
			for _, name := range peerOwner.HookScriptNames(opts) {
				usedByPeer[name] = true
			}
		}
	}
	var errs []error
	for _, name := range hookScriptNamesForConnector(opts, removed) {
		if shared[name] || usedByPeer[name] {
			continue
		}
		// HookScriptNames is also passed to the setup writer. Refuse a path
		// outside its hook directory even if a future connector is mistaken.
		if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
			errs = append(errs, fmt.Errorf("invalid hook script name %q", name))
			continue
		}
		info, err := hooks.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("inspect hook script %s: %w", name, err))
			continue
		}
		if !info.Mode().IsRegular() {
			errs = append(errs, fmt.Errorf("refusing to remove non-regular hook script %s", name))
			continue
		}
		body, err := readPinnedRegularFile(hooks, name, hookRuntimeRenderMaxBytes)
		if err != nil {
			errs = append(errs, fmt.Errorf("read hook script %s: %w", name, err))
			continue
		}
		if !bytes.Contains(body[:min(len(body), 512)], []byte(hookSchemaVersionMarker)) {
			errs = append(errs, fmt.Errorf("refusing to remove hook script without DefenseClaw marker: %s", name))
			continue
		}
		// Teardown may have replaced the script with a disabled tombstone.
		// A running agent can still call that cached path.
		if bytes.Contains(body[:min(len(body), 512)], []byte("(disabled tombstone)")) &&
			agentProcessMayRun(opts.DataDir, hookAgentProcessName(removed.Name())) {
			continue
		}
		if err := removePinnedRegularFile(hooks, name, info); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove hook script %s: %w", name, err))
		}
	}
	if len(errs) == 0 {
		// The script writer also publishes this connector's scoped credential.
		// Teardown normally revokes it; repeat that idempotent step for a
		// registration already gone when setup remove reconciles it.
		errs = append(errs, revokePerUserHookAPIToken(opts, removed.Name()))
	}
	return errors.Join(errs...)
}
