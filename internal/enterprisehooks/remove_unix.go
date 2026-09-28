// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// RemoveUserHooks removes DefenseClaw's own per-user hook registration for
// one Unix target (connector teardown, which edits only DefenseClaw-owned
// entries) and clears the target's hook contract lock entry. The standalone
// uninstall runs it in the per-user worker with the user's credentials,
// never in a root process. A home that no longer exists is not an error.
func RemoveUserHooks(ctx context.Context, opts InstallOptions) error {
	if err := refuseStandaloneRootInProcess("remove"); err != nil {
		return err
	}
	home, err := validateUserHome(opts.UserHome)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	uid, gid, err := resolveOwner(home, opts.OwnerUID, opts.OwnerGID)
	if err != nil {
		return err
	}
	if err := validateHomeOwner(home, uid); err != nil {
		return err
	}
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(home, ".defenseclaw")
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve data dir: %w", err)
	}
	reg := opts.Registry
	if reg == nil {
		reg = connector.NewDefaultRegistry()
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	conn, ok := reg.Get(name)
	if !ok {
		return fmt.Errorf("enterprise hooks: unknown connector %q", name)
	}
	setupOpts := connector.SetupOpts{
		DataDir:           dataDir,
		Interactive:       false,
		ManagedEnterprise: true,
		WorkspaceDir:      strings.TrimSpace(opts.WorkspaceDir),
		AgentVersion:      strings.TrimSpace(opts.AgentVersion),
		HookContractID:    strings.TrimSpace(opts.HookContractID),
	}
	return connector.WithUserHomeDir(home, func() error {
		return withOwnerCredentials(uid, gid, func() error {
			if err := conn.Teardown(ctx, setupOpts); err != nil {
				return fmt.Errorf("enterprise hooks: connector %s teardown failed: %w", conn.Name(), err)
			}
			if err := connector.ClearHookContractLockEntry(dataDir, conn.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("enterprise hooks: clear hook contract lock for %s: %w", conn.Name(), err)
			}
			return nil
		})
	})
}
