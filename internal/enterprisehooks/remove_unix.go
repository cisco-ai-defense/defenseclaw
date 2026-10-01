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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// RemoveUserHooks removes DefenseClaw's own per-user hook registration for
// one Unix target (connector teardown, which edits only DefenseClaw-owned
// entries), the connector's hook credential file and the target's hook
// contract lock entry. The standalone uninstall, and the guardian for a
// target the manifest no longer enrolls, run it in the per-user worker with
// the user's credentials, never in a root process. A home that no longer
// exists is not an error.
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
			// The connector's hook credential goes with its registration.
			if tokenPath, err := connector.HookTokenFilePath(filepath.Join(dataDir, "hooks"), conn.Name()); err == nil {
				if err := os.Remove(tokenPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("enterprise hooks: remove %s hook credential: %w", conn.Name(), err)
				}
			}
			if err := connector.ClearHookContractLockEntry(dataDir, conn.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("enterprise hooks: clear hook contract lock for %s: %w", conn.Name(), err)
			}
			return nil
		})
	})
}

// UserInstallKeptError is PurgeUserState's answer for an account whose
// ~/.defenseclaw holds its own per-user DefenseClaw install: the purge left
// the folder alone (the enterprise hook registrations were already removed),
// because it removes only what the enterprise deployment created.
type UserInstallKeptError struct {
	// Found names the entries of the account's own install.
	Found []string
}

func (e *UserInstallKeptError) Error() string {
	return "kept ~/.defenseclaw, which holds the account's own DefenseClaw install (" + strings.Join(e.Found, ", ") + ")"
}

// PurgeUserState removes one account's DefenseClaw per-user state for the
// standalone Unix uninstall --purge, in the per-user worker with the
// account's credentials, after RemoveUserHooks ran for its manifest
// targets. A connector that still keeps DefenseClaw's backups (one set up by
// an earlier route, or disabled before the uninstall) is torn down first, so
// the files DefenseClaw changed get their content back before the backups
// go; if any teardown fails, the state stays for a rerun. Then the state
// goes except the account's own hooks the foreign-hook policy moved aside
// and the hook scripts, which become disabled stubs (see
// connector.PurgeUserState). A home that no longer exists is not an error.
// A ~/.defenseclaw that holds the account's own per-user install stays
// whole, with a *UserInstallKeptError: its backups and data are that
// install's, not the enterprise deployment's.
func PurgeUserState(ctx context.Context, opts InstallOptions) error {
	if err := refuseStandaloneRootInProcess("purge"); err != nil {
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
	if rel, err := filepath.Rel(home, dataDir); err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("enterprise hooks: refusing to purge %s, which is not inside the user home %s", dataDir, home)
	}
	// The purge deletes everything in the folder, so only DefenseClaw's own
	// folder, and never through a link, which would name the user's files.
	if filepath.Base(dataDir) != ".defenseclaw" {
		return fmt.Errorf("enterprise hooks: refusing to purge %s, which is not a .defenseclaw folder", dataDir)
	}
	if _, err := os.Lstat(dataDir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := validateUserDataDir(home, dataDir, uid); err != nil {
		return err
	}
	reg := opts.Registry
	if reg == nil {
		reg = connector.NewDefaultRegistry()
	}
	return connector.WithUserHomeDir(home, func() error {
		return withOwnerCredentials(uid, gid, func() error {
			if found := connector.PersonalInstallEntries(dataDir); len(found) > 0 {
				removeStaleHookTempEntries(uid, os.TempDir(), filepath.Join(home, ".hermes", "cache", "scratch"))
				return &UserInstallKeptError{Found: found}
			}
			names, err := connector.BackedUpConnectors(dataDir)
			if err != nil {
				return fmt.Errorf("enterprise hooks: list connector backups: %w", err)
			}
			var failed []error
			for _, name := range names {
				conn, ok := reg.Get(name)
				if !ok {
					continue
				}
				setupOpts := connector.SetupOpts{DataDir: dataDir, ManagedEnterprise: true}
				if err := conn.Teardown(ctx, setupOpts); err != nil {
					failed = append(failed, fmt.Errorf("connector %s teardown failed: %w", conn.Name(), err))
				}
			}
			if len(failed) > 0 {
				return fmt.Errorf("enterprise hooks: kept the per-user state for its backups: %w", errors.Join(failed...))
			}
			if err := connector.PurgeUserState(dataDir); err != nil {
				return fmt.Errorf("enterprise hooks: remove the per-user state: %w", err)
			}
			removeStaleHookTempEntries(uid, os.TempDir(), filepath.Join(home, ".hermes", "cache", "scratch"))
			return nil
		})
	})
}

// removeStaleHookTempEntries removes the account's leftover hook temporary
// entries (defenseclaw-hook.*, which a hook's exit trap misses when the
// agent kills it) in dirs: only the account's own, and only ones old enough
// that no hook still runs in them. Best effort.
func removeStaleHookTempEntries(uid int, dirs ...string) {
	cutoff := time.Now().Add(-10 * time.Minute)
	for _, dir := range dirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "defenseclaw-hook.*"))
		for _, path := range matches {
			info, err := os.Lstat(path)
			if err != nil || info.ModTime().After(cutoff) {
				continue
			}
			if owned, _ := fileOwnerMatches(path, uid); owned {
				_ = os.RemoveAll(path)
			}
		}
	}
}
