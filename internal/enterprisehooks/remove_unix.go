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
	"slices"
	"strings"
	"syscall"
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
			return connector.RemovalLeavingNoNewDirs(conn, setupOpts, func() error {
				return removeUserHooksAs(ctx, conn, setupOpts, home, dataDir)
			})
		})
	})
}

// removeUserHooksAs is RemoveUserHooks' removal, run with the user's
// credentials and home.
func removeUserHooksAs(ctx context.Context, conn connector.Connector, setupOpts connector.SetupOpts, home, dataDir string) error {
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
	// The account's last connector takes the shared hook scripts with it,
	// checked while no install of another connector is under way.
	unlock, err := lockSharedHookRuntime(ctx, home)
	if err != nil {
		return err
	}
	defer unlock()
	if err := connector.RemoveUnusedSharedHookRuntime(dataDir); err != nil {
		return fmt.Errorf("enterprise hooks: remove the unused shared hook runtime: %w", err)
	}
	return nil
}

// PurgeSummary is what PurgeUserState found and removed, so the uninstall
// names only that for each account (GAP-1444).
type PurgeSummary struct {
	// Data reports that ~/.defenseclaw was there and is gone.
	Data bool
	// Kept reports that ~/.defenseclaw holds the account's own per-user
	// install from before the managed deployment enrolled it: the purge
	// leaves that folder and the install's binaries as they are, because a
	// machine uninstall never deletes or moves an account's own data
	// (GAP-0727, owner 2026-10-23).
	Kept bool
	// Binaries reports that per-user binaries or launcher links in
	// ~/.local/bin were removed.
	Binaries bool
	// UVCache reports that DefenseClaw's entries in ~/.cache/uv were
	// removed (GAP-1947).
	UVCache bool
}

// purgeUserFiles removes the per-user binaries and DefenseClaw's uv cache
// entries of the account, as the account, and records them in summary.
func purgeUserFiles(home, dataDir string, uid int, summary *PurgeSummary) error {
	removed, binErr := RemoveUserBinaries(home, dataDir, uid)
	summary.Binaries = len(removed) > 0
	cached, cacheErr := RemoveUserUVCacheEntries(home, uid)
	summary.UVCache = len(cached) > 0
	return errors.Join(binErr, cacheErr)
}

// PurgeUserState removes one account's DefenseClaw per-user state for the
// standalone Unix uninstall --purge, in the per-user worker with the
// account's credentials, after RemoveUserHooks ran for its manifest
// targets, and reports what it removed. A connector that still keeps
// DefenseClaw's backups (one set up by an earlier route, or disabled before
// the uninstall) is torn down first, so the files DefenseClaw changed get
// their content back before the backups go; if any teardown fails, the
// state stays for a rerun. When the folder holds the account's own per-user
// install from before the managed deployment enrolled it (its config,
// secrets, audit history, policies or upgrade backups), the folder and the
// install's binaries stay as they are and the summary says so (Kept): a
// machine uninstall never deletes or moves an account's own data. Only the
// Claude Code blocker the enrollment wrote over the install's hook script
// goes in both cases (RemovePersonalClaudeHookBlocker). Otherwise
// all of ~/.defenseclaw goes, including the hook scripts and the account's own
// hooks the foreign-hook policy moved aside (see connector.PurgeUserState),
// and so do the binaries and launcher links the per-user install put in
// ~/.local/bin (see RemoveUserBinaries) and DefenseClaw's entries in the
// account's uv cache (see RemoveUserUVCacheEntries). The caller stops the
// account's per-user gateway first. A home that no longer exists is not an
// error. The per-user worker runs it only after every Remove of the same job
// was checked clean (GAP-0632), and it keeps the state while a connector
// backup stays after the teardowns: that backup belongs to a file DefenseClaw
// left for the account (rel-1-0-3 GAP-0258).
func PurgeUserState(ctx context.Context, opts InstallOptions) (PurgeSummary, error) {
	var summary PurgeSummary
	if err := refuseStandaloneRootInProcess("purge"); err != nil {
		return summary, err
	}
	home, err := validateUserHome(opts.UserHome)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return summary, nil
		}
		return summary, err
	}
	uid, gid, err := resolveOwner(home, opts.OwnerUID, opts.OwnerGID)
	if err != nil {
		return summary, err
	}
	if err := validateHomeOwner(home, uid); err != nil {
		return summary, err
	}
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(home, ".defenseclaw")
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return summary, fmt.Errorf("enterprise hooks: resolve data dir: %w", err)
	}
	if rel, err := filepath.Rel(home, dataDir); err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return summary, fmt.Errorf("enterprise hooks: refusing to purge %s, which is not inside the user home %s", dataDir, home)
	}
	// The purge deletes everything in the folder, so only DefenseClaw's own
	// folder, and never through a link, which would name the user's files.
	if filepath.Base(dataDir) != ".defenseclaw" {
		return summary, fmt.Errorf("enterprise hooks: refusing to purge %s, which is not a .defenseclaw folder", dataDir)
	}
	if _, err := os.Lstat(dataDir); errors.Is(err, os.ErrNotExist) {
		// A rerun after the state went still removes the binaries.
		err := withOwnerCredentials(uid, gid, func() error {
			return purgeUserFiles(home, dataDir, uid, &summary)
		})
		return summary, err
	}
	if err := validateUserDataDir(home, dataDir, uid); err != nil {
		return summary, err
	}
	reg := opts.Registry
	if reg == nil {
		reg = connector.NewDefaultRegistry()
	}
	err = connector.WithUserHomeDir(home, func() error {
		return withOwnerCredentials(uid, gid, func() error {
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
			if err := keptManagedBackupsError(dataDir); err != nil {
				return err
			}
			if _, err := RemovePersonalClaudeHookBlocker(dataDir); err != nil {
				return fmt.Errorf("enterprise hooks: kept the per-user state, because the managed Claude Code blocker could not be removed: %w", err)
			}
			own, err := holdsPerUserInstall(dataDir)
			if err != nil {
				return fmt.Errorf("enterprise hooks: kept the per-user state, because it could not be read: %w", err)
			}
			if own {
				summary.Kept = true
				return nil
			}
			if err := connector.PurgeUserState(dataDir); err != nil {
				return fmt.Errorf("enterprise hooks: remove the per-user state: %w", err)
			}
			summary.Data = true
			removeStaleHookTempEntries(uid, os.TempDir(), filepath.Join(home, ".hermes", "cache", "scratch"))
			return purgeUserFiles(home, dataDir, uid, &summary)
		})
	})
	return summary, err
}

// PersonalClaudeHookBlocker is the script a managed enrollment writes over
// the account's own DefenseClaw Claude Code hook script
// (~/.defenseclaw/hooks/claude-code-hook.sh) while the machine policy covers
// Claude Code: the account's ~/.claude/settings.json can still run that
// script, and it must deny instead of allowing on a stopped personal
// gateway. It is right only while the computer is managed.
const PersonalClaudeHookBlocker = "#!/bin/sh\n# defenseclaw-managed-hook v0\necho 'defenseclaw: this computer is managed; the personal Claude Code hook cannot approve this call' >&2\nexit 2\n"

// RemovePersonalClaudeHookBlocker removes dataDir/hooks/claude-code-hook.sh
// when its bytes are exactly PersonalClaudeHookBlocker and reports whether it
// did. Every uninstall runs it as each account, purge or not (rel-1-0-4
// RB1-1): left in place, the blocker blocks every Claude Code tool call of a
// personal registration on a computer that is no longer managed. A missing
// script is a non-blocking hook error for Claude Code, as it was when the
// purge deleted ~/.defenseclaw; any other script stays as it is.
func RemovePersonalClaudeHookBlocker(dataDir string) (bool, error) {
	path := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() != int64(len(PersonalClaudeHookBlocker)) {
		return false, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	if string(body) != PersonalClaudeHookBlocker {
		return false, nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("remove %s: %w", path, err)
	}
	return true, nil
}

// perUserInstallMarkers are entries that only a per-user DefenseClaw
// install keeps in ~/.defenseclaw: its config, secrets, audit history and
// the copy of its data an upgrade keeps for a rollback. The managed
// enrollment never writes them there (its config and state live in the
// machine directories), so one of them means the folder holds the account's
// own install from before the managed deployment enrolled it.
var perUserInstallMarkers = []string{"config.yaml", ".env", "audit.db", "previous"}

// holdsPerUserInstall reports whether dataDir holds one of
// perUserInstallMarkers.
func holdsPerUserInstall(dataDir string) (bool, error) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	for _, entry := range entries {
		if slices.Contains(perUserInstallMarkers, entry.Name()) {
			return true, nil
		}
	}
	return false, nil
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
