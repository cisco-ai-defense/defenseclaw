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
	// Backup reports that ~/.defenseclaw held the account's own per-user
	// install, whose data was moved to a ~/.defenseclaw-backup-<UTC time>
	// folder in the home before the purge (#1299).
	Backup bool
	// Binaries reports that per-user binaries or launcher links in
	// ~/.local/bin were removed.
	Binaries bool
	// UVCache reports that DefenseClaw's entries in ~/.cache/uv were
	// removed (GAP-1947).
	UVCache bool
	// KeptRemovedConnectorBackups names the folders the purge moved the
	// OpenHands/OmniGent backups to instead of deleting them (GAP-2015).
	KeptRemovedConnectorBackups []string
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
// install from before the managed deployment enrolled it, that install's
// data (its config, secrets, audit history, policies and upgrade backups)
// is moved to a ~/.defenseclaw-backup-<UTC time> folder first (see
// backupPerUserInstall); if that fails, the state stays. Then all of
// ~/.defenseclaw goes, including the hook scripts and the account's own
// hooks the foreign-hook policy moved aside (see connector.PurgeUserState),
// and so do the binaries and launcher links the per-user install put in
// ~/.local/bin (see RemoveUserBinaries) and DefenseClaw's entries in the
// account's uv cache (see RemoveUserUVCacheEntries). The caller stops the
// account's per-user gateway first. A home that no longer exists is not an
// error. The per-user worker runs it only after every Remove of the same job
// was checked clean (GAP-0632), and it keeps the state while a connector
// backup stays after the teardowns: that backup belongs to a file DefenseClaw
// left for the account (rel-1-0-3 GAP-0258). That check runs before the
// backup of the account's own install, which would move connector_backups.
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
			backedUp, err := backupPerUserInstall(home, dataDir, time.Now())
			if err != nil {
				return fmt.Errorf("enterprise hooks: kept the per-user state, because its data from before the managed install could not be backed up: %w", err)
			}
			summary.Backup = backedUp
			kept, err := moveRemovedConnectorBackupsOut(dataDir)
			summary.KeptRemovedConnectorBackups = kept
			if err != nil {
				return fmt.Errorf("enterprise hooks: kept the per-user state: %w", err)
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

// perUserInstallMarkers are entries that only a per-user DefenseClaw
// install keeps in ~/.defenseclaw: its config, secrets, audit history and
// the copy of its data an upgrade keeps for a rollback. The managed
// enrollment never writes them there (its config and state live in the
// machine directories), so one of them means the folder holds the account's
// own install from before the managed deployment enrolled it.
var perUserInstallMarkers = []string{"config.yaml", ".env", "audit.db", "previous"}

// purgeWithoutBackup are the entries of ~/.defenseclaw a backup leaves
// behind for the purge to delete: what the managed enrollment wrote (the
// hook scripts and per-user hook credentials, the connector backups the
// teardowns above restored from, the hook contract lock, the session-facts
// cache and the list of folders DefenseClaw created for the agents, which
// connector.PurgeUserState reads) and the per-user install's runtime, which
// a reinstall recreates (its Python environment and uv caches, staging and
// lock, and the pid file of the gateway stopped before the purge).
var purgeWithoutBackup = map[string]bool{
	"hooks":                        true,
	"connector_backups":            true,
	"hook_contract_lock.json":      true,
	"hook_contract_lock.json.lock": true,
	"session-facts.json":           true,
	"watcher-created-dirs.json":    true,
	".venv":                        true,
	".uv":                          true,
	".staging":                     true,
	".install.lock":                true,
	"gateway.pid":                  true,
}

// perUserBackupPrefix starts the name of the folder in the home that keeps
// a per-user install's data across a purge.
const perUserBackupPrefix = ".defenseclaw-backup-"

// perUserBackupNote is the file in the backup folder that says what it is.
// It is written only when no moved entry has its name.
const perUserBackupNote = "DEFENSECLAW-BACKUP.txt"

// backupPerUserInstall moves the data of the account's own per-user install
// out of dataDir into a new ~/.defenseclaw-backup-<UTC time> folder in
// home, before the purge deletes dataDir (#1299: a managed purge deleted
// data that predated the enrollment, with no way back). It runs as the
// account. Nothing is moved when dataDir holds no per-user install (see
// perUserInstallMarkers); entries in purgeWithoutBackup stay for the purge.
// A rename is all it does: the backup is on the same filesystem and costs
// no space. backedUp reports that a backup folder was made. On an error the
// purge stops and keeps the state: what was moved already is in the backup,
// and the rest is still in dataDir, so nothing is lost.
func backupPerUserInstall(home, dataDir string, now time.Time) (backedUp bool, err error) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	install := false
	for _, entry := range entries {
		if slices.Contains(perUserInstallMarkers, entry.Name()) {
			install = true
			break
		}
	}
	if !install {
		return false, nil
	}
	stamp := now.UTC().Format("20060102T150405Z")
	var backup string
	for attempt := 0; ; attempt++ {
		name := perUserBackupPrefix + stamp
		if attempt > 0 {
			name += fmt.Sprintf("-%d", attempt+1)
		}
		backup = filepath.Join(home, name)
		err = os.Mkdir(backup, 0o700)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) || attempt >= 9 {
			return false, fmt.Errorf("create %s: %w", backup, err)
		}
	}
	for _, entry := range entries {
		if purgeWithoutBackup[entry.Name()] {
			continue
		}
		if err := os.Rename(filepath.Join(dataDir, entry.Name()), filepath.Join(backup, entry.Name())); err != nil {
			return true, fmt.Errorf("move %s to %s: %w", entry.Name(), backup, err)
		}
	}
	note := fmt.Sprintf(`DefenseClaw kept this copy of your own DefenseClaw data (~/.defenseclaw)
when the managed DefenseClaw deployment was removed with --purge on %s.
It holds what your personal DefenseClaw install had there before the
managed deployment enrolled this account: its config, secrets (.env),
audit history, policies and upgrade backups. The hook scripts, hook
credentials and Python environment were not kept: a reinstall recreates
them.

To use this data again, install DefenseClaw for your account and move
these files back into ~/.defenseclaw. If you do not need it, delete this
folder.
`, now.UTC().Format(time.RFC3339))
	// The note is a courtesy: the data is already safe in the folder, and a
	// moved file of the same name is never replaced.
	if file, err := os.OpenFile(filepath.Join(backup, perUserBackupNote), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		_, _ = file.WriteString(note)
		_ = file.Close()
	}
	return true, nil
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
