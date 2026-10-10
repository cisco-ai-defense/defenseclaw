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

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The gateway, the hook guardian and the lifecycle keep their state in the
// deployment folders the lifecycle owns: the data folder (the audit store,
// the device identity key, the hook tokens, the service .env), the hook
// guardian folders and the files next to config.yaml. A support script that
// ran chown -R root:wheel or chmod -R a+rX over the deployment changed every
// one of them, and repair, ensure and a package reinstall restored only the
// folders: the gateway could not open its audit store or refused its key
// files (redaction_unavailable:unsafe_key_permissions), every retry rolled
// back after the readiness timeout, and only a purge (losing the audit
// history and the device identity) recovered (GAP-0746, GAP-0747). Each
// transaction now gives every entry there the owner and mode it is written
// with, and status and verify name the entries that differ.

// maxStateDepth bounds how deep the state folders are walked.
const maxStateDepth = 8

// stateMode is the owner and mode one state entry is written with. With
// mask, mode is the most the entry may have: bits beyond it are removed and
// none are added (an entry whose exact mode the lifecycle does not know).
type stateMode struct {
	mode  os.FileMode
	owner fileOwner
	mask  bool
}

// wanted returns the mode the entry gets in place of current.
func (m stateMode) wanted(current os.FileMode) os.FileMode {
	if m.mask {
		return current.Perm() & m.mode
	}
	return m.mode
}

// drift compares an entry with want and returns the mode it gets. For a
// root-owned entry the folder lets the service account read, the group
// matters only when the mode grants it access; an entry the running process
// owns counts as root-owned (tests run unprivileged). verify reports, for
// root-owned entries, only an owner other than root and bits beyond the
// managed mode, which a guardian rewriting its files never leaves behind.
func (e *Env) drift(info os.FileInfo, uid, gid int, want stateMode, strict bool) (os.FileMode, bool) {
	mode := want.wanted(info.Mode())
	if want.owner.UID != 0 {
		return mode, info.Mode().Perm() != mode || uid != want.owner.UID || gid != want.owner.GID
	}
	if uid != 0 && uid != os.Geteuid() {
		return mode, true
	}
	if !strict {
		return mode, info.Mode().Perm()&^mode != 0
	}
	return mode, info.Mode().Perm() != mode || (mode&0o070 != 0 && gid != want.owner.GID)
}

// stateTree is a folder whose entries the lifecycle owns, with the owner and
// mode of each entry by its path below the folder.
type stateTree struct {
	dir  string
	rule func(rel string, dir bool) stateMode
}

// stateTrees are the state folders for the service account. Entries the
// guardian writes as root stay root-owned, so the service account cannot
// change them.
func (e *Env) stateTrees(account Account) []stateTree {
	service := fileOwner{UID: account.UID, GID: account.GID}
	rootService := fileOwner{UID: 0, GID: account.GID}
	manifest := filepath.Base(e.Layout.ManifestPath)
	return []stateTree{
		{dir: e.Layout.DataDir, rule: func(rel string, dir bool) stateMode {
			switch {
			case dir:
				return stateMode{mode: 0o700, owner: service}
			case rel == guardianStateFile:
				return stateMode{mode: 0o640, owner: rootService} // the gateway reads it
			case rel == guardianRepairsFile:
				return stateMode{mode: 0o600, owner: rootService}
			}
			// The gateway refuses a key file or hook token another account
			// can read.
			return stateMode{mode: 0o600, owner: service}
		}},
		{dir: filepath.Dir(e.Layout.ManifestPath), rule: func(rel string, dir bool) stateMode {
			switch {
			case dir:
				return stateMode{mode: 0o750, owner: rootService, mask: true}
			case rel == manifest:
				return stateMode{mode: 0o640, owner: rootService}
			case rel == enterprisehooks.UnixEligibleAccountsFileName, rel == enterprisehooks.UnprotectedAgentsFileName,
				rel == enterprisehooks.UnixCopilotVSCodeAccountsFileName:
				// The guardian refuses either one when another account can read it.
				return stateMode{mode: 0o600, owner: rootOwner()}
			}
			return stateMode{mode: 0o640, owner: rootService, mask: true}
		}},
		{dir: e.Layout.GuardianAuthDir, rule: func(rel string, dir bool) stateMode {
			switch {
			case dir:
				return stateMode{mode: 0o750, owner: rootService}
			case rel == managed.HookGuardianCredentialAttestationFile, rel == managed.HookGuardianCredentialTransactionFile,
				rel == managed.HookGuardianReconcileLockFile, rel == enterprisehooks.UnixCopilotVSCodeAccountsFileName,
				rel == "unix_target_bindings.json":
				return stateMode{mode: 0o600, owner: rootService} // root-only guardian records
			}
			return stateMode{mode: 0o640, owner: rootService, mask: true}
		}},
	}
}

// stateFile is one state file next to config.yaml.
type stateFile struct {
	path string
	stateMode
}

// configStateFiles are the files the lifecycle keeps next to config.yaml:
// the generation record the gateway reads, and the config_version 8 backup
// (which can hold a credential the v8 config had inline) and migration record
// of a migrated config.
func (e *Env) configStateFiles(account Account) []stateFile {
	rootService := fileOwner{UID: 0, GID: account.GID}
	return []stateFile{
		{path: configwrite.GenerationPath(e.Layout.ConfigPath), stateMode: stateMode{mode: 0o640, owner: rootService}},
		{path: e.Layout.ConfigPath + config.ConfigV8BackupSuffix, stateMode: stateMode{mode: 0o600, owner: rootOwner()}},
		{path: config.MigrationRecordPath(e.Layout.ConfigPath), stateMode: stateMode{mode: 0o640, owner: rootService}},
	}
}

// writerTemporary reports a file a writer stages before it renames it into
// place (internal/safefile).
func writerTemporary(name string) bool { return strings.HasPrefix(name, ".safefile-") }

// settleStateModes gives every entry of the state folders and every state
// file next to config.yaml the owner and mode it is written with. The service
// account can write the data folder, so the walk never follows a link: each
// entry is opened relative to its open parent without following a symlink,
// changed through that descriptor, and a file with another name elsewhere
// (a hard link, which could be any file) is refused rather than re-owned.
func (l *lifecycle) settleStateModes(account Account) error {
	env := l.env
	for _, tree := range env.stateTrees(account) {
		var changed []string
		if err := env.settleStateTree(tree, &changed); err != nil {
			return err
		}
		if len(changed) > 0 {
			l.noteChange("restored the owner and mode of %d %s under %s (%s)", len(changed), plural(len(changed), "entry", "entries"), tree.dir, examples(changed))
		}
	}
	for _, file := range env.configStateFiles(account) {
		path := env.P(file.path)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || !env.metadataDiffers(path, file.mode, file.owner) {
			continue
		}
		if err := env.fixMetadata(path, file.mode, file.owner); err != nil {
			return err
		}
		l.noteChange("restored the mode and owner of %s", file.path)
	}
	return nil
}

func (e *Env) settleStateTree(tree stateTree, changed *[]string) error {
	fd, err := unix.Open(e.P(tree.dir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s: %w", tree.dir, err)
	}
	dir := os.NewFile(uintptr(fd), e.P(tree.dir))
	defer dir.Close()
	return e.settleStateEntries(dir, tree, "", 0, changed)
}

func (e *Env) settleStateEntries(dir *os.File, tree stateTree, rel string, depth int, changed *[]string) error {
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("list %s: %w", filepath.Join(tree.dir, rel), err)
	}
	sort.Strings(names)
	for _, name := range names {
		if writerTemporary(name) {
			continue
		}
		child := filepath.Join(rel, name)
		fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENXIO) || errors.Is(err, unix.EOPNOTSUPP) {
				continue // gone, a symlink, or a socket: nothing of ours to restore
			}
			return fmt.Errorf("open %s: %w", filepath.Join(tree.dir, child), err)
		}
		entry := os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name))
		err = e.settleStateEntry(entry, tree, child, depth, changed)
		entry.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *Env) settleStateEntry(entry *os.File, tree stateTree, rel string, depth int, changed *[]string) error {
	info, err := entry.Stat()
	if err != nil {
		return fmt.Errorf("inspect %s: %w", filepath.Join(tree.dir, rel), err)
	}
	isDir := info.IsDir()
	if !isDir && !info.Mode().IsRegular() {
		return nil
	}
	want := tree.rule(rel, isDir)
	uid, gid, err := e.OwnerOf(entry.Name())
	if err != nil {
		return fmt.Errorf("inspect %s: %w", filepath.Join(tree.dir, rel), err)
	}
	if mode, drifted := e.drift(info, uid, gid, want, true); drifted || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		if st, ok := info.Sys().(*syscall.Stat_t); ok && !isDir && st.Nlink != 1 {
			return fmt.Errorf("%s has %d names (hard links), and another name could be any file, so its owner and mode are left as they are (%04o %d:%d, want %04o %d:%d); remove the other names, then rerun `%s`",
				filepath.Join(tree.dir, rel), st.Nlink, info.Mode().Perm(), uid, gid, mode, want.owner.UID, want.owner.GID, e.lifecycleCommand(ActionRepair))
		}
		// The mode first: another account loses access before the owner changes.
		if err := entry.Chmod(mode); err != nil {
			return fmt.Errorf("chmod %s: %w", filepath.Join(tree.dir, rel), err)
		}
		if err := e.Fchown(entry, want.owner.UID, want.owner.GID); err != nil {
			return fmt.Errorf("chown %s: %w", filepath.Join(tree.dir, rel), err)
		}
		*changed = append(*changed, rel)
	}
	if isDir && depth < maxStateDepth {
		return e.settleStateEntries(entry, tree, rel, depth+1, changed)
	}
	return nil
}

// clearStaleHookSocket removes what keeps the macOS gateway from binding its
// hook socket: it binds run/hook.sock itself and refuses to replace a socket
// another account owns, or anything that is not a socket. After chown -R
// root:wheel over the deployment the stale socket belonged to root, and every
// repair, ensure and apply trigger run failed activation and rolled back
// until someone removed it by hand (GAP-0746). Only root and the service
// account can create entries in run/, so such an entry is a leftover; a
// socket something still answers on is kept. On Linux systemd creates and
// owns the hook socket.
func (l *lifecycle) clearStaleHookSocket(account Account) {
	env := l.env
	if env.GOOS != "darwin" {
		return
	}
	path := env.P(env.Layout.HookSocketPath)
	info, err := os.Lstat(path)
	if err != nil || info.IsDir() {
		return
	}
	uid, _, err := env.OwnerOf(path)
	if err != nil {
		return
	}
	if info.Mode()&os.ModeSocket != 0 {
		if uid == account.UID {
			return // the gateway replaces a stale socket of its own
		}
		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			_ = conn.Close()
			return
		}
	}
	if err := os.Remove(path); err == nil {
		l.noteChange("removed the stale %s (owner uid %d), which kept the gateway from binding its hook socket", env.Layout.HookSocketPath, uid)
	}
}

// stateModeProblems names the entries of the state folders and the state
// files next to config.yaml whose owner or mode differs from the one they are
// written with. Entries the caller cannot read (status as a standard user)
// are not reported.
func (e *Env) stateModeProblems(account Account) []string {
	var problems []string
	repair := e.lifecycleCommand(ActionRepair)
	for _, tree := range e.stateTrees(account) {
		root := e.P(tree.dir)
		var wrong []string
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || path == root {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			if writerTemporary(d.Name()) || (!d.IsDir() && !d.Type().IsRegular()) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			uid, gid, err := e.OwnerOf(path)
			if err != nil {
				return nil
			}
			want := tree.rule(rel, d.IsDir())
			if mode, drifted := e.drift(info, uid, gid, want, false); drifted {
				wrong = append(wrong, fmt.Sprintf("%s is %04o %d:%d, want %04o %d:%d", rel, info.Mode().Perm(), uid, gid, mode, want.owner.UID, want.owner.GID))
			}
			if d.IsDir() && strings.Count(rel, string(filepath.Separator)) >= maxStateDepth-1 {
				return fs.SkipDir
			}
			return nil
		})
		if len(wrong) > 0 {
			problems = append(problems, fmt.Sprintf("%d %s under %s %s the wrong owner or mode (%s), so the gateway may be unable to use them or other accounts able to read them; run `%s` to restore them",
				len(wrong), plural(len(wrong), "entry", "entries"), tree.dir, plural(len(wrong), "has", "have"), examples(wrong), repair))
		}
	}
	for _, file := range e.configStateFiles(account) {
		path := e.P(file.path)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if uid, gid, err := e.OwnerOf(path); err == nil && (info.Mode().Perm() != file.mode || uid != file.owner.UID || gid != file.owner.GID) {
			problems = append(problems, fmt.Sprintf("%s is %04o %d:%d, want %04o %d:%d; run `%s` to restore it", file.path, info.Mode().Perm(), uid, gid, file.mode, file.owner.UID, file.owner.GID, repair))
		}
	}
	return problems
}

// closePrivateDirs removes the permission bits the private folders (the
// gateway data, the credentials, the hook guardian folders and the lifecycle
// state) have beyond their managed mode, and those of the config_version 8
// backup, which can hold a credential. It only takes access away, so a run
// does it before it waits for the lifecycle lock: after chmod -R a+rX a
// standard user could read runtime/device.key and runtime/.env until a
// transaction re-applied the folder modes, and a transaction that rolled
// back put the loosened modes back from its snapshot (GAP-0747).
func (e *Env) closePrivateDirs(ctx context.Context) {
	loadCredential := e.GOOS == "linux" && e.Services.Version(ctx) >= loadCredentialSystemd
	private := map[string]bool{
		e.Layout.DataDir: true, e.Layout.SecretsDir: true, filepath.Dir(e.Layout.ManifestPath): true,
		e.Layout.GuardianAuthDir: true, e.Layout.LifecycleDir: true,
	}
	for _, dir := range e.managedDirs(Account{}, loadCredential) {
		if private[dir.Path] {
			e.removeExtraModeBits(dir.Path, dir.Mode, true)
		}
	}
	e.removeExtraModeBits(e.Layout.ConfigPath+config.ConfigV8BackupSuffix, 0o600, false)
}

// removeExtraModeBits clears the bits of a folder or regular file beyond
// mode, through a descriptor opened without following a link.
func (e *Env) removeExtraModeBits(canonical string, mode os.FileMode, dir bool) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	if dir {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(e.P(canonical), flags, 0)
	if err != nil {
		return
	}
	f := os.NewFile(uintptr(fd), e.P(canonical))
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() != dir || (!dir && !info.Mode().IsRegular()) {
		return
	}
	if extra := info.Mode().Perm() &^ mode; extra != 0 {
		_ = f.Chmod(info.Mode().Perm() & mode)
	}
}

// examples lists the first three items and how many more there are.
func examples(items []string) string {
	if len(items) <= 3 {
		return strings.Join(items, "; ")
	}
	return strings.Join(items[:3], "; ") + fmt.Sprintf("; and %d more", len(items)-3)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
