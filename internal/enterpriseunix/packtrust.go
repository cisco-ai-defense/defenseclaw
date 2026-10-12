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
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rulePackTreeMaxEntries bounds the walk of an administrator rule pack.
const rulePackTreeMaxEntries = 20000

var errRulePackTreeTooLarge = errors.New("too many entries")

// rulePackTrust is the TrustRulePack check. The pack folder and the folders
// above it pass the gateway's own check of a managed rule pack (no symlink,
// not writable by group or others, no ACL write entry, owned by root or the
// service account), so ensure refuses a pack before the gateway is
// restarted into a failed start (GAP-0546). Every folder and file in the
// pack is then owned by root, so a standard user who owns one file (a pack
// copied with cp -a) cannot change what every user's agents are held to
// (GAP-0552).
func rulePackTrust(dir string) error {
	if err := managed.ValidateTrustedRuntimeDir(dir, "rule pack"); err != nil {
		return err
	}
	return rulePackTreeTrust(dir, func(uid uint32) bool { return uid == 0 })
}

// rulePackTreeTrust walks the pack without following links: each entry must
// not be a symlink, writable by group or others or carry an ACL write
// entry, and must be owned by an account trustedOwner accepts.
func rulePackTreeTrust(dir string, trustedOwner func(uint32) bool) error {
	entries := 0
	err := filepath.WalkDir(dir, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entries++; entries > rulePackTreeMaxEntries {
			return errRulePackTreeTooLarge
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; symlinks are not allowed in a rule pack", path)
		}
		if perm := info.Mode().Perm(); perm&0o022 != 0 {
			return fmt.Errorf("%s: group/other writable permissions %04o are not trusted", path, perm)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: cannot inspect the owner", path)
		}
		if !trustedOwner(st.Uid) {
			return fmt.Errorf("%s is owned by uid %d, not root", path, st.Uid)
		}
		return managed.ValidatePathACL(path)
	})
	if errors.Is(err, errRulePackTreeTooLarge) {
		return fmt.Errorf("%s has more than %d entries", dir, rulePackTreeMaxEntries)
	}
	return err
}

// sandboxPackDirProblem checks <policy_dir>/sandbox, the administrator's
// sandbox packs folder, when it exists: it holds what each profile's users
// are held to, so it must be a real folder owned by root, writable only by
// root, closed to other accounts (the packs name profiles and hosts users
// must not see), and readable by the gateway service account, which loads the
// packs, through every folder above it. ensure refuses a folder that fails,
// whether or not the config changed (GAP-0380, GAP-0403); status and verify
// report it. It returns "" for a good folder or none.
func (e *Env) sandboxPackDirProblem(ctx context.Context, cfg *config.Config) string {
	dir := e.sandboxPackDir(cfg)
	info, err := os.Lstat(e.P(dir))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ""
	case err != nil:
		return fmt.Sprintf("cannot inspect the sandbox packs folder %s: %v", dir, err)
	}
	account, haveAccount, err := e.Accounts.Lookup(ctx, e.Layout.ServiceUser)
	if err != nil {
		return fmt.Sprintf("cannot look up the %s gateway service account to check the sandbox packs folder %s: %v", e.Layout.ServiceUser, dir, err)
	}
	fix := e.sandboxPackDirFix(dir)
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Sprintf("the sandbox packs folder %s is not a folder (a symlink or a file); %s", dir, fix)
	}
	uid, gid, err := e.OwnerOf(e.P(dir))
	if err != nil {
		return fmt.Sprintf("cannot inspect the owner of the sandbox packs folder %s: %v", dir, err)
	}
	perm := info.Mode().Perm()
	groupOK := gid == 0 || (haveAccount && gid == account.GID)
	switch {
	case perm&0o007 != 0:
		return fmt.Sprintf("the sandbox packs folder %s is %04o, so every account can read the sandbox policy of every profile; %s", dir, perm, fix)
	case uid != 0 || perm&0o020 != 0 || !groupOK:
		return fmt.Sprintf("the sandbox packs folder %s is %04o owned by uid %d gid %d, so an account other than root could change or read the sandbox policy; %s",
			dir, perm, uid, gid, fix)
	}
	if err := e.Trust(e.P(dir), TrustRuntimeDir); err != nil {
		return fmt.Sprintf("the sandbox packs folder %s is not administrator-controlled: %v; %s", dir, err, fix)
	}
	if !haveAccount {
		return ""
	}
	if !accountMayAccess(uid, gid, info.Mode(), account, 0o5) {
		return fmt.Sprintf("the sandbox packs folder %s is %04o, so the %s gateway service account cannot read the packs; %s", dir, perm, e.Layout.ServiceUser, fix)
	}
	for parent := filepath.Dir(dir); parent != "/" && parent != "."; parent = filepath.Dir(parent) {
		puid, pgid, mode, err := statOwnerMode(e.P(parent))
		if err == nil && mode.IsDir() && !accountMayAccess(puid, pgid, mode, account, 0o1) {
			return fmt.Sprintf("%s is %04o, so the %s gateway service account cannot reach the sandbox packs below it; %s",
				parent, mode.Perm(), e.Layout.ServiceUser, e.serviceGroupTraverseFix(parent))
		}
	}
	return e.sandboxPacksUnreadable(dir, account)
}

// sandboxPacksUnreadable names the first folder or file in the sandbox packs
// folder the service account cannot read. Such a pack passed the folder
// check and failed only when the gateway activated, reported as outside the
// policy tree (GAP-0521).
func (e *Env) sandboxPacksUnreadable(dir string, account Account) string {
	root := e.P(dir)
	var problem string
	_ = filepath.WalkDir(root, func(full string, d fs.DirEntry, err error) error {
		if err != nil || full == root {
			return err
		}
		info, err := os.Lstat(full)
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
			return err
		}
		uid, gid, err := e.OwnerOf(full)
		if err != nil {
			return err
		}
		need := os.FileMode(0o4)
		if info.IsDir() {
			need = 0o5
		}
		if accountMayAccess(uid, gid, info.Mode(), account, need) {
			return nil
		}
		shown := dir
		if rel, relErr := filepath.Rel(root, full); relErr == nil {
			shown = filepath.Join(dir, rel)
		}
		group := e.Layout.ServiceGroup
		problem = fmt.Sprintf("%s is %04o owned by uid %d gid %d, so the %s gateway service account cannot read the sandbox pack; "+
			"let the %s service group read every pack without opening them to other accounts (for example: chown -R root:%s %s && chmod -R u=rwX,g=rX,o= %s) and retry",
			shown, info.Mode().Perm(), uid, gid, e.Layout.ServiceUser, group, group, dir, dir)
		return filepath.SkipAll
	})
	return problem
}

// settleStagedSandboxPacks lets the gateway service group read a sandbox
// packs folder the administrator staged before the first install. The
// service group does not exist before the install creates it, so no mode the
// administrator could give the folder passed sandboxPackDirProblem: 0755
// opens it to every account, root:root 0750 shuts the gateway out
// (GAP-0501). On a first install only, a folder that is root's and
// administrator-controlled (a real folder below a trusted chain, every entry
// root-owned, without links, group or other write, or ACL entries) becomes
// root:<service group> 0750, and every root-group entry in it gets the
// service group with group read (and search on folders). Anything else is
// left to sandboxPackDirProblem to refuse. It returns the change made, or "".
func (e *Env) settleStagedSandboxPacks(cfg *config.Config, account Account) (string, error) {
	dir := e.sandboxPackDir(cfg)
	full := e.P(dir)
	info, err := os.Lstat(full)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || account.GID <= 0 {
		return "", nil
	}
	if e.Trust(full, TrustRuntimeDir) != nil {
		return "", nil
	}
	type entry struct {
		path string
		mode os.FileMode
		gid  int
		dir  bool
	}
	var entries []entry
	walkErr := filepath.WalkDir(full, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if len(entries) >= rulePackTreeMaxEntries {
			return errRulePackTreeTooLarge
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) || info.Mode().Perm()&0o022 != 0 {
			return errNotSettled
		}
		uid, gid, err := e.OwnerOf(path)
		if err != nil || uid != 0 || (gid != 0 && gid != account.GID) {
			return errNotSettled
		}
		if err := managed.ValidatePathACL(path); err != nil {
			return errNotSettled
		}
		entries = append(entries, entry{path: path, mode: info.Mode().Perm(), gid: gid, dir: info.IsDir()})
		return nil
	})
	if walkErr != nil {
		// Not administrator-controlled as a whole: refused, unchanged.
		return "", nil
	}
	changed := 0
	for _, en := range entries {
		mode := en.mode
		switch {
		case en.path == full:
			mode = mode&^0o007 | 0o050
		case en.dir:
			mode |= 0o050
		case mode&0o400 != 0:
			mode |= 0o040
		}
		if en.gid == account.GID && mode == en.mode {
			continue
		}
		if err := e.Lchown(en.path, 0, account.GID); err != nil {
			return "", fmt.Errorf("give the %s service group the staged sandbox packs %s: %w", e.Layout.ServiceGroup, dir, err)
		}
		if err := os.Chmod(en.path, mode); err != nil {
			return "", fmt.Errorf("give the %s service group the staged sandbox packs %s: %w", e.Layout.ServiceGroup, dir, err)
		}
		changed++
	}
	if changed == 0 {
		return "", nil
	}
	return fmt.Sprintf("gave the %s service group read access to the sandbox packs staged in %s before the install (%d %s, now root:%s and closed to other accounts)",
		e.Layout.ServiceGroup, dir, changed, plural(changed, "entry", "entries"), e.Layout.ServiceGroup), nil
}

var errNotSettled = errors.New("not administrator-controlled")

// sandboxPackDir is <policy_dir>/sandbox.
func (e *Env) sandboxPackDir(cfg *config.Config) string {
	policyDir := e.Layout.PolicyDir
	if cfg != nil && strings.TrimSpace(cfg.PolicyDir) != "" {
		policyDir = filepath.Clean(cfg.PolicyDir)
	}
	return filepath.Join(policyDir, "sandbox")
}

// sandboxPackDirFix is the fix named with a refused sandbox packs folder:
// root and the service group, never other accounts.
func (e *Env) sandboxPackDirFix(dir string) string {
	return fmt.Sprintf("make it a folder owned by root:%s with mode 0750 (for example: chown -R root:%s %s && chmod 0750 %s) and retry",
		e.Layout.ServiceGroup, e.Layout.ServiceGroup, dir, dir)
}

// serviceGroupTraverseFix is the fix for a folder the gateway service
// account cannot pass through: give it to the service group, which keeps it
// closed to every other account (GAP-0258: o+x opened it to all of them).
func (e *Env) serviceGroupTraverseFix(dir string) string {
	return fmt.Sprintf("let the %s service group through it without opening it to other accounts (for example: chown root:%s %s && chmod 0750 %s) and retry",
		e.Layout.ServiceGroup, e.Layout.ServiceGroup, dir, dir)
}

// rulePackTrustAdvice is the fix named with a refused pack.
const rulePackTrustAdvice = "keep every folder and file of the pack, and the folders above it, owned by root and not writable by group or others, without symlinks or ACL entries that grant write (for example: chown -R root:root <pack> && chmod -R go-w <pack>)"
