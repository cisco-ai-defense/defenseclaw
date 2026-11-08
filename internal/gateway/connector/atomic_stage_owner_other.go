//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/runtimeowner"
)

// The three variables are the process facts the owner decision reads, so a test
// can stand in for the root run it cannot be.
var (
	atomicStageEUID    = os.Geteuid
	atomicStageTrusted = runtimeowner.Trusted
	atomicStageChown   = func(path string, uid, gid int) error { return os.Lchown(path, uid, gid) }
)

// atomicStageKeepOwner gives a file this process just created for an agent
// config to the account that owns that config. A gateway that runs as root for
// an account (sudo, a helper) would otherwise stage every vendor file
// (~/.claude/settings.json, ~/.codex/config.toml, ~/.copilot/hooks/...) as
// root, and the rename over the account's file hands it a root:600 config it
// cannot read (GAP-0848). The owner is the one the replaced file has, or, for a
// new file or one root already owns, the one the folder has: the account the
// folder belongs to. It does nothing for a non-root process, for a file in a
// root-owned folder (a machine-wide config stays root's), and for an owner that
// is neither the process nor an account-verified sudo invoker.
func atomicStageKeepOwner(stagedPath, writePath string) error {
	if atomicStageEUID() != 0 {
		return nil
	}
	uid, gid, ok := atomicStageOwner(writePath)
	if !ok {
		return nil
	}
	if err := atomicStageChown(stagedPath, int(uid), int(gid)); err != nil {
		return fmt.Errorf("give %s to its owner %d:%d: %w", stagedPath, uid, gid, err)
	}
	return nil
}

func atomicStageOwner(writePath string) (uid, gid uint32, ok bool) {
	if info, err := os.Lstat(writePath); err == nil && info.Mode().IsRegular() {
		if uid, gid, ok = atomicStageTrustedOwner(info); ok {
			return uid, gid, true
		}
	}
	if info, err := os.Stat(filepath.Dir(writePath)); err == nil && info.IsDir() {
		return atomicStageTrustedOwner(info)
	}
	return 0, 0, false
}

func atomicStageTrustedOwner(info os.FileInfo) (uid, gid uint32, ok bool) {
	stat, isStat := info.Sys().(*syscall.Stat_t)
	if !isStat || stat.Uid == 0 || !atomicStageTrusted(stat.Uid) {
		return 0, 0, false
	}
	return stat.Uid, stat.Gid, true
}

// atomicMkdirAll is os.MkdirAll that, for a root process, gives the folders it
// created to the account that owns the nearest folder that already existed: a
// missing ~/.copilot/hooks made by root is a root-owned folder the account
// cannot write to.
func atomicMkdirAll(dir string, perm os.FileMode) error {
	var created []string
	if atomicStageEUID() == 0 {
		for missing := filepath.Clean(dir); ; missing = filepath.Dir(missing) {
			if _, err := os.Lstat(missing); err == nil || !os.IsNotExist(err) {
				break
			}
			created = append(created, missing)
			if parent := filepath.Dir(missing); parent == missing {
				break
			}
		}
	}
	if err := os.MkdirAll(dir, perm); err != nil {
		return err
	}
	if len(created) == 0 {
		return nil
	}
	existing, err := os.Stat(filepath.Dir(created[len(created)-1]))
	if err != nil {
		return nil
	}
	uid, gid, ok := atomicStageTrustedOwner(existing)
	if !ok {
		return nil
	}
	for _, made := range created {
		if err := atomicStageChown(made, int(uid), int(gid)); err != nil {
			return fmt.Errorf("give %s to its owner %d:%d: %w", made, uid, gid, err)
		}
	}
	return nil
}
