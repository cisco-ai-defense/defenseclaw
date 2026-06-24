//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func resolveOwner(home string, uid, gid int) (int, int, error) {
	if uid < 0 || gid < 0 {
		info, err := os.Stat(home)
		if err != nil {
			return 0, 0, fmt.Errorf("enterprise hooks: stat user home owner: %w", err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, 0, fmt.Errorf("enterprise hooks: cannot inspect user home owner")
		}
		if uid < 0 {
			uid = int(st.Uid)
		}
		if gid < 0 {
			gid = int(st.Gid)
		}
	}
	if uid == 0 {
		return 0, 0, fmt.Errorf("enterprise hooks: refusing to target uid 0")
	}
	return uid, gid, nil
}

func fileOwnerMatches(path string, uid int) (bool, int) {
	if uid < 0 {
		return true, uid
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, -1
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, -1
	}
	return int(st.Uid) == uid, int(st.Uid)
}

func chownInstallFootprint(uid, gid int, dataDir string, footprint connector.AgentPaths, hookConfigPaths []string) error {
	if uid < 0 || gid < 0 {
		return nil
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("enterprise hooks: ensure data dir %s: %w", dataDir, err)
	}
	if err := chownTree(dataDir, uid, gid); err != nil {
		return err
	}
	for _, path := range append(append([]string{}, footprint.PatchedFiles...), hookConfigPaths...) {
		if path == "" {
			continue
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("enterprise hooks: chown %s: %w", path, err)
		}
	}
	for _, path := range footprint.CreatedDirs {
		if path == "" {
			continue
		}
		if err := chownTree(path, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func chownTree(root string, uid, gid int) error {
	if _, err := os.Lstat(root); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("enterprise hooks: inspect %s: %w", root, err)
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("enterprise hooks: walk %s: %w", path, err)
		}
		if err := os.Lchown(path, uid, gid); err != nil {
			return fmt.Errorf("enterprise hooks: chown %s: %w", path, err)
		}
		return nil
	})
}
