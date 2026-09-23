//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/acp"
)

func alignEnterpriseACPCredentialOwner(dataDir, principal, client, agent, profile, token string) error {
	info, err := os.Stat(dataDir)
	if err != nil {
		return fmt.Errorf("enterprise ACP: inspect managed data_dir owner: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("enterprise ACP: cannot inspect managed data_dir owner")
	}
	path, err := acp.EnterpriseCredentialPath(dataDir, principal, client, agent, profile)
	if err != nil {
		return err
	}
	indexPath, err := acp.EnterpriseCredentialIndexPath(dataDir, token)
	if err != nil {
		return err
	}
	for _, item := range []string{
		filepath.Join(dataDir, "acp"), filepath.Dir(path), path, filepath.Dir(indexPath), indexPath,
	} {
		entry, err := os.Lstat(item)
		if err != nil {
			return err
		}
		if entry.Mode()&os.ModeSymlink != 0 || (!entry.IsDir() && !entry.Mode().IsRegular()) {
			return fmt.Errorf("enterprise ACP: unsafe service credential path: %s", item)
		}
		if os.Geteuid() == 0 {
			if err := os.Lchown(item, int(stat.Uid), int(stat.Gid)); err != nil {
				return fmt.Errorf("enterprise ACP: align service credential owner: %w", err)
			}
		}
		mode := os.FileMode(0o600)
		if entry.IsDir() {
			mode = 0o700
		}
		if err := os.Chmod(item, mode); err != nil {
			return err
		}
	}
	return nil
}
