// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func alignEnterpriseHookScopedTokenOwner(dataDir, connectorName string) error {
	info, err := os.Stat(dataDir)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect managed data_dir for hook token ownership: %w", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("enterprise hooks: cannot inspect managed data_dir owner")
	}
	uid, gid := int(st.Uid), int(st.Gid)
	tokenPath, err := connector.HookAPITokenFilePath(dataDir, connectorName)
	if err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(filepath.Dir(tokenPath), uid, gid); err != nil {
			return fmt.Errorf("enterprise hooks: chown hook token dir: %w", err)
		}
		if err := os.Chown(tokenPath, uid, gid); err != nil {
			return fmt.Errorf("enterprise hooks: chown hook token: %w", err)
		}
	}
	if err := os.Chmod(tokenPath, 0o600); err != nil {
		return fmt.Errorf("enterprise hooks: chmod hook token: %w", err)
	}
	return nil
}
