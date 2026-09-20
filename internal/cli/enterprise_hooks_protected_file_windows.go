// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// writeEnterpriseHookProtectedFile publishes machine-owned guardian records
// without safefile's current-user ownership assumption. Production records
// are deliberately owned by BUILTIN\Administrators and are commonly rewritten
// by LocalSystem; staging the exact machine ACL before atomic replacement makes
// both first publication and every subsequent guardian tick repeat-safe.
func writeEnterpriseHookProtectedFile(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("empty protected machine file path")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect protected machine file parent: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return fmt.Errorf("protected machine file parent is not a regular directory: %s", parent)
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("protected machine file is not a regular non-link file: %s", path)
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect protected machine file: %w", statErr)
	}

	tmp, err := os.CreateTemp(parent, ".defenseclaw-machine-state-*")
	if err != nil {
		return fmt.Errorf("create protected machine file temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	defer cleanup()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write protected machine file temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync protected machine file temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close protected machine file temp: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(tmpPath); err != nil {
		return fmt.Errorf("protect machine file temp: %w", err)
	}
	if err := safefile.ReplaceFile(tmpPath, path); err != nil {
		return fmt.Errorf("publish protected machine file: %w", err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read published protected machine file: %w", err)
	}
	if !bytes.Equal(persisted, data) {
		return fmt.Errorf("protected machine file changed during publication: %s", path)
	}
	return nil
}
