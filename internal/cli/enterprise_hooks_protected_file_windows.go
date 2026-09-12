// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
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

// writeEnterpriseHookAdminOnlyFile publishes an installer-only machine file
// whose readers are always elevated (never a running service). It stamps the
// exact two-ACE AdminFile SDDL — Administrators owner+group, protected DACL
// granting SYSTEM + Administrators FULL — that
// enterprisehooks.ValidateWindowsManagedRuntimeAdminFile expects. The
// ordinary writeEnterpriseHookProtectedFile above additionally grants the
// gateway service a read ACE; that extra ACE fails this validator's strict
// two-ACE check on subsequent uninstall (the "DACL has 3 ACEs, want 2"
// regression on the managed hook contract cleanup receipt).
func writeEnterpriseHookAdminOnlyFile(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("empty admin-only file path")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect admin-only file parent: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return fmt.Errorf("admin-only file parent is not a regular directory: %s", parent)
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("admin-only file is not a regular non-link file: %s", path)
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect admin-only file: %w", statErr)
	}

	tmp, err := os.CreateTemp(parent, ".defenseclaw-admin-only-*")
	if err != nil {
		return fmt.Errorf("create admin-only file temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write admin-only file temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync admin-only file temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close admin-only file temp: %w", err)
	}
	if err := enterprisehooks.ProtectWindowsManagedRuntimeAdminFile(tmpPath); err != nil {
		return fmt.Errorf("protect admin-only file temp: %w", err)
	}
	if err := safefile.ReplaceFile(tmpPath, path); err != nil {
		return fmt.Errorf("publish admin-only file: %w", err)
	}
	// If the destination existed with a different (broader) ACL,
	// safefile.ReplaceFile may have preserved it — re-stamp the strict
	// two-ACE AdminFile shape after the rename so the file always ends
	// up in the exact shape the validator expects.
	if err := enterprisehooks.ProtectWindowsManagedRuntimeAdminFile(path); err != nil {
		return fmt.Errorf("stamp admin-only file: %w", err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read published admin-only file: %w", err)
	}
	if !bytes.Equal(persisted, data) {
		return fmt.Errorf("admin-only file changed during publication: %s", path)
	}
	return nil
}
