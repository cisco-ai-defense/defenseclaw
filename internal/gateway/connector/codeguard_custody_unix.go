// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package connector

import (
	"fmt"
	"os"
	"path/filepath"
)

func validateCodexCodeGuardTreeParentCustody(root string) error {
	parent := filepath.Dir(root)
	if _, err := os.Lstat(parent); err == nil {
		if err := hookAPIValidateDirectory(parent); err != nil {
			return fmt.Errorf("validate Codex CodeGuard skill parent custody: %w", err)
		}
		return nil
	} else if os.IsNotExist(err) {
		return nil
	} else {
		return err
	}
}

func validateCodexCodeGuardPrivateStateDirectory(path string) error {
	return hookAPIValidateDirectory(path)
}

func validateCodexCodeGuardTreeEntryCustody(path string, info os.FileInfo) error {
	if info == nil {
		return fmt.Errorf("missing Codex CodeGuard skill path identity: %s", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("Codex CodeGuard skill path is group/other writable: %s", path)
	}
	if err := hookAPIValidateOwner(path, info); err != nil {
		return fmt.Errorf("validate Codex CodeGuard skill path owner: %w", err)
	}
	if err := hookAPIValidateDirectoryACL(path); err != nil {
		return fmt.Errorf("validate Codex CodeGuard skill path ACL: %w", err)
	}
	return nil
}
