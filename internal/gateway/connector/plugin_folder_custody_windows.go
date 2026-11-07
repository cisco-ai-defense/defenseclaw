//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// explainPluginFolderCustody names the folder that carries the write access
// another account holds over the plugin folder, and the icacls command that
// removes it. The refusal itself names the inherited child (plugins), which
// is not the folder to fix (GAP-0731). A refusal with no such grant (owner,
// reparse point, unreadable) is returned as it was.
func explainPluginFolderCustody(dir string, chainErr error) error {
	if chainErr == nil {
		return nil
	}
	grant, ok := safefile.FirstForeignWriteGrant(dir)
	if !ok {
		return chainErr
	}
	return agentFolderCustodyError{cause: grant.Cause(), fix: grant.Fix()}
}

// explainPluginFileCustody leaves a refusal of the plugin file as it was.
func explainPluginFileCustody(_ string, _ os.FileInfo, fileErr error) error { return fileErr }
