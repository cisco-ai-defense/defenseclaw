//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// writeEnterpriseCredentialFile uses the managed runtime trust contract on
// Windows. After first enrollment the credential directories are deliberately
// owned by the gateway service SID, so generic current-user private-file
// helpers cannot safely reopen them for an administrator-driven rotation.
func writeEnterpriseCredentialFile(dataDir, path, label string, body []byte) error {
	acpDir := filepath.Join(dataDir, "acp")
	for _, directory := range []string{acpDir, filepath.Dir(path)} {
		if err := managed.PrepareServiceRuntimeDir(
			managed.DeploymentModeManagedEnterprise, directory, label+" directory",
		); err != nil {
			return err
		}
	}
	return managed.WriteServiceRuntimeFile(
		managed.DeploymentModeManagedEnterprise, path, label, body,
	)
}
