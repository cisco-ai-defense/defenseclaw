// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"path/filepath"
	"sync"
)

// enterpriseCredentialEnrollmentMu serializes callers in this process too.
var enterpriseCredentialEnrollmentMu sync.Mutex

func enterpriseCredentialEnrollmentLockPath(dataDir string) (string, error) {
	path, err := enterpriseCredentialLockPath(dataDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), ".enterprise-enrollment.lock"), nil
}

// EnterpriseLockFilePaths lists the lock files the ACP enrollment code creates
// lazily under dataDir, so the Guardian and Setup repair cover each of them.
func EnterpriseLockFilePaths(dataDir string) []string {
	var paths []string
	for _, build := range []func(string) (string, error){enterpriseCredentialLockPath, enterpriseCredentialEnrollmentLockPath} {
		if path, err := build(dataDir); err == nil {
			paths = append(paths, path)
		}
	}
	return paths
}
