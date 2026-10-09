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
