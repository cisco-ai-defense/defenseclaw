// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func writeEnterpriseHookProtectedFile(path string, data []byte) error {
	return safefile.Write(path, data)
}

// writeEnterpriseHookGatewayRecord atomically publishes a guardian record
// that the unprivileged gateway reads, such as the foreign-hook removal
// ledger. The new file gets its final mode (0640) and owner
// (enterpriseHookAuthorizationOwnershipSetter) and passes the record trust
// check before it is renamed into place, so the gateway never meets the
// record in a state it cannot read. The gateway denies every call while it
// cannot read the ledger: a file published 0600 and opened up only after
// its rename denied every account, the clean ones too, for that moment.
func writeEnterpriseHookGatewayRecord(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("guardian record %s is not a regular file", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".new-*")
	if err != nil {
		return fmt.Errorf("create guardian record %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o640)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write guardian record %s: %w", path, err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(tmpPath); err != nil {
		return fmt.Errorf("set the owner of guardian record %s: %w", path, err)
	}
	info, err := os.Lstat(tmpPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 {
		return fmt.Errorf("guardian record %s has mode %s before publication, want 0640", path, info.Mode())
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("publish guardian record %s: %w", path, err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// writeEnterpriseHookAdminOnlyFile mirrors the Windows-only variant on non-
// Windows hosts. Off-Windows there is no AdminFile SDDL to enforce, so the
// implementation folds into safefile.Write like the protected-file variant.
func writeEnterpriseHookAdminOnlyFile(path string, data []byte) error {
	return safefile.Write(path, data)
}

// enterpriseHookGuardianRecordBusy is Windows-only: an atomic rename never
// leaves a guardian record unopenable here.
func enterpriseHookGuardianRecordBusy(error) bool { return false }
