// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// validateServiceOwnedAuditDB checks a managed store for an elevated
// administrator's compaction: the folders above it, and audit.db and each
// SQLite sidecar that exists, must pass the checks the gateway's own open
// makes (no reparse point, a trusted owner, no untrusted write entry) and
// carry the protected DACL the managed gateway service's runtime files have.
// Unlike the gateway's open it needs no gateway service token and never
// rewrites an ACL: a file whose DACL is not the managed one is refused, and
// the enterprise repair restores it.
//
// opened is set on the check after the compaction's own open: a sidecar
// that did not exist before (the WAL SQLite creates for the claim, with the
// folder's inherited entries) then needs only the trust checks. Every file
// that existed before the open got the full check first.
func validateServiceOwnedAuditDB(absolute string, opened bool) error {
	serviceSID, err := auditDBWindowsPinnedGatewayServiceSID()
	if err != nil {
		return err
	}
	if serviceSID == nil {
		return errors.New("audit: no managed gateway service is pinned for this store")
	}
	if err := ensureTrustedAuditDBParents(filepath.Dir(absolute), auditDBPathHooks{}.withDefaults(), false); err != nil {
		return err
	}
	paths := []string{absolute}
	for _, suffix := range auditDBSQLiteSidecarSuffixes {
		paths = append(paths, absolute+suffix)
	}
	for index, path := range paths {
		if index > 0 {
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				continue
			}
		}
		if err := validateServiceOwnedAuditDBFile(path, serviceSID, opened && index > 0); err != nil {
			return err
		}
	}
	return nil
}

func validateServiceOwnedAuditDBFile(path string, serviceSID *windows.SID, inheritedOK bool) error {
	file, err := openAuditDBFileNoFollow(path, false, false)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", path, err)
	}
	defer file.Close() //nolint:errcheck -- inspection handle.
	sd, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("audit: inspect the Windows security descriptor of %s: %w", path, err)
	}
	if err := validateAuditDBWindowsSecurityDescriptor(path, sd, false, true); err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("audit: inspect the Windows DACL of %s: %w", path, err)
	}
	if inheritedOK && control&windows.SE_DACL_PROTECTED == 0 {
		return nil
	}
	canonical := false
	if control&windows.SE_DACL_PROTECTED != 0 {
		canonical, err = auditDBWindowsManagedRuntimeFileCanonical(sd, serviceSID)
		if err != nil {
			return err
		}
	}
	if !canonical {
		return fmt.Errorf("audit: %s does not have the managed gateway service's protected DACL; "+
			"run the enterprise repair before you compact it", path)
	}
	return nil
}
