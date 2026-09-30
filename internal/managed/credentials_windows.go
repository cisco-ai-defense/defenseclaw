//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func resolvePlatformServiceCredential(name, secretsDir string) ([]byte, CredentialSource, error) {
	if strings.TrimSpace(secretsDir) == "" {
		return nil, "", ErrNoServiceCredential
	}
	path := filepath.Join(secretsDir, name)
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", ErrNoServiceCredential
		}
		return nil, "", fmt.Errorf("inspect credential %s: %w", name, err)
	}
	if err := ValidateTrustedFilePath(path, "protected credential"); err != nil {
		return nil, "", err
	}
	if err := rejectUntrustedCredentialReaders(path); err != nil {
		return nil, "", err
	}
	data, err := readBoundedCredential(path)
	if err != nil {
		return nil, "", fmt.Errorf("credential %s: %w", name, err)
	}
	return data, CredentialFromFile, nil
}

// rejectUntrustedCredentialReaders requires that only LocalSystem,
// Administrators and the pinned gateway service SID hold any allow ACE on
// the credential. ValidateTrustedFilePath only checks writers; a secret
// also needs its readers constrained.
func rejectUntrustedCredentialReaders(path string) error {
	extended, err := winpath.Extended(path)
	if err != nil {
		return fmt.Errorf("%s: encode extended Windows path: %w", path, err)
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: inspect Windows security descriptor: %w", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%s: protected credential needs an explicit DACL", path)
	}
	var gatewaySID *windows.SID
	if account := strings.TrimSpace(os.Getenv(WindowsServiceAccountEnv)); account != "" {
		gatewaySID, err = WindowsServiceAccountSID(account)
		if err != nil {
			return fmt.Errorf("%s: resolve gateway service SID: %w", path, err)
		}
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return fmt.Errorf("%s: inspect Windows ACE %d: %w", path, i, err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if windowsTrustedOwner(sid) {
			continue
		}
		if gatewaySID != nil && sameWindowsSID(sid, gatewaySID) && !windowsWriteLikeAccess(ace.Mask) {
			continue
		}
		return fmt.Errorf("%s: principal %s may read the protected credential; only LocalSystem, Administrators and the gateway service may", path, sidString(sid))
	}
	return nil
}
