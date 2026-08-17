// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	windowspayload "github.com/defenseclaw/defenseclaw/packaging/windows"
)

// errWindowsEnterpriseInstallerNotFound marks the case where discovery found
// no installer beside the executable, which is the only case the embedded copy
// may answer.
var errWindowsEnterpriseInstallerNotFound = errors.New(
	"Windows enterprise installer was not found",
)

// stageWindowsEnterprisePayload writes the embedded lifecycle scripts to disk
// and returns the entry script with the cleanup that removes them. The two
// files travel together because the script imports its module by name from its
// own directory.
func stageWindowsEnterprisePayload() (string, func() error, error) {
	return stageWindowsEnterprisePayloadIn(newWindowsEnterprisePayloadDirectory)
}

func stageWindowsEnterprisePayloadIn(
	newDirectory func() (string, error),
) (string, func() error, error) {
	if !windowspayload.Available() {
		return "", nil, errors.New("this build carries no embedded Windows enterprise installer")
	}
	directory, err := newDirectory()
	if err != nil {
		return "", nil, err
	}
	cleanup := func() error {
		if err := os.RemoveAll(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove the staged Windows enterprise installer: %w", err)
		}
		return nil
	}
	script := filepath.Join(directory, windowspayload.InstallerName)
	module := filepath.Join(directory, windowspayload.ModuleName)
	for path, content := range map[string][]byte{
		script: windowspayload.Installer(),
		module: windowspayload.Module(),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return "", nil, errors.Join(
				fmt.Errorf("stage the embedded %s: %w", filepath.Base(path), err),
				cleanup(),
			)
		}
		if err := protectWindowsEnterpriseStagedPayload(path); err != nil {
			return "", nil, errors.Join(
				fmt.Errorf("protect the embedded %s: %w", filepath.Base(path), err),
				cleanup(),
			)
		}
	}
	// The staged pair meets the same trust gate as a pair found on disk, so a
	// staging root anyone else can write fails here rather than in PowerShell.
	if err := windowsEnterpriseTrustValidator(script); err != nil {
		return "", nil, errors.Join(err, cleanup())
	}
	return script, cleanup, nil
}

// protectWindowsEnterpriseStagedPayload aligns files created in the elevated
// ProgramData capability with its machine-trusted ownership. os.WriteFile
// otherwise leaves them owned by the creating administrator account even
// though the parent has an Administrators-owned protected DACL. Unelevated
// status staging remains owned by the calling user and is validated against
// that same user's trusted temporary-directory boundary.
func protectWindowsEnterpriseStagedPayload(path string) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	administrators, err := windows.CreateWellKnownSid(
		windows.WinBuiltinAdministratorsSid,
	)
	if err != nil {
		return fmt.Errorf("resolve the Administrators SID: %w", err)
	}
	if err := setEnterpriseWindowsRuntimeProtection(
		path,
		administrators,
		nil,
		false,
	); err != nil {
		return fmt.Errorf("apply machine-trusted payload protection: %w", err)
	}
	return nil
}

// newWindowsEnterprisePayloadDirectory creates the directory the scripts are
// staged into. An elevated run stages under a root only SYSTEM and
// Administrators can write, so nobody can swap a script between this write and
// the read PowerShell makes.
func newWindowsEnterprisePayloadDirectory() (string, error) {
	if windows.GetCurrentProcessToken().IsElevated() {
		parent, err := windowsEnterpriseProgramDataResolver()
		if err != nil {
			return "", fmt.Errorf("resolve the trusted ProgramData directory: %w", err)
		}
		return createProtectedWindowsEnterpriseDirectory(
			parent,
			"DefenseClaw-Installer-",
			"Windows enterprise installer staging",
			rand.Read,
			windows.CreateDirectory,
		)
	}
	// Unelevated status runs stage in the caller's own temp directory, whose
	// per-user ownership the trust gate then confirms.
	parent, err := trustedWindowsEnterpriseUserTempDirectory()
	if err != nil {
		return "", err
	}
	directory, err := os.MkdirTemp(parent, "DefenseClaw-Installer-")
	if err != nil {
		return "", fmt.Errorf("create the Windows enterprise installer staging directory: %w", err)
	}
	if err := managed.ValidateTrustedRuntimeDir(
		directory,
		"Windows enterprise installer staging directory",
	); err != nil {
		return "", errors.Join(err, os.RemoveAll(directory))
	}
	return directory, nil
}
