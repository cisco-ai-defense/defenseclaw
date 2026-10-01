//go:build !windows

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
	"syscall"
)

// systemdCredentialsRoot is where systemd materializes LoadCredential=
// files; only accept $CREDENTIALS_DIRECTORY beneath it.
const systemdCredentialsRoot = "/run/credentials/"

func resolvePlatformServiceCredential(name, secretsDir string) ([]byte, CredentialSource, error) {
	if dir := strings.TrimSpace(os.Getenv("CREDENTIALS_DIRECTORY")); dir != "" {
		data, err := readSystemdCredential(dir, name)
		if err == nil {
			return data, CredentialFromSystemd, nil
		}
		if !errors.Is(err, ErrNoServiceCredential) {
			return nil, "", err
		}
	}
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
	if err := validateProtectedCredentialFile(path); err != nil {
		return nil, "", err
	}
	data, err := readBoundedCredential(path)
	if err != nil {
		return nil, "", fmt.Errorf("credential %s: %w", name, err)
	}
	return data, CredentialFromFile, nil
}

// readSystemdCredential reads a LoadCredential= file. systemd creates the
// directory privately for the unit; the environment variable itself comes
// from the root-owned unit, so a user cannot redirect it.
func readSystemdCredential(dir, name string) ([]byte, error) {
	clean := filepath.Clean(dir)
	if !strings.HasPrefix(clean+"/", systemdCredentialsRoot) {
		return nil, fmt.Errorf("CREDENTIALS_DIRECTORY %q is outside %s", dir, systemdCredentialsRoot)
	}
	path := filepath.Join(clean, name)
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoServiceCredential
		}
		return nil, fmt.Errorf("inspect systemd credential %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("systemd credential %s is not a protected regular file", name)
	}
	return readBoundedCredential(path)
}

// validateProtectedCredentialFile requires a root-owned regular file whose
// ancestors are administrator-owned, that no group or other principal can
// write, and that other users cannot read. Group read is allowed so a
// root:<service group> 0640 file can serve a non-root gateway.
func validateProtectedCredentialFile(path string) error {
	if err := ValidateTrustedFilePath(path, "protected credential"); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("%s: protected credential must not be accessible to other users (mode %04o)", path, info.Mode().Perm())
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
		return fmt.Errorf("%s: protected credential must have exactly one link", path)
	}
	return nil
}
