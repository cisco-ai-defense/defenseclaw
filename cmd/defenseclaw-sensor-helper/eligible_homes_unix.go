// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Replaced by tests, which cannot create the root-owned record and config.
var (
	loadEligibleAccounts = enterprisehooks.LoadUnixEligibleAccounts
	enrollmentModeFor    = standaloneEnrollmentMode
)

// eligibleHomes is the homes of the accounts the enumerator found eligible,
// as the guardian scans them (GAP-1092): every eligible account outside
// manifest enrollment. Under manifest enrollment the enumerator is idle and
// its record is what its last auto pass published, so only the accounts a
// manifest target enrolls count (GAP-0761). Excluded, exempt and service
// accounts never reach the record, and accounts whose home is untrusted are
// kept apart from it (identity only), so neither is watched.
func eligibleHomes(manifestPath string, manifest enterprisehooks.Manifest) ([]string, error) {
	mode, err := enrollmentModeFor(manifestPath)
	if err != nil {
		return nil, err
	}
	accounts, err := loadEligibleAccounts(enterprisehooks.UnixEligibleAccountsPath(manifestPath))
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(strings.TrimSpace(mode), config.EnterpriseEnrollmentManifest) {
		// A target the administrator disabled enrolls nobody, as in
		// manifestHomes; one that does not say is enabled (GAP-1488).
		enabled := enterprisehooks.Manifest{Targets: slices.DeleteFunc(slices.Clone(manifest.Targets),
			func(target enterprisehooks.ManifestTarget) bool { return !target.IsEnabled() })}
		accounts = enterprisehooks.ManifestEnrolledAccounts(accounts, enabled)
	}
	homes := make([]string, 0, len(accounts))
	for _, account := range accounts {
		homes = append(homes, account.Home)
	}
	return homes, nil
}

// standaloneEnrollmentMode reads enterprise.enrollment.mode from the
// protected config of the standalone layout that manifestPath belongs to.
// A manifest outside the layout, or a config that does not exist yet, is
// the default (auto) mode.
func standaloneEnrollmentMode(manifestPath string) (string, error) {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil || filepath.Clean(manifestPath) != layout.ManifestPath {
		return "", nil
	}
	if _, err := os.Lstat(layout.ConfigPath); errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err := managed.ValidateTrustedConfigPath(layout.ConfigPath); err != nil {
		return "", err
	}
	file, err := os.Open(layout.ConfigPath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, manifestLimit+1))
	if err != nil {
		return "", err
	}
	if len(data) > manifestLimit {
		return "", fmt.Errorf("managed config exceeds %d bytes", manifestLimit)
	}
	var doc struct {
		Enterprise struct {
			Enrollment struct {
				Mode string `yaml:"mode"`
			} `yaml:"enrollment"`
		} `yaml:"enterprise"`
	}
	if err := yaml.Unmarshal(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), &doc); err != nil {
		return "", fmt.Errorf("parse managed config: %w", err)
	}
	return doc.Enterprise.Enrollment.Mode, nil
}
