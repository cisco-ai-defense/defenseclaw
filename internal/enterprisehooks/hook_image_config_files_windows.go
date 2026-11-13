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

package enterprisehooks

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// WindowsManagedHookConfigFiles lists, for every enabled target of the
// guardian's manifest, the agent config files its connector's hooks live in
// (connector.HookPolicyWatchPathsForConnector, the set the guardian watches),
// resolved for that account's home. GAP-0751 prune and retire read them for
// references to a launch folder. A target whose home no longer exists is
// skipped (its configs went with it); any other problem is returned, which
// makes the caller's scan incomplete.
func WindowsManagedHookConfigFiles(manifestPath string) ([]string, []string) {
	manifest, err := LoadManifest(manifestPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: %v", manifestPath, err)}
	}
	registry := newWindowsEnterpriseConnectorRegistry()
	var files, problems []string
	for _, target := range manifest.Targets {
		if target.Enabled != nil && !*target.Enabled {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(target.Connector))
		home := strings.TrimSpace(target.UserHome)
		if name == "" || home == "" {
			continue
		}
		if _, err := os.Lstat(home); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		conn, ok := registry.Get(name)
		if !ok {
			continue
		}
		dataDir, err := resolveWindowsEnterpriseDataDir(home, target.DataDir)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s (%s): %v", home, name, err))
			continue
		}
		setup := connector.SetupOpts{DataDir: dataDir, ManagedEnterprise: true}
		if err := connector.WithUserHomeDir(home, func() error {
			files = append(files, connector.HookPolicyWatchPathsForConnector(conn, setup)...)
			return nil
		}); err != nil {
			problems = append(problems, fmt.Sprintf("%s (%s): %v", home, name, err))
		}
	}
	return files, problems
}
