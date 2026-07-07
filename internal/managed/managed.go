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
	"os"
	"path/filepath"
	"strings"
)

const (
	DeploymentModeManagedEnterprise = "managed_enterprise"
	ConfigPathEnv                   = "DEFENSECLAW_CONFIG"
	DeploymentModeEnv               = "DEFENSECLAW_DEPLOYMENT_MODE"
	HookGuardianAuthorizationDirEnv = "DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR"
	HookGuardianAuthorizationFile   = "protected_targets.json"
	CMIDLibPathEnv                  = "DEFENSECLAW_CMID_LIB_PATH"
)

func IsManagedEnterprise(mode string) bool {
	return strings.EqualFold(strings.TrimSpace(mode), DeploymentModeManagedEnterprise)
}

func HookGuardianAuthorizationDir(dataDir string) string {
	if configured := strings.TrimSpace(os.Getenv(HookGuardianAuthorizationDirEnv)); configured != "" {
		return filepath.Clean(configured)
	}
	return filepath.Clean(strings.TrimSpace(dataDir)) + "-hook-guardian"
}

func HookGuardianAuthorizationPath(dataDir string) string {
	return filepath.Join(HookGuardianAuthorizationDir(dataDir), HookGuardianAuthorizationFile)
}
