// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"strings"
)

// DefenseClaw home and config pins a managed service environment carries
// next to the deployment mode.
const (
	managedHomeEnv   = "DEFENSECLAW_HOME"
	managedConfigEnv = "DEFENSECLAW_CONFIG"
)

// StandaloneManagedTreeAccount reports the gateway service account a new
// object at path is created for, and whether it is created at all in the
// managed protection: this process is pinned to a managed deployment of the
// standalone profile with the gateway service account named, and path lies in
// the pinned runtime directory (DEFENSECLAW_HOME) or beside the pinned config
// (DEFENSECLAW_CONFIG). The Secure Client profile, a per-user install, an
// unpinned process and a path in someone else's folder (a user profile, the
// repository) all report false, so their objects keep the protection the
// caller gives them.
func StandaloneManagedTreeAccount(path string) (string, bool) {
	account := strings.TrimSpace(os.Getenv(WindowsServiceAccountEnv))
	if account == "" || !IsManagedEnterprise(os.Getenv(DeploymentModeEnv)) ||
		!IsStandaloneProfile(os.Getenv(EnterpriseProfileEnv)) || strings.TrimSpace(path) == "" {
		return "", false
	}
	roots := []string{os.Getenv(managedHomeEnv)}
	if config := strings.TrimSpace(os.Getenv(managedConfigEnv)); config != "" {
		roots = append(roots, filepath.Dir(config))
	}
	for _, root := range roots {
		if strings.TrimSpace(root) != "" && pathWithinRoot(root, path) {
			return account, true
		}
	}
	return "", false
}

// pathWithinRoot reports whether path is root or below it, by lexical
// comparison (case-insensitive where the platform is).
func pathWithinRoot(root, path string) bool {
	if !filepath.IsAbs(root) || !filepath.IsAbs(path) {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
