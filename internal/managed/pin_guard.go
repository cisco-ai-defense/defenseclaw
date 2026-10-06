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
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// declaresManagedConfig matches a config.yaml that itself says
// deployment_mode: managed_enterprise.
var declaresManagedConfig = regexp.MustCompile(`(?m)^deployment_mode:\s*["']?managed_enterprise`)

// IgnoreUnmanagedPins drops the machine-wide pins (DEFENSECLAW_DEPLOYMENT_MODE
// and DEFENSECLAW_ENTERPRISE_PROFILE) from this process's environment when it
// loads a per-user config: a managed service always loads a machine-owned
// config, never one under a user's home directory, so a pin seen here is a
// stray export that must not turn an unmanaged host into a managed one (the
// CLI refusing to write, the gateway refusing to start) or break it with an
// invalid mode. A per-user config that itself declares managed_enterprise
// keeps its pins. It returns the names it dropped, never the values.
func IgnoreUnmanagedPins(configPath, homeDir string) []string {
	var set []string
	for _, name := range []string{DeploymentModeEnv, EnterpriseProfileEnv} {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			set = append(set, name)
		}
	}
	if len(set) == 0 || !underDirectory(configPath, homeDir) || declaresManaged(configPath) {
		return nil
	}
	for _, name := range set {
		_ = os.Unsetenv(name)
	}
	return set
}

func underDirectory(path, dir string) bool {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(dir) == "" {
		return false
	}
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	if runtime.GOOS == "windows" {
		// Windows paths are not case-sensitive.
		path, dir = strings.ToLower(path), strings.ToLower(dir)
	}
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func declaresManaged(configPath string) bool {
	file, err := os.Open(configPath) // #nosec G304 -- the config path this process loads.
	if err != nil {
		return false
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 1<<20))
	return err == nil && declaresManagedConfig.Match(raw)
}
