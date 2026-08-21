// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
)

// ResolveRelativeGatewayDeviceKeyFile resolves a portable relative device-key
// spelling beneath an explicit absolute data directory. The boolean is false
// for absolute paths and for relative spellings that could be interpreted as
// rooted, drive-relative, volume-relative, ADS-backed, or outside dataDir.
func ResolveRelativeGatewayDeviceKeyFile(keyFile, dataDir string) (string, bool) {
	if keyFile == "" || !filepath.IsAbs(dataDir) || filepath.IsAbs(keyFile) ||
		filepath.VolumeName(keyFile) != "" || strings.Contains(keyFile, ":") ||
		strings.HasPrefix(keyFile, "/") || strings.HasPrefix(keyFile, `\`) {
		return "", false
	}

	root, err := filepath.Abs(filepath.Clean(dataDir))
	if err != nil {
		return "", false
	}
	target := filepath.Clean(filepath.Join(root, keyFile))
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.IsAbs(relative) {
		return "", false
	}
	return target, true
}

func normalizeRelativeGatewayDeviceKeyFile(candidate *Config) {
	if candidate == nil || filepath.IsAbs(candidate.Gateway.DeviceKeyFile) {
		return
	}
	if resolved, ok := ResolveRelativeGatewayDeviceKeyFile(
		candidate.Gateway.DeviceKeyFile,
		candidate.DataDir,
	); ok {
		candidate.Gateway.DeviceKeyFile = resolved
	}
}
