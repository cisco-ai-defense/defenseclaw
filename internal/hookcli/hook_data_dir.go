// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookcli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// loadHookRuntimeConfig loads configFile as the hook runtime of its folder
// does, and names the data directory it gives that runtime: the one rule
// hook-outage-mode (whether a hook may open an outage) and hook-data-dir
// (which folder install.sh locks) share. The load leaves out
// DEFENSECLAW_CONFIG, which a hook inherits from the agent and install.sh
// from its caller: naming this file, it would move a default data_dir to
// DEFENSECLAW_HOME (loadConfigSourceChecked). The data directory is the
// config's data_dir, a relative one taken from the config's folder, or that
// folder; "" for a config path that is not absolute.
func LoadHookRuntimeConfig(configFile string) (*config.Config, string, error) {
	if !filepath.IsAbs(configFile) {
		return nil, "", fmt.Errorf("config path %q is not absolute", configFile)
	}
	value, present := os.LookupEnv(managed.ConfigPathEnv)
	if present {
		if err := os.Unsetenv(managed.ConfigPathEnv); err != nil {
			return nil, "", err
		}
		defer func() { _ = os.Setenv(managed.ConfigPathEnv, value) }()
	}
	loaded, err := config.LoadFromFile(configFile)
	if err != nil || loaded == nil {
		return nil, "", fmt.Errorf("load %s: %w", configFile, err)
	}
	return loaded, ConfigDataDir(configFile, loaded.DataDir), nil
}

// configDataDir is the absolute data directory a data_dir value of the
// config at configFile names: an absolute value as it is, a relative one
// from the config's folder; "" without an absolute config path or a value.
func ConfigDataDir(configFile, dataDir string) string {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" || !filepath.IsAbs(configFile) {
		return ""
	}
	if !filepath.IsAbs(dataDir) {
		dataDir = filepath.Join(filepath.Dir(configFile), dataDir)
	}
	return filepath.Clean(dataDir)
}
