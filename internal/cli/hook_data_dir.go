// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// hookDataDirNow is the data directory a gateway started with this process's
// environment renders its per-user hooks into, the folder whose
// .install.lock those hooks look for (hookOutageInstallHeld): the data_dir of
// the config the gateway loads (config.ConfigPath, so DEFENSECLAW_CONFIG, or
// config.yaml in DEFENSECLAW_HOME or ~/.defenseclaw), as the runtime loader
// reads it, or the loader's default folder. The loader takes every YAML form
// of the key (a quoted key, a flow mapping, a value on the next line), which
// a line reader in install.sh did not.
//
// A config this release cannot load (an older release's, before migrate)
// is read as plain YAML for its data_dir, which can only name one more folder
// to hold. A config that is not YAML at all, or a data_dir that is not a
// string, is an error: install.sh then stops before it stops the gateway.
// The answer is "" when the data directory is not an absolute path: the
// hooks of such a runtime never let an outage through (hookOutageFailModeNow
// compares an absolute folder).
//
// A config kept apart from the installer's home (DEFENSECLAW_CONFIG) whose
// data_dir is that home, set or by default, is also the config of hooks in
// its own folder: loaded there without DEFENSECLAW_CONFIG, as a hook loads
// it, the runtime takes the config's folder as its data directory
// (loadConfigSourceChecked), so hook-outage-mode can open an outage there.
// install.sh already holds its home (LOCK_DIR), so the answer is then the
// config's folder, when the config is a config.yaml with a hooks folder
// beside it.
func hookDataDirNow() (string, error) {
	configFile := filepath.Clean(config.ConfigPath())
	dir, err := hookDataDirOfConfig(configFile)
	if err != nil || dir == "" {
		return dir, err
	}
	folder := filepath.Dir(configFile)
	// Hooks read only <data dir>/config.yaml (hookOutageFailModeNow).
	if filepath.Base(configFile) == config.DefaultConfigName &&
		pathidentity.Same(dir, config.DefaultDataPath()) && !pathidentity.Same(folder, dir) {
		if info, statErr := os.Stat(filepath.Join(folder, "hooks")); statErr == nil && info.IsDir() {
			return absoluteOrEmpty(folder), nil
		}
	}
	return dir, nil
}

func hookDataDirOfConfig(configFile string) (string, error) {
	if _, err := os.Lstat(configFile); errors.Is(err, fs.ErrNotExist) {
		return absoluteOrEmpty(config.DefaultDataPath()), nil
	} else if err != nil {
		return "", fmt.Errorf("read %s: %w", configFile, err)
	}
	if loaded, err := config.LoadFromFile(configFile); err == nil && loaded != nil {
		return absoluteOrEmpty(loaded.DataDir), nil
	}
	raw, err := os.ReadFile(configFile)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", configFile, err)
	}
	var source map[string]any
	if err := yaml.Unmarshal(raw, &source); err != nil {
		return "", fmt.Errorf("%s is not YAML the gateway can read: %w", configFile, err)
	}
	value, present := source["data_dir"]
	if !present || value == nil {
		return absoluteOrEmpty(config.DefaultDataPath()), nil
	}
	dir, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("data_dir in %s is not a string", configFile)
	}
	if dir == "" {
		return absoluteOrEmpty(config.DefaultDataPath()), nil
	}
	return absoluteOrEmpty(dir), nil
}

func absoluteOrEmpty(dir string) string {
	if !filepath.IsAbs(dir) {
		return ""
	}
	return filepath.Clean(dir)
}

func init() {
	cmd := &cobra.Command{
		Use:    "hook-data-dir",
		Short:  "Print the data directory the gateway renders this account's per-user hooks into (run by install.sh)",
		Hidden: true,
		// The installer runs it before it stops the gateway: no daemon
		// bootstrap, no audit store, only a read of the config.
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		Args:        cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := hookDataDirNow()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), dir)
			return err
		},
	}
	rootCmd.AddCommand(cmd)
}
