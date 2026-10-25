// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// hookDataDirsNow are the data directories a gateway started with this
// process's environment renders its per-user hooks into, and every folder
// whose hooks load that config as their own and can open an outage there,
// one per line for install.sh to hold, the first one the hooks' own folder,
// then the account's own .defenseclaw, which every per-user hook checks.
// The data directory is the folder whose
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
// A relative data_dir is taken from the config's folder (configDataDir),
// as hook-outage-mode takes it. The answer is "" when the data directory is
// still not an absolute path: the hooks of such a runtime never let an
// outage through (hookOutageFailModeNow compares an absolute folder).
//
// A config kept apart from the installer's home (DEFENSECLAW_CONFIG) whose
// data_dir is that home, set or by default, is also the config of hooks in
// its own folder: loaded there without DEFENSECLAW_CONFIG, as a hook loads
// it, the runtime takes the config's folder as its data directory
// (loadConfigSourceChecked), so hook-outage-mode can open an outage there.
// install.sh already holds its home (LOCK_DIR), so the answer is then the
// config's folder, when that folder's config.yaml is the config, by file identity, with a hooks folder
// beside it whose hooks take that folder as their data directory, by the
// rule they use (loadHookRuntimeConfig).
//
// A relative DEFENSECLAW_CONFIG or DEFENSECLAW_HOME names a folder from
// install.sh's working directory, the one this command runs in. Both are
// made absolute first (absoluteInstallerEnv): a relative spelling named no
// folder ("") and install.sh then held only its home, while hooks beside
// the config load it by its absolute path and could open an outage.
func hookDataDirsNow() ([]string, error) {
	restore, err := absoluteInstallerEnv()
	if err != nil {
		return nil, err
	}
	defer restore()
	configFile := filepath.Clean(config.ConfigPath())
	dir, err := hookDataDirOfConfig(configFile)
	if err != nil {
		return nil, err
	}
	var dirs []string
	add := func(candidate string) {
		candidate = absoluteOrEmpty(candidate)
		if candidate == "" {
			return
		}
		for _, held := range dirs {
			if pathidentity.Same(held, candidate) {
				return
			}
		}
		dirs = append(dirs, candidate)
	}
	if dir == "" {
		return nil, nil
	}
	// Hooks read only <data dir>/config.yaml (hookOutageFailModeNow), with
	// the same rule (loadHookRuntimeConfig). That file is the configured
	// one whenever it is the same file, by any name: the configured file
	// itself, a config.yaml link to it, or the folder a linked configured
	// file resolves to (GAP review loop 2: DEFENSECLAW_CONFIG=policy.yaml
	// with config.yaml a link to it left that folder unlocked).
	for _, folder := range hookConfigFolders(configFile) {
		if pathidentity.Same(folder, dir) {
			continue
		}
		if info, statErr := os.Stat(filepath.Join(folder, "hooks")); statErr != nil || !info.IsDir() {
			continue
		}
		alias := filepath.Join(folder, config.DefaultConfigName)
		if !sameExistingFile(alias, configFile) {
			continue
		}
		if _, own, loadErr := loadHookRuntimeConfig(alias); loadErr == nil && pathidentity.Same(own, folder) {
			add(folder)
		}
	}
	add(dir)
	// Every per-user hook of this account also looks for an install in the
	// account's own .defenseclaw (hookOutageInstallHeld), whatever folder
	// and name it loads its config by. Holding it closes the outage of a
	// hook whose config.yaml is the configured file under a name no path
	// from that file leads to (a hard link, or a link in another folder).
	// It is named even when it is not there yet (a custom DEFENSECLAW_HOME):
	// install.sh makes it for the install, so the lock is there to find.
	if home := outageAccountHome(); home != "" {
		add(filepath.Join(home, config.DefaultDataDirName))
	}
	return dirs, nil
}

// hookConfigFolders are the folders whose hooks may load configFile as
// their config.yaml: the folder of every name on its way to the file (the
// configured name, each link it passes through, the file itself), told
// apart by file identity, so a folder reached by a link, a bind mount or
// another spelling counts once.
func hookConfigFolders(configFile string) []string {
	var folders []string
	add := func(folder string) {
		for _, seen := range folders {
			if pathidentity.Same(seen, folder) {
				return
			}
		}
		folders = append(folders, folder)
	}
	name := configFile
	for hop := 0; hop < 40; hop++ {
		add(filepath.Dir(name))
		target, err := os.Readlink(name)
		if err != nil {
			break
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(name), target)
		}
		name = filepath.Clean(target)
	}
	if real, err := filepath.EvalSymlinks(configFile); err == nil {
		if real, err = filepath.Abs(real); err == nil {
			add(filepath.Dir(real))
		}
	}
	return folders
}

// sameExistingFile reports whether a and b both exist and are the same file
// once links are followed.
func sameExistingFile(a, b string) bool {
	left, err := os.Stat(a)
	if err != nil {
		return false
	}
	right, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(left, right)
}

// loadHookRuntimeConfig loads configFile as the hook runtime of its folder
// does, and names the data directory it gives that runtime: the one rule
// hook-outage-mode (whether a hook may open an outage) and hook-data-dir
// (which folder install.sh locks) share. The load leaves out
// DEFENSECLAW_CONFIG, which a hook inherits from the agent and install.sh
// from its caller: naming this file, it would move a default data_dir to
// DEFENSECLAW_HOME (loadConfigSourceChecked). The data directory is the
// config's data_dir, a relative one taken from the config's folder, or that
// folder; "" for a config path that is not absolute.
func loadHookRuntimeConfig(configFile string) (*config.Config, string, error) {
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
	return loaded, configDataDir(configFile, loaded.DataDir), nil
}

// configDataDir is the absolute data directory a data_dir value of the
// config at configFile names: an absolute value as it is, a relative one
// from the config's folder; "" without an absolute config path or a value.
func configDataDir(configFile, dataDir string) string {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" || !filepath.IsAbs(configFile) {
		return ""
	}
	if !filepath.IsAbs(dataDir) {
		dataDir = filepath.Join(filepath.Dir(configFile), dataDir)
	}
	return filepath.Clean(dataDir)
}

func hookDataDirOfConfig(configFile string) (string, error) {
	if _, err := os.Lstat(configFile); errors.Is(err, fs.ErrNotExist) {
		return absoluteOrEmpty(config.DefaultDataPath()), nil
	} else if err != nil {
		return "", fmt.Errorf("read %s: %w", configFile, err)
	}
	if loaded, err := config.LoadFromFile(configFile); err == nil && loaded != nil {
		return absoluteOrEmpty(configDataDir(configFile, loaded.DataDir)), nil
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
	return absoluteOrEmpty(configDataDir(configFile, dir)), nil
}

// absoluteInstallerEnv binds a relative DEFENSECLAW_CONFIG and
// DEFENSECLAW_HOME to this process's working directory, as install.sh's own
// paths are, so the loader and the hook folder below see the absolute
// folders, and returns the function that puts the values back.
func absoluteInstallerEnv() (func(), error) {
	var undo []func()
	restore := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
	for _, name := range []string{managed.ConfigPathEnv, "DEFENSECLAW_HOME"} {
		value := os.Getenv(name)
		if value == "" || filepath.IsAbs(value) {
			continue
		}
		absolute, err := filepath.Abs(value)
		if err == nil {
			err = os.Setenv(name, absolute)
		}
		if err != nil {
			restore()
			return nil, fmt.Errorf("resolve %s %q: %w", name, value, err)
		}
		undo = append(undo, func() { _ = os.Setenv(name, value) })
	}
	return restore, nil
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
			dirs, err := hookDataDirsNow()
			if err != nil {
				return err
			}
			if len(dirs) == 0 {
				dirs = []string{""}
			}
			for _, dir := range dirs {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), dir); err != nil {
					return err
				}
			}
			return nil
		},
	}
	rootCmd.AddCommand(cmd)
}
