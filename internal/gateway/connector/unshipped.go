// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// maxPluginManifestBytes bounds how much of a plugin.yaml NotShipped reads.
const maxPluginManifestBytes = 64 << 10

// unshippedFileNameRE limits the connector names whose DefenseClaw-owned files
// RemoveUnshippedConnectorFiles derives: lowercase, no dots or separators, so
// a name read from the lock or roster can never address anything outside the
// hooks directory.
var unshippedFileNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// NotShipped reports whether name is a connector this build cannot provide:
// Get does not resolve it, plugin discovery (when a plugin directory was
// configured) finished without error, and no plugin directory declares that
// name. A plugin that is present but failed to load, or a plugin directory
// that could not be scanned, keeps the name "possibly shipped" so callers
// retain its state and retry its teardown once the plugin is fixed.
func (r *Registry) NotShipped(name string) bool {
	name = strings.TrimSpace(name)
	if r == nil || name == "" {
		return false
	}
	if _, ok := r.Get(name); ok {
		return false
	}
	r.mu.RLock()
	dir, discoveryErr := r.pluginDir, r.pluginDiscoveryErr
	r.mu.RUnlock()
	if discoveryErr != nil {
		return false
	}
	declared, err := pluginDirDeclares(dir, name)
	return err == nil && !declared
}

// pluginDirDeclares reports whether any plugin subdirectory of dir is named
// name or carries a plugin.yaml whose name is name (compared without case).
func pluginDirDeclares(dir, name string) (bool, error) {
	if strings.TrimSpace(dir) == "" {
		return false, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if strings.EqualFold(entry.Name(), name) {
			return true, nil
		}
		manifestName, ok := readPluginManifestName(filepath.Join(dir, entry.Name(), "plugin.yaml"))
		if ok && strings.EqualFold(strings.TrimSpace(manifestName), name) {
			return true, nil
		}
	}
	return false, nil
}

func readPluginManifestName(path string) (string, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxPluginManifestBytes))
	if err != nil {
		return "", false
	}
	var manifest pluginManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return "", false
	}
	return manifest.Name, true
}

// RemoveUnshippedConnectorFiles removes the files DefenseClaw itself wrote in
// dataDir/hooks for a connector this build no longer ships: its hook scripts
// (<name>-hook.sh, <name>-hook.ps1) and its OTLP path token
// (.otlp-<name>.token). An agent whose config still points at a removed
// script then fails to start the hook (a non-blocking error for most agents)
// instead of running a fail-closed script against a gateway route that no
// longer exists. Agent config files are never touched.
//
// It does nothing unless NotShipped(name) holds, the name is a plain
// lowercase identifier, and no registered connector or shared helper claims
// the file. A missing file is not an error.
func (r *Registry) RemoveUnshippedConnectorFiles(dataDir, name string) ([]string, error) {
	name = strings.TrimSpace(name)
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" || !unshippedFileNameRE.MatchString(name) || !r.NotShipped(name) {
		return nil, nil
	}
	claimed := r.claimedHookFileStems()
	hooks := filepath.Join(filepath.Clean(dataDir), "hooks")
	var candidates []string
	if _, taken := claimed[name+"-hook"]; !taken {
		candidates = append(candidates, name+"-hook.sh", name+"-hook.ps1")
	}
	if _, scoped := OTLPPathTokenScopeForConnector(name); !scoped {
		candidates = append(candidates, otlpPathTokenFileName(OTLPPathTokenScope(name)))
	}
	var removed []string
	var errs []error
	for _, base := range candidates {
		path := filepath.Join(hooks, base)
		info, err := os.Lstat(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			errs = append(errs, fmt.Errorf("%s is not a regular file; left in place", path))
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, path)
	}
	return removed, errors.Join(errs...)
}

// claimedHookFileStems returns the extension-free names of every hook file a
// shipped connector or shared helper may own.
func (r *Registry) claimedHookFileStems() map[string]struct{} {
	stems := make(map[string]struct{})
	add := func(file string) {
		base := filepath.Base(strings.TrimSpace(file))
		if base == "" || base == "." {
			return
		}
		stems[strings.ToLower(strings.TrimSuffix(base, filepath.Ext(base)))] = struct{}{}
	}
	for _, script := range hookScripts {
		add(script)
	}
	for _, script := range hookHelperScripts {
		add(script)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, group := range []map[string]Connector{r.builtins, r.plugins} {
		for name, conn := range group {
			stems[strings.ToLower(name)+"-hook"] = struct{}{}
			if named, ok := conn.(interface{ HookScriptNames(SetupOpts) []string }); ok {
				for _, script := range named.HookScriptNames(SetupOpts{}) {
					add(script)
				}
			}
		}
	}
	return stems
}
