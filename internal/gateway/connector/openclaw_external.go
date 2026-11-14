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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// openClawPluginTreeTrusted checks that an administrator-installed plugin
// tree (connectors.openclaw.plugin_dir) and the folders above it cannot be
// changed by a standard account: plain files and folders owned by root
// (SYSTEM or Administrators on Windows), none group or other writable.
// Tests replace it.
var openClawPluginTreeTrusted = func(dir string) error {
	return managed.ValidateTrustedRuntimeCodeTree(dir, "OpenClaw plugin_dir")
}

// openClawExportHint names the command that writes the plugin of this build.
func openClawExportHint(dir string) string {
	return fmt.Sprintf("as an administrator run: defenseclaw-gateway connector openclaw export-plugin --dir %s", dir)
}

// verifyExternalOpenClawPlugin accepts an administrator-installed plugin
// only when it is protected and its files are exactly the plugin this
// gateway embeds: no file missing, added or changed. A partial or older
// plugin would load with gaps or not at all, and OpenClaw would then run
// unguarded.
func verifyExternalOpenClawPlugin(dir string, paths openClawPaths) error {
	dir = filepath.Clean(dir)
	if dir == filepath.Clean(paths.managedPluginDir()) {
		return fmt.Errorf("openclaw: connectors.openclaw.plugin_dir %s is the folder DefenseClaw manages; install the administrator copy outside the OpenClaw home", dir)
	}
	if !openClawExtensionAvailable() {
		return fmt.Errorf("openclaw extension is not bundled in this gateway build, so the plugin at %s cannot be checked", dir)
	}
	if err := openClawPluginTreeTrusted(dir); err != nil {
		return fmt.Errorf("openclaw: the administrator-installed plugin at %s is not protected (%v); %s", dir, err, openClawExportHint(dir))
	}
	if diff := openClawBundleDifference(dir); diff != "" {
		return fmt.Errorf("openclaw: the plugin at %s (version %s) is not the plugin of this DefenseClaw build (version %s): %s; %s",
			dir, openClawPluginVersionAt(dir), openClawEmbeddedPluginVersion(), diff, openClawExportHint(dir))
	}
	return nil
}

// openClawBundleDifference names the first way dir differs from the
// embedded plugin (a changed, added, missing or non-regular file), or "".
func openClawBundleDifference(dir string) string {
	want := map[string]bool{}
	if err := fs.WalkDir(openClawExtensionFS, openClawPluginRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && path.Base(p) != openClawPlaceholderName {
			rel := strings.TrimPrefix(p, openClawPluginRoot+"/")
			want[rel] = true
		}
		return nil
	}); err != nil || len(want) == 0 {
		return "this build embeds no plugin"
	}
	diff := ""
	seen := map[string]bool{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case !d.Type().IsRegular():
			diff = rel + " is not a regular file"
		case !want[rel]:
			diff = rel + " is not part of the plugin"
		default:
			embedded, _ := openClawExtensionFS.ReadFile(path.Join(openClawPluginRoot, rel))
			if have, err := os.ReadFile(p); err != nil || !bytes.Equal(have, embedded) {
				diff = rel + " differs"
			}
		}
		if diff != "" {
			return errNotBundledFile
		}
		seen[rel] = true
		return nil
	})
	if diff != "" {
		return diff
	}
	if err != nil {
		return err.Error()
	}
	for rel := range want {
		if !seen[rel] {
			return rel + " is missing"
		}
	}
	return ""
}

func openClawPluginVersionFrom(data []byte) string {
	var pkg struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &pkg) != nil || strings.TrimSpace(pkg.Version) == "" {
		return "unknown"
	}
	return strings.TrimSpace(pkg.Version)
}

func openClawPluginVersionAt(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return "unknown"
	}
	return openClawPluginVersionFrom(data)
}

func openClawEmbeddedPluginVersion() string {
	data, err := openClawExtensionFS.ReadFile(path.Join(openClawPluginRoot, "package.json"))
	if err != nil {
		return "unknown"
	}
	return openClawPluginVersionFrom(data)
}

// errOpenClawPreflight marks a preflight refusal: nothing was changed.
var errOpenClawPreflight = errors.New("openclaw preflight")

// openClawPreflight reports why Setup would not be able to change the
// OpenClaw files, before it changes any. Before 1.0.10 a root-owned plugin
// or an openclaw.json of another account made setup fail half way and roll
// back, and an upgrade left OpenClaw unguarded until someone noticed.
func openClawPreflight(paths openClawPaths, externalDir string) error {
	if externalDir != "" {
		if err := verifyExternalOpenClawPlugin(externalDir, paths); err != nil {
			return fmt.Errorf("%w: %v", errOpenClawPreflight, err)
		}
	} else if err := openClawTreeOwnedForWrite(paths.managedPluginDir()); err != nil {
		return fmt.Errorf("%w: %s belongs to another account (%v): it looks like an administrator-installed plugin; "+
			"set connectors.openclaw.plugin_install external and connectors.openclaw.plugin_dir to it, or remove it",
			errOpenClawPreflight, paths.managedPluginDir(), err)
	}
	for _, p := range []string{paths.home, paths.extensionsDir(), filepath.Dir(paths.config), paths.config} {
		if externalDir != "" && p == paths.extensionsDir() {
			continue
		}
		if err := openClawPathOwnedForWrite(p); err != nil {
			return fmt.Errorf("%w: DefenseClaw cannot change %s (%v); run the gateway as the account that owns the OpenClaw home, "+
				"or use the separate-user layout in the OpenClaw connector docs", errOpenClawPreflight, p, err)
		}
	}
	return nil
}

// OpenClawPreflight is openClawPreflight for opts (the CLI preflight
// command and the upgrade check).
func (c *OpenClawConnector) OpenClawPreflight(opts SetupOpts) error {
	// The same check setup runs first, separate-user layout included
	// (rel-1-0-10 GAP-0078: the command applied the owner checks of the
	// one-account layout to the OpenClaw account files).
	return c.checkAgentSettings(opts)
}

// ExportOpenClawPlugin writes the embedded plugin into dir, which must not
// exist or must be empty, for an administrator to protect and name in
// connectors.openclaw.plugin_dir.
func ExportOpenClawPlugin(dir string) error {
	if !openClawExtensionAvailable() {
		return fmt.Errorf("openclaw extension is not bundled in this gateway build")
	}
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || filepath.Base(dir) != "defenseclaw" {
		return fmt.Errorf("--dir must be an absolute path ending in a folder named defenseclaw")
	}
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s is not empty; remove it first", dir)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeEmbeddedTree(openClawExtensionFS, openClawPluginRoot, dir, 0o644, 0o755)
}

// openClawPathOwnedForWrite is the platform owner check
// (openclaw_owner_*.go); tests replace it.
var openClawPathOwnedForWrite = openClawPathOwnedForWriteOS

// openClawTreeOwnedForWrite applies openClawPathOwnedForWrite to dir and
// every entry beneath it, so a removal never stops half way on a file of
// another account. A missing dir passes.
func openClawTreeOwnedForWrite(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := openClawPathOwnedForWrite(p); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		return nil
	})
}

// checkAgentSettings is the check setup runs before it changes anything
// (defenseclaw-gateway connector check-agent-settings): the OpenClaw
// preflight, so an edited or unprotected administrator-installed plugin, or
// OpenClaw files of another account, stop the setup before config.yaml is
// saved and the gateway restarts (rel-1-0-10 GAP-0075). On Windows an
// OpenClaw known to be older than the native hooks is refused here too.
func (c *OpenClawConnector) checkAgentSettings(opts SetupOpts) error {
	if openClawHooksGOOS == "windows" && openClawLacksNativeHooks(openClawObservedVersion(opts)) {
		return fmt.Errorf("openclaw: on Windows DefenseClaw guards OpenClaw through its native plugin hooks, which need OpenClaw %s or later; upgrade OpenClaw (npm install -g openclaw@latest)", OpenClawNativeHooksSince)
	}
	paths := c.pathsFor(opts)
	if openClawSeparateUser(opts) {
		if paths.external == "" {
			return fmt.Errorf("%w: connectors.openclaw.plugin_account needs plugin_install: external", errOpenClawPreflight)
		}
		if err := verifyExternalOpenClawPlugin(paths.external, paths); err != nil {
			return fmt.Errorf("%w: %v", errOpenClawPreflight, err)
		}
		return nil
	}
	return openClawPreflight(paths, paths.external)
}
