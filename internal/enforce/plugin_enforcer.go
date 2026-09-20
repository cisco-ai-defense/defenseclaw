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

package enforce

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

type PluginEnforcer struct {
	quarantineDir string
	shell         *sandbox.OpenShell
}

func NewPluginEnforcer(quarantineDir string, shell *sandbox.OpenShell) *PluginEnforcer {
	return &PluginEnforcer{quarantineDir: quarantineDir, shell: shell}
}

func (e *PluginEnforcer) Quarantine(pluginPath string) (string, error) {
	// Refuse bundled-skill containers and descendants before any stat
	// touches the source tree — a vendor-supplied .system container
	// must never be moved to the quarantine store even in the
	// crash-recovery reconciler. The check is on the caller-supplied
	// path (not a resolved one) because plugin_enforcer operates on
	// paths the caller has already validated; the sibling
	// AssetQuarantinePlan path does its own containment check and
	// re-verifies here as defence in depth.
	if IsBundledSkillPath(pluginPath) {
		return "", ErrBundledSkill
	}
	info, err := os.Stat(pluginPath)
	if err != nil {
		return "", fmt.Errorf("enforce: plugin path %q: %w", pluginPath, err)
	}

	name := filepath.Base(pluginPath)
	dest := filepath.Join(e.quarantineDir, "plugins", name)

	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return "", fmt.Errorf("enforce: create quarantine dir: %w", err)
	}

	if info.IsDir() {
		if err := copyDir(pluginPath, dest); err != nil {
			return "", fmt.Errorf("enforce: copy plugin to quarantine: %w", err)
		}
		if err := os.RemoveAll(pluginPath); err != nil {
			return dest, fmt.Errorf("enforce: remove original plugin: %w", err)
		}
	} else {
		if err := copyFile(pluginPath, dest); err != nil {
			return "", fmt.Errorf("enforce: copy plugin to quarantine: %w", err)
		}
		if err := os.Remove(pluginPath); err != nil {
			return dest, fmt.Errorf("enforce: remove original plugin: %w", err)
		}
	}

	return dest, nil
}

func (e *PluginEnforcer) Restore(pluginName, originalPath string) error {
	base := filepath.Base(pluginName)
	src := filepath.Join(e.quarantineDir, "plugins", base)
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("enforce: quarantined plugin %q not found: %w", base, err)
	}

	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("enforce: stat quarantined plugin: %w", err)
	}

	if info.IsDir() {
		if err := copyDir(src, originalPath); err != nil {
			return fmt.Errorf("enforce: restore plugin: %w", err)
		}
		return os.RemoveAll(src)
	}

	if err := copyFile(src, originalPath); err != nil {
		return fmt.Errorf("enforce: restore plugin: %w", err)
	}
	return os.Remove(src)
}

func (e *PluginEnforcer) IsQuarantined(pluginName string) bool {
	base := filepath.Base(pluginName)
	path := filepath.Join(e.quarantineDir, "plugins", base)
	_, err := os.Stat(path)
	return err == nil
}
