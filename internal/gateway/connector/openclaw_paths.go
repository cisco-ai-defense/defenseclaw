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
	"path/filepath"
	"strings"
	"sync"
)

// openClawPaths is where the connector finds OpenClaw: the OpenClaw home
// (claw.home_dir in config.yaml) and the openclaw.json it patches
// (claw.config_file, else <home>/openclaw.json). Before 1.0.10 the connector
// always used ~/.openclaw of the process account and ignored claw.home_dir,
// so a sidecar configured for another OpenClaw home patched the wrong file.
type openClawPaths struct {
	home   string
	config string
	// external is connectors.openclaw.plugin_dir when plugin_install is
	// external, else "".
	external string
}

// openClawPathsIn is the layout of one OpenClaw home with its default
// openclaw.json.
func openClawPathsIn(home string) openClawPaths {
	home = filepath.Clean(home)
	return openClawPaths{home: home, config: filepath.Join(home, "openclaw.json")}
}

func (p openClawPaths) extensionsDir() string { return filepath.Join(p.home, "extensions") }

func (p openClawPaths) managedPluginDir() string {
	return filepath.Join(p.home, "extensions", "defenseclaw")
}

// pluginDir is the folder OpenClaw loads the DefenseClaw plugin from.
func (p openClawPaths) pluginDir() string {
	if p.external != "" {
		return p.external
	}
	return p.managedPluginDir()
}

// defaultOpenClawPaths is the layout used when config.yaml names none:
// ~/.openclaw of the process account.
func defaultOpenClawPaths() openClawPaths {
	return openClawPathsIn(filepath.Join(userHomeDir(), ".openclaw"))
}

// resolveOpenClawPaths turns the SetupOpts values into a layout. An empty
// home is the default home; an empty config file is <home>/openclaw.json.
// OpenClawHomeOverride (tests) wins over both.
func resolveOpenClawPaths(home, config, external string) openClawPaths {
	if external = strings.TrimSpace(external); external != "" {
		external = filepath.Clean(external)
	}
	if OpenClawHomeOverride != "" {
		p := openClawPathsIn(OpenClawHomeOverride)
		p.external = external
		return p
	}
	home, config = strings.TrimSpace(home), strings.TrimSpace(config)
	p := defaultOpenClawPaths()
	if home != "" {
		p = openClawPathsIn(home)
	}
	if config != "" {
		p.config = filepath.Clean(config)
	}
	p.external = external
	return p
}

// openClawPathState remembers the layout the last Setup, Teardown or
// SetOpenClawPaths call named, for the methods that get no SetupOpts
// (BundledPluginDir, IsBundledPlugin, ComponentTargets).
type openClawPathState struct {
	mu    sync.RWMutex
	paths openClawPaths
	set   bool
}

// pathsFor resolves the layout of opts. SetupOpts that name no OpenClaw home
// or config file (callers outside the sidecar) use the remembered layout, so
// they act on the same files as the last Setup; named paths are remembered.
func (c *OpenClawConnector) pathsFor(opts SetupOpts) openClawPaths {
	if strings.TrimSpace(opts.OpenClawHome) == "" && strings.TrimSpace(opts.OpenClawConfigPath) == "" &&
		strings.TrimSpace(opts.OpenClawPluginDir) == "" {
		return c.currentPaths()
	}
	p := resolveOpenClawPaths(opts.OpenClawHome, opts.OpenClawConfigPath, opts.OpenClawPluginDir)
	c.state.mu.Lock()
	c.state.paths, c.state.set = p, true
	c.state.mu.Unlock()
	return p
}

// currentPaths is the remembered layout, else the default one.
func (c *OpenClawConnector) currentPaths() openClawPaths {
	c.state.mu.RLock()
	p, set := c.state.paths, c.state.set
	c.state.mu.RUnlock()
	if set {
		return p
	}
	return resolveOpenClawPaths("", "", "")
}

// SetOpenClawPaths records the OpenClaw home, openclaw.json and external
// plugin folder named by config.yaml (claw.home_dir, claw.config_file,
// connectors.openclaw.plugin_dir). The sidecar calls it before it wires the
// plugin watcher.
func (c *OpenClawConnector) SetOpenClawPaths(home, config, external string) {
	p := resolveOpenClawPaths(home, config, external)
	c.state.mu.Lock()
	c.state.paths, c.state.set = p, true
	c.state.mu.Unlock()
}
