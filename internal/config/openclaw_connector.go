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

package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// OpenClawConnectorMinProductVersion is the first release that reads
// connectors.openclaw; a signed bundle that sets it must require it.
const OpenClawConnectorMinProductVersion = "1.0.10"

// OpenClaw plugin install modes (connectors.openclaw.plugin_install).
const (
	// OpenClawPluginManaged: DefenseClaw writes its plugin into
	// <claw.home_dir>/extensions/defenseclaw on every setup (the default).
	OpenClawPluginManaged = "managed"
	// OpenClawPluginExternal: an administrator installed the plugin at
	// plugin_dir; DefenseClaw checks that its files equal the bundle of this
	// build and never writes or deletes them.
	OpenClawPluginExternal = "external"
)

// OpenClawConnectorConfig is connectors.openclaw. Every key is optional; an
// absent block keeps the 1.0.9 behaviour (managed plugin, operator.admin
// requested, OpenClaw and DefenseClaw as one OS account).
type OpenClawConnectorConfig struct {
	PluginInstall string `mapstructure:"plugin_install" yaml:"plugin_install,omitempty"`
	PluginDir     string `mapstructure:"plugin_dir"     yaml:"plugin_dir,omitempty"`
	// OperatorAdmin requests the operator.admin scope from OpenClaw, used
	// only to turn off a skill, plugin or MCP server through OpenClaw config.
	// nil means true. false keeps read, write and approvals; blocks are still
	// enforced by DefenseClaw admission and inspection.
	OperatorAdmin *bool `mapstructure:"operator_admin" yaml:"operator_admin,omitempty"`
	// PluginAccount names the OS account the OpenClaw gateway runs as when it
	// is not the sidecar account (separate-user layout): the listener proof
	// answers it and the sidecar accepts its OpenClaw listener.
	PluginAccount string `mapstructure:"plugin_account" yaml:"plugin_account,omitempty"`
	// PluginTokenFile is where the sidecar publishes the plugin credential for
	// the plugin account; PluginTokenGroup (Linux, macOS) may read it.
	PluginTokenFile  string `mapstructure:"plugin_token_file"  yaml:"plugin_token_file,omitempty"`
	PluginTokenGroup string `mapstructure:"plugin_token_group" yaml:"plugin_token_group,omitempty"`
}

// OpenClawPluginInstall is the resolved plugin_install mode.
func (c *Config) OpenClawPluginInstall() string {
	if c == nil {
		return OpenClawPluginManaged
	}
	switch strings.ToLower(strings.TrimSpace(c.Connectors.OpenClaw.PluginInstall)) {
	case "", OpenClawPluginManaged:
		return OpenClawPluginManaged
	default:
		return OpenClawPluginExternal
	}
}

// OpenClawExternalPluginDir is plugin_dir when plugin_install is external,
// else "".
func (c *Config) OpenClawExternalPluginDir() string {
	if c.OpenClawPluginInstall() != OpenClawPluginExternal {
		return ""
	}
	return filepath.Clean(strings.TrimSpace(c.Connectors.OpenClaw.PluginDir))
}

// OpenClawOperatorAdmin reports whether the OpenClaw client requests
// operator.admin.
func (c *Config) OpenClawOperatorAdmin() bool {
	if c == nil || c.Connectors.OpenClaw.OperatorAdmin == nil {
		return true
	}
	return *c.Connectors.OpenClaw.OperatorAdmin
}

var openClawAccountPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.\\-]{0,63}$`)

// ValidateOpenClawConnector checks connectors.openclaw.
func (c *Config) ValidateOpenClawConnector() error {
	if c == nil {
		return nil
	}
	oc := c.Connectors.OpenClaw
	mode := strings.ToLower(strings.TrimSpace(oc.PluginInstall))
	switch mode {
	case "", OpenClawPluginManaged, OpenClawPluginExternal:
	default:
		return fmt.Errorf("config: connectors.openclaw.plugin_install %q must be managed or external", oc.PluginInstall)
	}
	dir := strings.TrimSpace(oc.PluginDir)
	if mode == OpenClawPluginExternal {
		if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
			return fmt.Errorf("config: connectors.openclaw.plugin_dir must be a clean absolute path when plugin_install is external")
		}
		// OpenClaw names a plugin folder after the plugin id, and teardown
		// and drift checks find DefenseClaw load paths by that name.
		if filepath.Base(dir) != "defenseclaw" {
			return fmt.Errorf("config: connectors.openclaw.plugin_dir must end in a folder named defenseclaw (the plugin id), for example /opt/defenseclaw/openclaw/defenseclaw")
		}
	} else if dir != "" {
		return fmt.Errorf("config: connectors.openclaw.plugin_dir is used only with plugin_install: external")
	}
	if a := strings.TrimSpace(oc.PluginAccount); a != "" && !openClawAccountPattern.MatchString(a) {
		return fmt.Errorf("config: connectors.openclaw.plugin_account %q is not an account name", oc.PluginAccount)
	}
	tokenFile := strings.TrimSpace(oc.PluginTokenFile)
	if tokenFile != "" && (!filepath.IsAbs(tokenFile) || filepath.Clean(tokenFile) != tokenFile) {
		return fmt.Errorf("config: connectors.openclaw.plugin_token_file must be a clean absolute path")
	}
	if (tokenFile != "" || strings.TrimSpace(oc.PluginTokenGroup) != "") && strings.TrimSpace(oc.PluginAccount) == "" {
		return fmt.Errorf("config: connectors.openclaw.plugin_token_file and plugin_token_group need plugin_account (separate-user layout)")
	}
	if g := strings.TrimSpace(oc.PluginTokenGroup); g != "" && !openClawAccountPattern.MatchString(g) {
		return fmt.Errorf("config: connectors.openclaw.plugin_token_group %q is not a group name", oc.PluginTokenGroup)
	}
	if c.SecureClientIntegration() && oc != (OpenClawConnectorConfig{}) {
		return fmt.Errorf("config: connectors.openclaw is not supported with the Secure Client integration")
	}
	return nil
}

// UsesMinProductVersion110Keys reports the 1.0.10 keys cfg sets, which a
// signed bundle may carry only with min_product_version 1.0.10 or later.
func (c *Config) UsesMinProductVersion110Keys() []string {
	if c == nil || c.Connectors.OpenClaw == (OpenClawConnectorConfig{}) {
		return nil
	}
	return []string{"connectors.openclaw"}
}
