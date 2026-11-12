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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// The separate-user layout (connectors.openclaw.plugin_account): the
// OpenClaw gateway runs as its own OS account and owns openclaw.json; the
// DefenseClaw gateway runs as another. DefenseClaw then never writes
// openclaw.json. An administrator adds the DefenseClaw entry once (setup
// prints it) and installs the plugin (plugin_install: external). Setup
// publishes the plugin credential to plugin_token_file for the plugin
// account and checks the entry read-only.

// openClawSeparateUser reports the separate-user layout for opts.
func openClawSeparateUser(opts SetupOpts) bool {
	return strings.TrimSpace(opts.OpenClawPluginAccount) != ""
}

// openClawSeparateUserEntry is the plugin connection config the plugin needs
// when it cannot read the DefenseClaw data folder.
func openClawSeparateUserEntry(opts SetupOpts) map[string]interface{} {
	host, apiPort := splitOpenClawAddr(opts.APIAddr, 18970)
	_, proxyPort := splitOpenClawAddr(opts.ProxyAddr, 4000)
	return map[string]interface{}{
		"tokenFile":     strings.TrimSpace(opts.OpenClawPluginTokenFile),
		"sidecarHost":   host,
		"sidecarPort":   apiPort,
		"guardrailPort": proxyPort,
	}
}

func splitOpenClawAddr(addr string, defaultPort int) (string, int) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || host == "" {
		return "127.0.0.1", defaultPort
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 {
		return host, defaultPort
	}
	return host, n
}

// openClawSeparateUserBlock is the openclaw.json block the administrator
// merges in, as indented JSON.
func openClawSeparateUserBlock(opts SetupOpts, paths openClawPaths) string {
	entry := map[string]interface{}{"enabled": true, "config": openClawSeparateUserEntry(opts)}
	block := map[string]interface{}{"plugins": map[string]interface{}{
		"allow":   []string{"defenseclaw"},
		"load":    map[string]interface{}{"paths": []string{paths.external}},
		"entries": map[string]interface{}{"defenseclaw": entry},
	}}
	if opts.HILTEnabled {
		block["approvals"] = map[string]interface{}{"plugin": map[string]interface{}{"enabled": true, "mode": "session"}}
	}
	out, _ := json.MarshalIndent(block, "", "  ")
	return string(out)
}

// openClawSeparateUserMissing names what openclaw.json lacks of the block.
func openClawSeparateUserMissing(cfg map[string]interface{}, opts SetupOpts, paths openClawPaths) []string {
	var missing []string
	plugins, _ := cfg["plugins"].(map[string]interface{})
	allow, _ := plugins["allow"].([]interface{})
	if !containsJSONString(allow, "defenseclaw") {
		missing = append(missing, "plugins.allow defenseclaw")
	}
	load, _ := plugins["load"].(map[string]interface{})
	loadPaths, _ := load["paths"].([]interface{})
	if !containsJSONString(loadPaths, paths.external) {
		missing = append(missing, "plugins.load.paths "+paths.external)
	}
	entries, _ := plugins["entries"].(map[string]interface{})
	entry, _ := entries["defenseclaw"].(map[string]interface{})
	if entry["enabled"] != true {
		missing = append(missing, "plugins.entries.defenseclaw.enabled true")
	}
	have, _ := entry["config"].(map[string]interface{})
	for key, want := range openClawSeparateUserEntry(opts) {
		if fmt.Sprint(have[key]) != fmt.Sprint(want) {
			missing = append(missing, fmt.Sprintf("plugins.entries.defenseclaw.config.%s %v", key, want))
		}
	}
	if opts.HILTEnabled {
		approvals, _ := cfg["approvals"].(map[string]interface{})
		plugin, _ := approvals["plugin"].(map[string]interface{})
		if plugin["enabled"] != true {
			missing = append(missing, "approvals.plugin.enabled true")
		}
	}
	return missing
}

func containsJSONString(list []interface{}, want string) bool {
	for _, v := range list {
		if s, _ := v.(string); s == want {
			return true
		}
	}
	return false
}

// registerSeparateUser is Setup in the separate-user layout. It changes
// only the plugin token file.
func (c *OpenClawConnector) registerSeparateUser(opts SetupOpts, paths openClawPaths) error {
	if paths.external == "" {
		return fmt.Errorf("%w: connectors.openclaw.plugin_account needs plugin_install: external", errOpenClawPreflight)
	}
	if err := verifyExternalOpenClawPlugin(paths.external, paths); err != nil {
		return fmt.Errorf("%w: %v", errOpenClawPreflight, err)
	}
	token := strings.TrimSpace(opts.HookAPIToken)
	if !opts.HookAPITokenScoped || token == "" {
		return fmt.Errorf("openclaw: the separate-user layout needs the connector-scoped plugin credential, which could not be issued in %s; run defenseclaw doctor", opts.DataDir)
	}
	if err := publishOpenClawPluginToken(strings.TrimSpace(opts.OpenClawPluginTokenFile),
		strings.TrimSpace(opts.OpenClawPluginTokenGroup), token); err != nil {
		return fmt.Errorf("openclaw: publish the plugin credential to %s: %w", opts.OpenClawPluginTokenFile, err)
	}
	data, err := readConnectorStateFile(paths.config)
	if err != nil {
		return fmt.Errorf("openclaw: read %s (the DefenseClaw account needs read access in the separate-user layout): %w", paths.config, err)
	}
	cfg, err := parseOpenClawConfig(paths.config, data)
	if err != nil {
		return err
	}
	if missing := openClawSeparateUserMissing(cfg, opts, paths); len(missing) > 0 {
		return fmt.Errorf("openclaw: %s (owned by %s) does not register DefenseClaw yet (missing: %s). DefenseClaw does not write it in the separate-user layout; "+
			"as %s or an administrator merge this into it, then restart the OpenClaw gateway:\n%s",
			paths.config, opts.OpenClawPluginAccount, strings.Join(missing, ", "), opts.OpenClawPluginAccount, openClawSeparateUserBlock(opts, paths))
	}
	return nil
}

// teardownSeparateUser removes the published plugin credential and says
// which openclaw.json entries the administrator removes.
func (c *OpenClawConnector) teardownSeparateUser(opts SetupOpts, paths openClawPaths) error {
	tokenFile := strings.TrimSpace(opts.OpenClawPluginTokenFile)
	if tokenFile != "" {
		if err := os.Remove(tokenFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove the plugin credential %s: %w", tokenFile, err)
		}
	}
	fmt.Fprintf(openClawTeardownNoticeOutput, "[connector] openclaw: removed the plugin credential; DefenseClaw does not write %s in the separate-user layout, "+
		"so remove plugins.entries.defenseclaw, defenseclaw from plugins.allow and %s from plugins.load.paths there yourself\n", paths.config, paths.external)
	return nil
}
