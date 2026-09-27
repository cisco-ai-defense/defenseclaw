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
	"fmt"
	"path"
	"reflect"
)

// In-image OpenCode system policy. OpenCode reads the managed config
// directory (/etc/opencode on Linux) after every user, project and
// OPENCODE_CONFIG_CONTENT layer, and merges plugin lists across layers, so a
// plugin registered there cannot be removed by user or project config and
// runs last (its view of tool arguments is authoritative).
const (
	OpenCodeSandboxManagedConfigPath = "/etc/opencode/opencode.json"
	// OpenCodeSandboxPluginPath is the root-owned bridge plugin.
	OpenCodeSandboxPluginPath = SandboxLibDir + "/opencode/defenseclaw.js"
)

// openCodeSandboxStartupEnv must be real process environment (OpenShell does
// not propagate image ENV): the update check runs before config is read.
var openCodeSandboxStartupEnv = map[string]string{
	"OPENCODE_DISABLE_AUTOUPDATE": "1",
}

// renderOpenCodeSandboxArtifacts renders the OpenCode overlay: the sandbox
// bridge plugin (root-owned) and the managed config that registers it and
// pins the update check and session sharing off.
func renderOpenCodeSandboxArtifacts(rt resolvedSandboxTarget) (SandboxArtifacts, error) {
	plugin, err := renderSandboxPlugin("opencode-plugin.js", rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	managed, err := renderOpenCodeSandboxManagedConfig()
	if err != nil {
		return SandboxArtifacts{}, err
	}
	if err := verifyOpenCodeSandboxManagedConfig(managed); err != nil {
		return SandboxArtifacts{}, err
	}
	env := make(map[string]string, len(openCodeSandboxStartupEnv))
	for key, value := range openCodeSandboxStartupEnv {
		env[key] = value
	}
	return finalizeSandboxArtifacts(SandboxArtifacts{
		Connector:    "opencode",
		HookContract: rt.contract.ContractID,
		TamperTier:   SandboxTamperTierManaged,
		Files: []SandboxFile{
			{Path: OpenCodeSandboxPluginPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: plugin},
			{Path: OpenCodeSandboxManagedConfigPath, Mode: 0o644, Owner: SandboxOwnerRoot, Data: managed},
		},
		Env:      env,
		Binaries: []SandboxBinary{harnessBinary("opencode")},
	})
}

// openCodeSandboxPluginURL is how the managed config names the plugin.
func openCodeSandboxPluginURL() string {
	return "file://" + path.Clean(OpenCodeSandboxPluginPath)
}

func renderOpenCodeSandboxManagedConfig() ([]byte, error) {
	body, err := json.MarshalIndent(map[string]interface{}{
		"$schema":    "https://opencode.ai/config.json",
		"plugin":     []string{openCodeSandboxPluginURL()},
		"autoupdate": false,
		"share":      "disabled",
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal OpenCode sandbox managed config: %w", err)
	}
	return append(body, '\n'), nil
}

// verifyOpenCodeSandboxManagedConfig reads the managed config back and checks
// the keys the image depends on.
func verifyOpenCodeSandboxManagedConfig(body []byte) error {
	var cfg struct {
		Plugin     []string `json:"plugin"`
		Autoupdate *bool    `json:"autoupdate"`
		Share      string   `json:"share"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return fmt.Errorf("verify OpenCode sandbox managed config: %w", err)
	}
	if !reflect.DeepEqual(cfg.Plugin, []string{openCodeSandboxPluginURL()}) {
		return fmt.Errorf("verify OpenCode sandbox managed config: plugin = %v", cfg.Plugin)
	}
	if cfg.Autoupdate == nil || *cfg.Autoupdate {
		return fmt.Errorf("verify OpenCode sandbox managed config: autoupdate is not pinned off")
	}
	if cfg.Share != "disabled" {
		return fmt.Errorf("verify OpenCode sandbox managed config: share = %q", cfg.Share)
	}
	return nil
}
