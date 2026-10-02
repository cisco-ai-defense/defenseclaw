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

// AmpSandboxPluginPath is the sandbox bridge plugin. Amp loads plugins only
// from the user's ~/.config/amp/plugins and a project's .amp/plugins (it has
// no system plugin location, and /etc/ampcode/managed-settings.json cannot
// register one), so the plugin lives in the image HOME and the connector's
// tamper tier is user: the agent can edit or delete it, and the hook-silence
// detector plus OpenShell egress are the backstop. Amp ignores
// AMP_DISABLE_PLUGINS outside its development builds.
const AmpSandboxPluginPath = SandboxHomeDir + "/.config/amp/plugins/defenseclaw.ts"

// ampSandboxStartupEnv must be real process environment (OpenShell does not
// propagate image ENV).
var ampSandboxStartupEnv = map[string]string{
	"AMP_SKIP_UPDATE_CHECK": "1",
}

func init() {
	registerHookOnlySandboxRenderer("amp", renderAmpSandboxArtifacts)
}

// renderAmpSandboxArtifacts renders the Amp overlay: the sandbox bridge
// plugin, owned by the sandbox user.
func renderAmpSandboxArtifacts(c *hookOnlyConnector, rt resolvedSandboxTarget) (SandboxArtifacts, error) {
	plugin, err := renderSandboxPlugin("amp-plugin.ts", rt)
	if err != nil {
		return SandboxArtifacts{}, err
	}
	env := make(map[string]string, len(ampSandboxStartupEnv))
	for key, value := range ampSandboxStartupEnv {
		env[key] = value
	}
	return SandboxArtifacts{
		Connector:    "amp",
		HookContract: rt.contract.ContractID,
		TamperTier:   SandboxTamperTierUser,
		Files:        []SandboxFile{{Path: AmpSandboxPluginPath, Mode: 0o600, Owner: SandboxOwnerUser, Data: plugin}},
		Env:          env,
		Binaries:     []SandboxBinary{harnessBinary("amp")},
	}, nil
}
