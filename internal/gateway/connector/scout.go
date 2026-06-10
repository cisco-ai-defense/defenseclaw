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
	"context"
	"fmt"
	"net/http"
)

// ScoutConnector supports Microsoft's documented Scout local surfaces.
//
// Scout is powered by OpenClaw, but the public Scout preview docs expose
// skills and admin entitlement controls rather than a hook config file
// DefenseClaw can patch. Keep setup inert until Microsoft publishes a
// blocking hook contract.
type ScoutConnector struct {
	gatewayToken string
	masterKey    string
}

func NewScoutConnector() *ScoutConnector { return &ScoutConnector{} }

func (c *ScoutConnector) Name() string { return "scout" }

func (c *ScoutConnector) Description() string {
	return "Microsoft Scout local skill discovery and opt-in CodeGuard skill support"
}

func (c *ScoutConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeNone }
func (c *ScoutConnector) SubprocessPolicy() SubprocessPolicy     { return SubprocessNone }

func (c *ScoutConnector) Setup(ctx context.Context, opts SetupOpts) error {
	_ = ctx
	_ = opts
	return fmt.Errorf("scout has no documented hook or proxy enforcement surface yet; DefenseClaw supports Scout local skill discovery and opt-in CodeGuard skill installation only")
}

func (c *ScoutConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	_ = ctx
	_ = opts
	return nil
}

func (c *ScoutConnector) VerifyClean(opts SetupOpts) error {
	_ = opts
	return nil
}

func (c *ScoutConnector) Authenticate(r *http.Request) bool {
	_ = r
	return false
}

func (c *ScoutConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	_ = r
	_ = body
	return nil, fmt.Errorf("scout does not route model traffic through DefenseClaw")
}

func (c *ScoutConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken = gatewayToken
	c.masterKey = masterKey
}

func (c *ScoutConnector) Capabilities(opts SetupOpts) ConnectorCapabilities {
	skillPaths := scoutSkillPaths(opts)
	return ConnectorCapabilities{
		Hooks: HookCapability{
			CanBlock:           false,
			CanAskNative:       false,
			SupportsFailClosed: false,
			Scope:              "none",
		},
		MCP: unsupportedSurface("Scout uses MCP-backed tools internally, but Microsoft has not published a local MCP server install config path for Scout."),
		Skills: SurfaceCapability{
			Supported:      true,
			Scope:          "user",
			ReadPaths:      skillPaths,
			WritePaths:     []string{homePath(".copilot", "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
			Notes: []string{
				"Scout custom skills are documented as SKILL.md directories under ~/.copilot/skills; ~/.copilot/m-skills is discovered for Microsoft-managed workspace skills.",
			},
		},
		Rules:   unsupportedSurface("Scout does not publish a separate local rules install surface."),
		Plugins: unsupportedSurface("Scout does not publish a local plugin install surface."),
		Agents:  unsupportedSurface("Scout sub-agent assets are managed inside Scout; no local agent asset path is documented."),
		CodeGuard: CodeGuardCapability{
			Supported:      true,
			InstallTargets: []string{"skill"},
			OptInOnly:      true,
			AutoInstall:    false,
			Idempotent:     true,
			ConflictSafe:   true,
			Notes: []string{
				"Project CodeGuard can be installed as an explicit Scout skill asset; runtime blocking is still unavailable until Scout exposes hooks.",
			},
		},
		Telemetry: TelemetryCapability{
			Notes: []string{"Scout does not publish a hook or native OTLP export surface for DefenseClaw runtime telemetry."},
		},
	}
}

func (c *ScoutConnector) AgentPaths(opts SetupOpts) AgentPaths {
	_ = opts
	return AgentPaths{}
}

func (c *ScoutConnector) HookScripts(opts SetupOpts) []string {
	_ = opts
	return nil
}

func (c *ScoutConnector) RequiredEnv() []EnvRequirement {
	return []EnvRequirement{{
		Scope:       EnvScopeNone,
		Description: "No environment variables are required by DefenseClaw; Scout access is controlled by Microsoft 365 Frontier/Intune entitlement and Scout sign-in.",
	}}
}

func (c *ScoutConnector) SupportsComponentScanning() bool { return true }

func (c *ScoutConnector) ComponentTargets(cwd string) map[string][]string {
	_ = cwd
	return map[string][]string{
		"skill": scoutSkillPaths(SetupOpts{}),
	}
}

func scoutSkillPaths(opts SetupOpts) []string {
	_ = opts
	return uniqueNonEmptyStrings([]string{
		homePath(".copilot", "skills"),
		homePath(".copilot", "m-skills"),
	})
}
