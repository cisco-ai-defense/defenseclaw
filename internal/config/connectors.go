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

// ConnectorsConfig holds configuration for each agent framework connector.
type ConnectorsConfig struct {
	OpenClaw  OpenClawConnectorConfig  `mapstructure:"openclaw"  yaml:"openclaw"`
	ZeptoClaw ZeptoClawConnectorConfig `mapstructure:"zeptoclaw" yaml:"zeptoclaw"`
}

// OpenClawConnectorConfig configures the OpenClaw connector.
type OpenClawConnectorConfig struct {
	// Enabled controls whether the OpenClaw connector is active.
	// Default: true (backward compatible with existing deployments).
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// TokenEnv is the environment variable name for the gateway token.
	// Default: OPENCLAW_GATEWAY_TOKEN.
	TokenEnv string `mapstructure:"token_env" yaml:"token_env"`
}

// ZeptoClawConnectorConfig configures the ZeptoClaw connector.
type ZeptoClawConnectorConfig struct {
	// Enabled controls whether the ZeptoClaw connector is active.
	// Default: false (must be explicitly enabled via setup).
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// TokenEnv is the environment variable name for the proxy auth token.
	TokenEnv string `mapstructure:"token_env" yaml:"token_env"`
	// Providers maps provider name to upstream connection details.
	// Populated by `defenseclaw setup guardrail --claw zeptoclaw`.
	Providers map[string]ZCProviderConfig `mapstructure:"providers" yaml:"providers"`
}

// ZCProviderConfig describes a single upstream LLM provider for ZeptoClaw.
type ZCProviderConfig struct {
	UpstreamURL string `mapstructure:"upstream_url" yaml:"upstream_url"`
	AuthHeader  string `mapstructure:"auth_header"  yaml:"auth_header"`
	AuthScheme  string `mapstructure:"auth_scheme"  yaml:"auth_scheme"`
}

// DefaultConnectorsConfig returns the default connector configuration.
// OpenClaw is enabled by default for backward compatibility; ZeptoClaw
// is disabled until explicitly enabled.
func DefaultConnectorsConfig() ConnectorsConfig {
	return ConnectorsConfig{
		OpenClaw: OpenClawConnectorConfig{
			Enabled:  true,
			TokenEnv: "OPENCLAW_GATEWAY_TOKEN",
		},
		ZeptoClaw: ZeptoClawConnectorConfig{
			Enabled: false,
		},
	}
}
