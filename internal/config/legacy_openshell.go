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

import "strings"

// The legacy openshell-sandbox (0.0.x) standalone integration is gone, but a
// host that still runs it has a config that says openshell.mode=standalone and
// points guardrail.host at the host side of the sandbox veth link (10.200.0.1).
// Until `defenseclaw sandbox legacy-cleanup` resets that config, the gateway
// API must keep binding where the sandboxed OpenClaw and every health probe
// (upgrade, watchdog, status, the Python CLI) expect it; otherwise an upgrade
// health check dials an address nothing listens on and rolls back. These
// helpers are the single Go owner of that decision, mirrored by
// legacy_standalone_api_host in cli/defenseclaw/config.py.

// IsLegacyStandalone reports whether cfg still describes a legacy
// openshell-sandbox standalone install.
//
// LEGACY(openshell-0.0.x): delete one release after cleanup.
func IsLegacyStandalone(cfg *Config) bool {
	return cfg != nil && cfg.OpenShell.IsStandalone()
}

// LegacyStandaloneAPIHost returns the API bind host a legacy standalone
// install uses (guardrail.host, the host end of the sandbox veth link) and
// true, or "" and false when the shim does not apply. An explicit
// gateway.api_bind still takes precedence at every call site.
//
// LEGACY(openshell-0.0.x): delete one release after cleanup.
func LegacyStandaloneAPIHost(cfg *Config) (string, bool) {
	if !IsLegacyStandalone(cfg) {
		return "", false
	}
	host := strings.TrimSpace(cfg.Guardrail.Host)
	if host == "" || host == "localhost" {
		return "", false
	}
	return host, true
}

// LegacyStandalonePlainGatewayWS reports whether the OpenClaw gateway
// connection stays on plain WS because a legacy standalone install reaches the
// sandboxed OpenClaw over its point-to-point veth link. gateway.tls still
// forces TLS on.
//
// LEGACY(openshell-0.0.x): delete one release after cleanup.
func LegacyStandalonePlainGatewayWS(cfg *Config) bool {
	return IsLegacyStandalone(cfg) && !cfg.Gateway.TLS
}

// LegacySandboxHome returns the sandbox user's home directory recorded by a
// legacy standalone install, or "" when the shim does not apply. The gateway
// client reads the sandboxed OpenClaw's openclaw.json and device pairing from
// there until cleanup.
//
// LEGACY(openshell-0.0.x): delete one release after cleanup.
func LegacySandboxHome(cfg *Config) string {
	if !IsLegacyStandalone(cfg) {
		return ""
	}
	return cfg.OpenShell.EffectiveSandboxHome()
}
