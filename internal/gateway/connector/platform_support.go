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
	"fmt"
	"runtime"
)

// PlatformSupportStatus is the operator-facing availability state for a
// connector on an operating system.
type PlatformSupportStatus string

const (
	PlatformSupported    PlatformSupportStatus = "supported"
	PlatformPreview      PlatformSupportStatus = "preview"
	PlatformNotCertified PlatformSupportStatus = "not_certified"
	PlatformUnsupported  PlatformSupportStatus = "unsupported"
)

// PlatformSupport includes both the machine-readable state and the reason that
// setup/presentation surfaces show to the operator.
type PlatformSupport struct {
	Status PlatformSupportStatus
	Reason string
}

// proxyConnectors are the connectors built around DefenseClaw's local
// guardrail proxy and an in-agent plugin (OpenClaw, ZeptoClaw). Membership is
// a fixed fact about the connector (IsProxyConnector); whether its model
// traffic really goes through the proxy on this host follows the resolved
// hook mode (UsesGuardrailProxy): OpenClaw on native Windows runs only its
// native plugin hooks.
var proxyConnectors = map[string]struct{}{
	"openclaw":  {},
	"zeptoclaw": {},
}

// windowsConnectorSupport is the Go source of truth for native Windows
// connector availability. Keep it in exact parity with the Python
// cli/defenseclaw/platform_support.py WINDOWS_CONNECTOR_SUPPORT mapping.
var windowsConnectorSupport = map[string]PlatformSupport{
	"codex": {
		Status: PlatformSupported,
		Reason: "Codex CLI and the DefenseClaw hook entrypoint are supported on native Windows x64.",
	},
	"kiro": {
		Status: PlatformSupported,
		Reason: "Kiro IDE and Kiro CLI share hooks; ACP stdio mediation is supported on native Windows x64 when kiro-cli is present.",
	},
	"claudecode": {
		Status: PlatformSupported,
		Reason: "Claude Code and the DefenseClaw native executable hook entrypoint are supported on native Windows x64.",
	},
	"cursor": {
		Status: PlatformSupported,
		Reason: "Cursor Agent and the DefenseClaw PowerShell hook adapter are supported on native Windows x64.",
	},
	"devin": {
		Status: PlatformSupported,
		Reason: "Native Devin CLI lifecycle hooks are supported on Windows x64 using the pinned 3000.4.25 CLI; cloud Devin, proxy, native OTLP, and managed higher-layer enforcement are not covered.",
	},
	"copilot": {
		Status: PlatformSupported,
		Reason: "The DefenseClaw GitHub Copilot CLI integration is supported on native Windows x64.",
	},
	"antigravity": {
		Status: PlatformSupported,
		Reason: "The Antigravity integration is supported on native Windows x64.",
	},
	"opencode": {
		Status: PlatformSupported,
		Reason: "OpenCode V2 and the DefenseClaw plugin are supported on native Windows x64 using the reviewed @opencode/cli contract.",
	},
	"amp": {
		Status: PlatformSupported,
		Reason: "Amp and the DefenseClaw system policy plugin are supported on native Windows x64.",
	},
	"hermes": {
		Status: PlatformSupported,
		Reason: "Hermes native shell hooks use a direct DefenseClaw executable on native Windows x64; restart any open Hermes session after setup so it loads them.",
	},
	"openclaw": {
		Status: PlatformSupported,
		Reason: "OpenClaw 2026.8.35 or later is supported on native Windows x64 through its native plugin hooks (no guardrail proxy, no model response scan); managed Windows is not in this release.",
	},
	"zeptoclaw": {
		Status: PlatformUnsupported,
		Reason: "ZeptoClaw publishes macOS/Linux builds and its DefenseClaw integration requires the guardrail proxy.",
	},
}

// IsProxyConnector reports whether name is one of the proxy/plugin
// connectors (OpenClaw, ZeptoClaw) as opposed to a hook-based connector. It
// does not change with the host: the managed hook installers and automatic
// application protection never take these connectors. For whether the
// connector's model traffic goes through the guardrail proxy on this host
// (proxy binding, token selection, traffic mode) use UsesGuardrailProxy.
func IsProxyConnector(name string) bool {
	_, ok := proxyConnectors[name]
	return ok
}

// UsesGuardrailProxy reports whether name routes model traffic through
// DefenseClaw's guardrail proxy on this host. It follows the resolved
// OpenClaw hook mode (DESIGN-REVIEW-1 P2-12): proxy and hybrid use the proxy
// (Linux, macOS), native does not (Windows, where DefenseClaw hosts no
// proxy). Linux and macOS answer exactly as IsProxyConnector.
func UsesGuardrailProxy(name string) bool {
	return UsesGuardrailProxyOnOS(name, openClawHooksGOOS)
}

// UsesGuardrailProxyOnOS is UsesGuardrailProxy for goos.
func UsesGuardrailProxyOnOS(name, goos string) bool {
	if !IsProxyConnector(name) {
		return false
	}
	if name == "openclaw" {
		return OpenClawHookModeUsesProxy(resolveOpenClawHookModeOn(goos, "", ""))
	}
	return true
}

// ConnectorSupportOnOS returns a supported/preview/not-certified/unsupported
// classification with a human-readable reason. Unknown plugin connectors fail
// closed on Windows pending separate certification.
func ConnectorSupportOnOS(name, goos string) PlatformSupport {
	if goos == "windows" {
		if support, ok := windowsConnectorSupport[name]; ok {
			return support
		}
		return PlatformSupport{
			Status: PlatformNotCertified,
			Reason: "This connector has not completed native Windows x64 certification.",
		}
	}
	if name == "opencode" {
		if goos == "linux" || goos == "darwin" {
			return PlatformSupport{Status: PlatformSupported, Reason: "OpenCode V2 and the DefenseClaw plugin are supported on Linux and macOS using the reviewed @opencode/cli contract."}
		}
		return PlatformSupport{Status: PlatformPreview, Reason: "OpenCode V2 has not completed certification on this operating system."}
	}
	return PlatformSupport{
		Status: PlatformSupported,
		Reason: fmt.Sprintf("Connector setup is supported on %s.", goos),
	}
}

// connectorSupportedOnOS reports whether setup/presentation may offer name on
// goos. Preview connectors are deliberately available.
func connectorSupportedOnOS(name, goos string) bool {
	status := ConnectorSupportOnOS(name, goos).Status
	return connectorStatusAvailable(status)
}

func connectorStatusAvailable(status PlatformSupportStatus) bool {
	return status == PlatformSupported || status == PlatformPreview
}

// ConnectorSupportOnHostOS returns the full classification for the host OS.
func ConnectorSupportOnHostOS(name string) PlatformSupport {
	return ConnectorSupportOnOS(name, runtime.GOOS)
}

// ConnectorSupportedOnHostOS reports availability on the current host OS.
func ConnectorSupportedOnHostOS(name string) bool {
	status := ConnectorSupportOnHostOS(name).Status
	return connectorStatusAvailable(status)
}

// CheckPlatformSupport returns the shared operator-facing preview warning or
// unsupported error for a connector on goos. Supported connectors return two
// empty values so callers can preserve their existing control flow.
func CheckPlatformSupport(name, goos string) (string, error) {
	support := ConnectorSupportOnOS(name, goos)
	switch support.Status {
	case PlatformUnsupported:
		return "", fmt.Errorf("connector %q is not supported on %s: %s", name, goos, support.Reason)
	case PlatformNotCertified:
		return "", fmt.Errorf("connector %q is not certified on %s: %s", name, goos, support.Reason)
	case PlatformPreview:
		return fmt.Sprintf("connector %s is preview on %s: %s", name, goos, support.Reason), nil
	default:
		return "", nil
	}
}

// CheckPlatformSupportOnHost applies CheckPlatformSupport to runtime.GOOS.
func CheckPlatformSupportOnHost(name string) (string, error) {
	return CheckPlatformSupport(name, runtime.GOOS)
}

// validateConnectorSupportedOnOS returns the clear setup error used by direct
// connector lifecycle calls. It is injectable by OS for focused tests.
func validateConnectorSupportedOnOS(name, goos string) error {
	_, err := CheckPlatformSupport(name, goos)
	return err
}

func errConnectorUnsupportedOnOS(name, goos string) error {
	return validateConnectorSupportedOnOS(name, goos)
}
