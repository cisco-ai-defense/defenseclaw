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
	"strings"
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

// proxyConnectors are the chat/LLM-proxy connectors that interpose on model
// traffic through DefenseClaw's local guardrail proxy. Topology and platform
// support are deliberately separate facts: OpenClaw itself has a native
// Windows path, but DefenseClaw does not host its proxy lifecycle on Windows.
var proxyConnectors = map[string]struct{}{
	"openclaw":  {},
	"zeptoclaw": {},
}

// deprecatedConnectorSupport keeps retired built-ins resolvable only for
// teardown and migration. Setup and presentation surfaces must not offer them
// on any operating system.
var deprecatedConnectorSupport = map[string]PlatformSupport{
	"geminicli": {
		Status: PlatformUnsupported,
		Reason: "Gemini CLI integration is deprecated; use the Antigravity connector. Existing managed Gemini CLI state remains removable through teardown and uninstall.",
	},
	"windsurf": {
		Status: PlatformUnsupported,
		Reason: "Windsurf/Cascade is retired; use Devin. Existing authenticated Windsurf state remains recognizable only for upgrade and uninstall cleanup.",
	},
}

// windowsConnectorSupport is the Go source of truth for native Windows
// connector availability. Keep it in exact parity with the Python
// cli/defenseclaw/platform_support.py WINDOWS_CONNECTOR_SUPPORT mapping.
var windowsConnectorSupport = map[string]PlatformSupport{
	"codex": {
		Status: PlatformSupported,
		Reason: "Codex CLI and the DefenseClaw hook entrypoint are supported on native Windows x64; authentic packaged plus official-client validation metadata is not recorded and live evidence remains false.",
	},
	"claudecode": {
		Status: PlatformSupported,
		Reason: "Claude Code and the DefenseClaw native executable hook entrypoint are supported on native Windows x64; immutable packaged plus official-client validation metadata is not recorded and live evidence remains false.",
	},
	"cursor": {
		Status: PlatformSupported,
		Reason: "Cursor Agent and the DefenseClaw PowerShell hook adapter are available on native Windows x64; official-client validation metadata is not recorded and live evidence remains false.",
	},
	"devin": {
		Status: PlatformSupported,
		Reason: "Native Devin CLI lifecycle hooks are supported on Windows x64 using the pinned 3000.4.25 CLI; cloud Devin, proxy, ACP, native OTLP, and managed higher-layer enforcement are not covered.",
	},
	"geminicli": {
		Status: PlatformUnsupported,
		Reason: "Gemini CLI integration is deprecated; use the Antigravity connector. Existing managed Gemini CLI state remains removable through teardown and uninstall.",
	},
	"copilot": {
		Status: PlatformSupported,
		Reason: "The DefenseClaw GitHub Copilot CLI integration is supported on native Windows x64; authentication, HITL, and official-client live evidence remain unverified and unclaimed.",
	},
	"antigravity": {
		Status: PlatformSupported,
		Reason: "The Antigravity integration is supported on native Windows x64; authentication, HITL, and official-client live evidence remain unverified and unclaimed.",
	},
	"opencode": {
		Status: PlatformSupported,
		Reason: "OpenCode native Windows setup is supported; official-client validation metadata is not recorded and live evidence remains false. OpenCode recommends WSL but does not require it.",
	},
	"amp": {
		Status: PlatformSupported,
		Reason: "Amp and the DefenseClaw system policy plugin are supported on native Windows x64.",
	},
	"hermes": {
		Status: PlatformSupported,
		Reason: "Hermes native shell hooks use a direct DefenseClaw executable; packaged and official-client Windows x64 validation metadata is not recorded, running-client state remains pending reload, and live evidence remains false.",
	},
	"openhands": {
		Status: PlatformUnsupported,
		Reason: "OpenHands CLI requires WSL; DefenseClaw does not implement a WSL connector path.",
	},
	"omnigent": {
		Status: PlatformSupported,
		Reason: "OmniGent 0.7.0 is supported on native Windows in degraded mode; DefenseClaw uses its awaited in-process policy API without terminal wrapping or filesystem/network sandbox parity.",
	},
	"openclaw": {
		Status: PlatformUnsupported,
		Reason: "DefenseClaw on Windows is hook-only; OpenClaw integration requires the guardrail proxy.",
	},
	"zeptoclaw": {
		Status: PlatformUnsupported,
		Reason: "ZeptoClaw publishes macOS/Linux builds and its DefenseClaw integration requires the guardrail proxy.",
	},
}

// darwinConnectorSupport records explicit implemented-but-not-yet-certified
// native macOS states. Connectors absent from this map retain the established
// supported behavior; deprecated names are rejected before this lookup.
var darwinConnectorSupport = map[string]PlatformSupport{
	"codex": {
		Status: PlatformPreview,
		Reason: "Codex CLI and DefenseClaw's native macOS arm64 hook, OTLP, notify, signed-executable, and exact-restore paths are implemented; durable packaged and authenticated official-client certification evidence is not recorded.",
	},
	"claudecode": {
		Status: PlatformPreview,
		Reason: "Claude Code and DefenseClaw's signed native Mach-O hook path are implemented on macOS arm64; durable packaged and authenticated official-client certification evidence is not recorded.",
	},
	"cursor": {
		Status: PlatformPreview,
		Reason: "Cursor Agent and Cursor Desktop hook integrations are implemented on macOS arm64, with distinct CLI and Desktop release streams; durable packaged and authenticated official-client certification evidence is not recorded.",
	},
	"devin": {
		Status: PlatformPreview,
		Reason: "Native Devin CLI lifecycle hooks are implemented on macOS arm64 using the pinned 3000.4.25 contract; durable authenticated official-client evidence is not recorded, and cloud Devin, ACP, proxy, plugins, and native OTLP remain unclaimed.",
	},
	"hermes": {
		Status: PlatformPreview,
		Reason: "Hermes Agent's >=0.19.0,<0.21.0 shell-hook contract and DefenseClaw's POSIX hook entrypoint are implemented on macOS arm64; durable packaged and official-client certification evidence is not recorded.",
	},
	"openhands": {
		Status: PlatformPreview,
		Reason: "OpenHands CLI and DefenseClaw's protected native macOS arm64 hook and trace-only OTLP launch paths are implemented; durable packaged and authenticated official-client certification evidence is not recorded.",
	},
	"antigravity": {
		Status: PlatformPreview,
		Reason: "Antigravity's >=1.1.8 hook contract and native macOS arm64 integration are implemented; 1.1.10 is availability metadata only and durable authenticated official-client certification evidence is not recorded.",
	},
}

// IsProxyConnector reports whether name is a proxy/chat connector (as opposed
// to a hook-based connector).
func IsProxyConnector(name string) bool {
	_, ok := proxyConnectors[name]
	return ok
}

// ConnectorSupportOnOS returns a supported/preview/not-certified/unsupported
// classification with a human-readable reason. Unknown plugin connectors fail
// closed on Windows pending separate certification.
func ConnectorSupportOnOS(name, goos string) PlatformSupport {
	if support, ok := deprecatedConnectorSupport[name]; ok {
		return support
	}
	goos = strings.ToLower(strings.TrimSpace(goos))
	if goos == "macos" {
		goos = "darwin"
	}
	if goos == "windows" {
		if support, ok := windowsConnectorSupport[name]; ok {
			return support
		}
		return PlatformSupport{
			Status: PlatformNotCertified,
			Reason: "This connector has not completed native Windows x64 certification.",
		}
	}
	if goos == "darwin" {
		if support, ok := darwinConnectorSupport[name]; ok {
			return support
		}
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
