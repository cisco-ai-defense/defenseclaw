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
	PlatformSupported   PlatformSupportStatus = "supported"
	PlatformPreview     PlatformSupportStatus = "preview"
	PlatformUnsupported PlatformSupportStatus = "unsupported"
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

// windowsConnectorSupport is the Go source of truth for native Windows
// connector availability. Keep it in exact parity with the Python
// cli/defenseclaw/platform_support.py WINDOWS_CONNECTOR_SUPPORT mapping.
var windowsConnectorSupport = map[string]PlatformSupport{
	"codex": {
		Status: PlatformSupported,
		Reason: "Codex CLI and the DefenseClaw hook entrypoint run natively on Windows.",
	},
	"claudecode": {
		Status: PlatformSupported,
		Reason: "Claude Code supports native Windows with Git for Windows and native hooks.",
	},
	"cursor": {
		Status: PlatformSupported,
		Reason: "Cursor IDE hooks run natively on Windows; Cursor CLI remains WSL-only.",
	},
	"windsurf": {
		Status: PlatformSupported,
		Reason: "Windsurf documents native Windows Cascade hooks.",
	},
	"geminicli": {
		Status: PlatformSupported,
		Reason: "Gemini CLI documents native Windows command hooks and PowerShell execution.",
	},
	"copilot": {
		Status: PlatformSupported,
		Reason: "GitHub Copilot CLI documents Windows hook execution through PowerShell.",
	},
	"antigravity": {
		Status: PlatformSupported,
		Reason: "Antigravity runs natively on Windows and exposes local JSON hooks.",
	},
	"opencode": {
		Status: PlatformSupported,
		Reason: "OpenCode runs directly on Windows and loads the JavaScript bridge plugin without shell shims.",
	},
	"hermes": {
		Status: PlatformPreview,
		Reason: "Hermes supports native Windows upstream, but DefenseClaw's native Windows hook integration remains preview pending live end-to-end validation.",
	},
	"openhands": {
		Status: PlatformUnsupported,
		Reason: "OpenHands CLI requires WSL; DefenseClaw does not implement a WSL connector path.",
	},
	"omnigent": {
		Status: PlatformUnsupported,
		Reason: "OmniGent has no supported native Windows terminal/sandbox path for this connector.",
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

// IsProxyConnector reports whether name is a proxy/chat connector (as opposed
// to a hook-based connector).
func IsProxyConnector(name string) bool {
	_, ok := proxyConnectors[name]
	return ok
}

// ConnectorSupportOnOS returns a supported/preview/unsupported classification
// with a human-readable reason. Unknown plugin connectors preserve historical
// behavior and remain available.
func ConnectorSupportOnOS(name, goos string) PlatformSupport {
	if goos == "windows" {
		if support, ok := windowsConnectorSupport[name]; ok {
			return support
		}
		return PlatformSupport{
			Status: PlatformSupported,
			Reason: "No native Windows restriction is registered for this plugin connector.",
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
	return ConnectorSupportOnOS(name, goos).Status != PlatformUnsupported
}

// ConnectorSupportOnHostOS returns the full classification for the host OS.
func ConnectorSupportOnHostOS(name string) PlatformSupport {
	return ConnectorSupportOnOS(name, runtime.GOOS)
}

// ConnectorSupportedOnHostOS reports availability on the current host OS.
func ConnectorSupportedOnHostOS(name string) bool {
	return ConnectorSupportOnHostOS(name).Status != PlatformUnsupported
}

// CheckPlatformSupport returns the shared operator-facing preview warning or
// unsupported error for a connector on goos. Supported connectors return two
// empty values so callers can preserve their existing control flow.
func CheckPlatformSupport(name, goos string) (string, error) {
	support := ConnectorSupportOnOS(name, goos)
	switch support.Status {
	case PlatformUnsupported:
		return "", fmt.Errorf("connector %q is not supported on %s: %s", name, goos, support.Reason)
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
