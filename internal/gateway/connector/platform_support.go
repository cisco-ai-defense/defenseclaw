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

// proxyConnectors are the chat/LLM-proxy connectors that interpose on model
// traffic through DefenseClaw's local guardrail proxy. They are unsupported on
// Windows, where DefenseClaw runs hook-only: the native Go hook entrypoint
// replaces the Bash hook chain, and there is no Windows guardrail-proxy
// lifecycle to host these connectors.
//
// This is the Go single source of truth for OS support. Keep it in sync with
// the Python cli/defenseclaw/platform_support.py WINDOWS_UNSUPPORTED_CONNECTORS
// set — a parity test pins the two lists together.
var proxyConnectors = map[string]struct{}{
	"openclaw":  {},
	"zeptoclaw": {},
}

// IsProxyConnector reports whether name is a proxy/chat connector (as opposed
// to a hook-based connector).
func IsProxyConnector(name string) bool {
	_, ok := proxyConnectors[name]
	return ok
}

// connectorSupportedOnOS reports whether a connector can be listed or set up on
// the given GOOS. Every hook-based connector is supported on every OS; the
// proxy connectors are unsupported on Windows.
func connectorSupportedOnOS(name, goos string) bool {
	if goos == "windows" && IsProxyConnector(name) {
		return false
	}
	return true
}

// ConnectorSupportedOnHostOS reports support on the current host OS.
func ConnectorSupportedOnHostOS(name string) bool {
	return connectorSupportedOnOS(name, runtime.GOOS)
}

// errConnectorUnsupportedOnOS is the clear, behavior-first error proxy-connector
// Setup returns when invoked on an OS that cannot host the guardrail proxy.
func errConnectorUnsupportedOnOS(name, goos string) error {
	return fmt.Errorf("connector %q is not supported on %s: DefenseClaw on %s is hook-only and proxy connectors require the guardrail proxy", name, goos, goos)
}
