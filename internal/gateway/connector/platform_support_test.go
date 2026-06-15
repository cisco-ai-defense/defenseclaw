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
	"sort"
	"testing"
)

// proxyConnectorNames mirrors the Python
// platform_support.WINDOWS_UNSUPPORTED_CONNECTORS set. A change on either
// side must be made on both; these tests fail loudly if they drift.
var proxyConnectorNames = []string{"openclaw", "zeptoclaw"}

// hookConnectorNames are the hook-based connectors supported on every
// OS, including Windows.
var hookConnectorNames = []string{
	"antigravity",
	"claudecode",
	"codex",
	"copilot",
	"cursor",
	"geminicli",
	"hermes",
	"opencode",
	"openhands",
	"windsurf",
}

func TestProxyConnectorsSetMatchesMirror(t *testing.T) {
	got := make([]string, 0, len(proxyConnectors))
	for name := range proxyConnectors {
		got = append(got, name)
	}
	sort.Strings(got)
	want := append([]string(nil), proxyConnectorNames...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("proxyConnectors = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("proxyConnectors = %v, want %v", got, want)
		}
	}
}

func TestIsProxyConnector(t *testing.T) {
	for _, name := range proxyConnectorNames {
		if !IsProxyConnector(name) {
			t.Errorf("IsProxyConnector(%q) = false, want true", name)
		}
	}
	for _, name := range hookConnectorNames {
		if IsProxyConnector(name) {
			t.Errorf("IsProxyConnector(%q) = true, want false", name)
		}
	}
}

func TestConnectorSupportedOnOS(t *testing.T) {
	// Windows: proxy connectors unsupported, hook connectors supported.
	for _, name := range proxyConnectorNames {
		if connectorSupportedOnOS(name, "windows") {
			t.Errorf("connectorSupportedOnOS(%q, windows) = true, want false", name)
		}
	}
	for _, name := range hookConnectorNames {
		if !connectorSupportedOnOS(name, "windows") {
			t.Errorf("connectorSupportedOnOS(%q, windows) = false, want true", name)
		}
	}
	// Unix: everything supported.
	for _, goos := range []string{"linux", "darwin"} {
		for _, name := range append(append([]string(nil), proxyConnectorNames...), hookConnectorNames...) {
			if !connectorSupportedOnOS(name, goos) {
				t.Errorf("connectorSupportedOnOS(%q, %s) = false, want true", name, goos)
			}
		}
	}
}

// TestRegistryNamesFilterToHookConnectorsOnWindows takes the full built-in
// registry (Available() returns all connectors on this non-Windows host) and
// asserts that applying the Windows OS filter yields exactly the hook
// connectors, with both proxy connectors removed.
func TestRegistryNamesFilterToHookConnectorsOnWindows(t *testing.T) {
	reg := NewDefaultRegistry()
	var all []string
	for _, info := range reg.Available() {
		all = append(all, info.Name)
	}

	var onWindows []string
	for _, name := range all {
		if connectorSupportedOnOS(name, "windows") {
			onWindows = append(onWindows, name)
		}
	}
	sort.Strings(onWindows)

	want := append([]string(nil), hookConnectorNames...)
	sort.Strings(want)
	if len(onWindows) != len(want) {
		t.Fatalf("windows-filtered connectors = %v, want %v", onWindows, want)
	}
	for i := range onWindows {
		if onWindows[i] != want[i] {
			t.Fatalf("windows-filtered connectors = %v, want %v", onWindows, want)
		}
	}
}
