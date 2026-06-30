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
	"strings"
	"testing"
)

var windowsSupportedConnectorNames = []string{
	"antigravity",
	"claudecode",
	"codex",
	"copilot",
	"cursor",
	"geminicli",
	"opencode",
	"windsurf",
}

var windowsPreviewConnectorNames = []string{"hermes"}

var windowsUnsupportedConnectorNames = []string{
	"openclaw",
	"openhands",
	"omnigent",
	"zeptoclaw",
}

var proxyConnectorNames = []string{"openclaw", "zeptoclaw"}

func allWindowsConnectorNames() []string {
	out := append([]string(nil), windowsSupportedConnectorNames...)
	out = append(out, windowsPreviewConnectorNames...)
	out = append(out, windowsUnsupportedConnectorNames...)
	return out
}

func TestWindowsConnectorSupportTaxonomy(t *testing.T) {
	want := make(map[string]PlatformSupportStatus)
	for _, name := range windowsSupportedConnectorNames {
		want[name] = PlatformSupported
	}
	for _, name := range windowsPreviewConnectorNames {
		want[name] = PlatformPreview
	}
	for _, name := range windowsUnsupportedConnectorNames {
		want[name] = PlatformUnsupported
	}

	if len(windowsConnectorSupport) != len(want) {
		t.Fatalf("windowsConnectorSupport has %d entries, want %d", len(windowsConnectorSupport), len(want))
	}
	for name, wantStatus := range want {
		support, ok := windowsConnectorSupport[name]
		if !ok {
			t.Errorf("windowsConnectorSupport missing %q", name)
			continue
		}
		if support.Status != wantStatus {
			t.Errorf("%s status=%q, want %q", name, support.Status, wantStatus)
		}
		if strings.TrimSpace(support.Reason) == "" {
			t.Errorf("%s has no support reason", name)
		}
	}
}

func TestProxyConnectorsRemainTopologyOnly(t *testing.T) {
	got := make([]string, 0, len(proxyConnectors))
	for name := range proxyConnectors {
		got = append(got, name)
	}
	sort.Strings(got)
	want := append([]string(nil), proxyConnectorNames...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("proxyConnectors=%v, want %v", got, want)
	}
	for _, name := range []string{"openhands", "omnigent", "hermes"} {
		if IsProxyConnector(name) {
			t.Errorf("IsProxyConnector(%q)=true, want false", name)
		}
	}
}

func TestConnectorSupportOnOS(t *testing.T) {
	for _, name := range windowsSupportedConnectorNames {
		if got := ConnectorSupportOnOS(name, "windows").Status; got != PlatformSupported {
			t.Errorf("%s status=%q, want supported", name, got)
		}
	}
	for _, name := range windowsPreviewConnectorNames {
		if got := ConnectorSupportOnOS(name, "windows").Status; got != PlatformPreview {
			t.Errorf("%s status=%q, want preview", name, got)
		}
		if !connectorSupportedOnOS(name, "windows") {
			t.Errorf("preview connector %s should remain available", name)
		}
	}
	for _, name := range windowsUnsupportedConnectorNames {
		if got := ConnectorSupportOnOS(name, "windows").Status; got != PlatformUnsupported {
			t.Errorf("%s status=%q, want unsupported", name, got)
		}
		if connectorSupportedOnOS(name, "windows") {
			t.Errorf("unsupported connector %s should be unavailable", name)
		}
	}

	for _, goos := range []string{"linux", "darwin"} {
		for _, name := range allWindowsConnectorNames() {
			if got := ConnectorSupportOnOS(name, goos).Status; got != PlatformSupported {
				t.Errorf("%s on %s status=%q, want supported", name, goos, got)
			}
		}
	}

	if got := ConnectorSupportOnOS("plugin-example", "windows").Status; got != PlatformSupported {
		t.Fatalf("unknown plugin status=%q, want supported", got)
	}
}

func TestValidateConnectorSupportedOnOS(t *testing.T) {
	if err := validateConnectorSupportedOnOS("hermes", "windows"); err != nil {
		t.Fatalf("preview connector should validate: %v", err)
	}
	err := validateConnectorSupportedOnOS("openhands", "windows")
	if err == nil || !strings.Contains(err.Error(), "requires WSL") {
		t.Fatalf("expected clear OpenHands Windows rejection, got %v", err)
	}
}

func TestRegistryWindowsFilterKeepsSupportedAndPreview(t *testing.T) {
	reg := NewDefaultRegistry()
	var got []string
	for _, name := range reg.Names() {
		if connectorSupportedOnOS(name, "windows") {
			got = append(got, name)
		}
	}
	sort.Strings(got)
	want := append([]string(nil), windowsSupportedConnectorNames...)
	want = append(want, windowsPreviewConnectorNames...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("windows-filtered connectors=%v, want %v", got, want)
	}
}
