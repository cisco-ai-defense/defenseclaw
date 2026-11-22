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
	"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "openclaw", "opencode",
}

var windowsPreviewConnectorNames = []string{}

var windowsNotCertifiedConnectorNames = []string{}

var windowsUnsupportedConnectorNames = []string{
	"zeptoclaw",
}

var proxyConnectorNames = []string{"openclaw", "zeptoclaw"}

func allWindowsConnectorNames() []string {
	out := append([]string(nil), windowsSupportedConnectorNames...)
	out = append(out, windowsPreviewConnectorNames...)
	out = append(out, windowsNotCertifiedConnectorNames...)
	out = append(out, windowsUnsupportedConnectorNames...)
	return out
}

func TestWindowsConnectorSupportTaxonomy(t *testing.T) {
	want := make(map[string]PlatformSupportStatus)
	for _, name := range windowsSupportedConnectorNames {
		want[name] = PlatformSupported
	}
	// Preview connectors remain selectable while certification evidence is
	// still pending.
	for _, name := range windowsPreviewConnectorNames {
		want[name] = PlatformPreview
	}
	for _, name := range windowsNotCertifiedConnectorNames {
		want[name] = PlatformNotCertified
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
	for _, name := range []string{"hermes"} {
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
	for _, name := range windowsNotCertifiedConnectorNames {
		if got := ConnectorSupportOnOS(name, "windows").Status; got != PlatformNotCertified {
			t.Errorf("%s status=%q, want not_certified", name, got)
		}
		if connectorSupportedOnOS(name, "windows") {
			t.Errorf("not-certified connector %s should be unavailable", name)
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
			want := PlatformSupported
			if got := ConnectorSupportOnOS(name, goos).Status; got != want {
				t.Errorf("%s on %s status=%q, want %q", name, goos, got, want)
			}
		}
	}

	if got := ConnectorSupportOnOS("plugin-example", "windows").Status; got != PlatformNotCertified {
		t.Fatalf("unknown plugin status=%q, want not_certified", got)
	}
}

func TestOpenCodeV2PlatformSupportMatchesLiveCertificationGAP0552(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		if support := ConnectorSupportOnOS("opencode", goos); support.Status != PlatformSupported {
			t.Errorf("opencode on %s status=%q, want supported", goos, support.Status)
		}
		if warning, err := CheckPlatformSupport("opencode", goos); warning != "" || err != nil {
			t.Errorf("opencode on %s warning=%q err=%v, want no warning or error", goos, warning, err)
		}
	}
}

func TestClaudeCodePlatformSupportStaysSupportedGAP0552BenignTwin(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		if support := ConnectorSupportOnOS("claudecode", goos); support.Status != PlatformSupported {
			t.Errorf("claudecode on %s status=%q, want supported", goos, support.Status)
		}
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

func TestCheckPlatformSupportPreservesOperatorWording(t *testing.T) {
	warning, err := CheckPlatformSupport("cursor", "windows")
	if err != nil || warning != "" {
		t.Fatalf("supported Cursor result warning=%q err=%v", warning, err)
	}

	for _, name := range []string{"copilot", "antigravity", "hermes"} {
		warning, err = CheckPlatformSupport(name, "windows")
		if err != nil || warning != "" {
			t.Fatalf("supported %s result warning=%q err=%v", name, warning, err)
		}
	}

	warning, err = CheckPlatformSupport("zeptoclaw", "windows")
	if warning != "" {
		t.Fatalf("unsupported warning = %q, want empty", warning)
	}
	wantError := "connector \"zeptoclaw\" is not supported on windows: " + windowsConnectorSupport["zeptoclaw"].Reason
	if err == nil || err.Error() != wantError {
		t.Fatalf("unsupported error = %v, want %q", err, wantError)
	}
}

func TestValidateConnectorSupportedOnOS(t *testing.T) {
	for _, name := range []string{"copilot", "antigravity", "hermes"} {
		if err := validateConnectorSupportedOnOS(name, "windows"); err != nil {
			t.Fatalf("supported connector %s should remain available: %v", name, err)
		}
	}
	if err := validateConnectorSupportedOnOS("openclaw", "windows"); err != nil {
		t.Fatalf("OpenClaw runs native hooks on Windows and must be available: %v", err)
	}
	err := validateConnectorSupportedOnOS("zeptoclaw", "windows")
	if err == nil || !strings.Contains(err.Error(), "requires the guardrail proxy") {
		t.Fatalf("expected clear ZeptoClaw Windows rejection, got %v", err)
	}
}

// The OpenClaw Windows row says what native mode leaves out, so an operator
// does not expect the proxy-only protections there.
func TestOpenClawWindowsRowNamesNativeModeLimits(t *testing.T) {
	reason := ConnectorSupportOnOS("openclaw", "windows").Reason
	for _, want := range []string{OpenClawNativeHooksSince, "native plugin hooks", "no guardrail proxy", "managed Windows"} {
		if !strings.Contains(reason, want) {
			t.Errorf("OpenClaw Windows reason %q does not say %q", reason, want)
		}
	}
}

// UsesGuardrailProxy follows the resolved hook mode: OpenClaw uses the proxy
// on Linux and macOS (proxy or hybrid) and not on Windows (native), while
// IsProxyConnector stays the fixed connector family on every OS.
func TestUsesGuardrailProxyFollowsTheOpenClawHookMode(t *testing.T) {
	cases := []struct {
		name, goos string
		want       bool
	}{
		{"openclaw", "linux", true},
		{"openclaw", "darwin", true},
		{"openclaw", "windows", false},
		{"zeptoclaw", "linux", true},
		{"zeptoclaw", "windows", true},
		{"codex", "linux", false},
		{"codex", "windows", false},
	}
	for _, tc := range cases {
		if got := UsesGuardrailProxyOnOS(tc.name, tc.goos); got != tc.want {
			t.Errorf("UsesGuardrailProxyOnOS(%q, %q) = %v, want %v", tc.name, tc.goos, got, tc.want)
		}
	}
	prev := openClawHooksGOOS
	t.Cleanup(func() { openClawHooksGOOS = prev })
	for _, goos := range []string{"linux", "darwin", "windows"} {
		openClawHooksGOOS = goos
		if !IsProxyConnector("openclaw") {
			t.Errorf("IsProxyConnector(openclaw) on %s = false; the family does not change with the OS", goos)
		}
		want := goos != "windows"
		if got := UsesGuardrailProxy("openclaw"); got != want {
			t.Errorf("UsesGuardrailProxy(openclaw) on %s = %v, want %v", goos, got, want)
		}
		wantMode := LLMTrafficModeProxy
		if goos == "windows" {
			wantMode = LLMTrafficModeHooksOnly
		}
		if got := LLMTrafficModeForConnector("openclaw"); got != wantMode {
			t.Errorf("LLMTrafficModeForConnector(openclaw) on %s = %q, want %q", goos, got, wantMode)
		}
	}
}
