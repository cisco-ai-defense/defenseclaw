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

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// The daemon and managed ensure use the same effective version requirement.
func TestGAP0608SandboxEnterpriseVersionFloor(t *testing.T) {
	prev := sandboxRenderedGateway
	sandboxRenderedGateway = func(string) (string, string) { return "", "" }
	t.Cleanup(func() { sandboxRenderedGateway = prev })
	cfg := &config.Config{}
	for _, tc := range []struct{ install, pin, want string }{
		{"setup", "0.1.3", openshell.InstallerVersion},
		{"setup", openshell.InstallerVersion, openshell.InstallerVersion},
		{"prerequisite", "0.1.3", openshell.InstallerVersion},
		{"prerequisite", "0.1.5", openshell.InstallerVersion},
		{"prerequisite", "0.1.6", "0.1.6"},
		{"prerequisite", "0.1.7", "0.1.7"},
		{"", ">=0.1.1 <0.2.0", ">=0.1.6 <0.2.0"},
	} {
		cfg.Enterprise.OpenShell = config.EnterpriseOpenShellConfig{Install: tc.install, Driver: "docker", Version: tc.pin}
		if got := sandboxEnterprise(cfg, config.OpenShellAdminConfig{}).Version; got != tc.want {
			t.Errorf("install %q pin %q: daemon version %q, want %q", tc.install, tc.pin, got, tc.want)
		}
	}
}

func TestGAP0608ImpossibleRangeIsUnavailable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Enterprise.OpenShell.Version = ">=0.1.1 <0.1.6"
	if why := sandboxOpenShellPrerequisite(cfg, 0, "docker"); !strings.Contains(why, "no release at or above the OpenShell 0.1.6 floor") {
		t.Errorf("unavailable reason = %q", why)
	}
}

func TestGAP0608LegacyPrerequisiteRecordGuidance(t *testing.T) {
	for _, pin := range []string{"0.1.3", "0.1.5", "0.01.5"} {
		text := installedOpenShellPrerequisite("openshell: 0.1.6 is installed, enterprise.openshell.version pins " + pin)
		if !strings.Contains(text, "OpenShell 0.1.6 floor") || !strings.Contains(text, "set the pin to 0.1.6 or later") || strings.Contains(text, "install the pinned release") {
			t.Errorf("old pin %s: guidance = %q", pin, text)
		}
	}
	text := installedOpenShellPrerequisite("openshell: 0.1.6 is installed, enterprise.openshell.version pins 0.1.7")
	if !strings.Contains(text, "install the pinned release") {
		t.Errorf("supported pin guidance = %q", text)
	}
}
