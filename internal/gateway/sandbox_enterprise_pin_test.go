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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// The daemon of a host DefenseClaw 1.0.3 set up with the setup pin "0.1.3",
// which runs no sandbox (openshell.SupportedMin), installs the release this
// build installs, as ensure renders it; a prerequisite pin is the
// administrator's install and is judged as it is.
func TestSandboxEnterpriseMigratesTheOldSetupPin(t *testing.T) {
	prev := sandboxRenderedGateway
	sandboxRenderedGateway = func(string) (string, string) { return "", "" }
	t.Cleanup(func() { sandboxRenderedGateway = prev })
	cfg := &config.Config{}
	for _, tc := range []struct{ install, pin, want string }{
		{"setup", "0.1.3", openshell.InstallerVersion},
		{"setup", openshell.InstallerVersion, openshell.InstallerVersion},
		{"prerequisite", "0.1.3", "0.1.3"},
		{"", ">=0.1.1 <0.2.0", ">=0.1.1 <0.2.0"},
	} {
		cfg.Enterprise.OpenShell = config.EnterpriseOpenShellConfig{Install: tc.install, Driver: "docker", Version: tc.pin}
		if got := sandboxEnterprise(cfg, config.OpenShellAdminConfig{}).Version; got != tc.want {
			t.Errorf("install %q pin %q: daemon version %q, want %q", tc.install, tc.pin, got, tc.want)
		}
	}
}
