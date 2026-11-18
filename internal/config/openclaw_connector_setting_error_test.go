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

import (
	"errors"
	"strings"
	"testing"
)

// GAP-1140: a connectors.openclaw refusal is a SettingError at the key it
// names, so config set shows the rule (on Windows: run OpenClaw and
// DefenseClaw as one account), not "could not be compiled safely" at "$".
func TestValidateOpenClawConnectorNamesTheSetting(t *testing.T) {
	prev := openClawGOOS
	t.Cleanup(func() { openClawGOOS = prev })
	for _, tc := range []struct {
		goos, path, want string
		oc               OpenClawConnectorConfig
	}{
		{"windows", "connectors.openclaw.plugin_account", "on Windows run OpenClaw and DefenseClaw as one account",
			OpenClawConnectorConfig{PluginAccount: "dcw-oc"}},
		{"linux", "connectors.openclaw.plugin_account", "needs plugin_install: external",
			OpenClawConnectorConfig{PluginAccount: "openclaw", PluginTokenFile: "/etc/dc/oc.token"}},
		{"linux", "connectors.openclaw.plugin_install", "must be managed or external",
			OpenClawConnectorConfig{PluginInstall: "copy"}},
	} {
		openClawGOOS = tc.goos
		cfg := &Config{}
		cfg.Connectors.OpenClaw = tc.oc
		err := cfg.ValidateOpenClawConnector()
		var setting *SettingError
		if !errors.As(err, &setting) || setting.Path != tc.path || !strings.Contains(setting.Detail(), tc.want) {
			t.Errorf("%s %+v: err = %#v, want a SettingError at %s with %q", tc.goos, tc.oc, err, tc.path, tc.want)
		}
	}
}
