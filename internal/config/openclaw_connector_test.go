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
	"strings"
	"testing"
)

func TestValidateOpenClawConnector(t *testing.T) {
	no := false
	cases := []struct {
		name string
		oc   OpenClawConnectorConfig
		want string
	}{
		{"absent", OpenClawConnectorConfig{}, ""},
		{"managed", OpenClawConnectorConfig{PluginInstall: "managed", OperatorAdmin: &no}, ""},
		{"external", OpenClawConnectorConfig{PluginInstall: "external", PluginDir: "/opt/dc/openclaw/defenseclaw"}, ""},
		{"bad mode", OpenClawConnectorConfig{PluginInstall: "copy"}, "managed or external"},
		{"external no dir", OpenClawConnectorConfig{PluginInstall: "external"}, "clean absolute path"},
		{"external relative", OpenClawConnectorConfig{PluginInstall: "external", PluginDir: "opt/defenseclaw"}, "clean absolute path"},
		{"external wrong name", OpenClawConnectorConfig{PluginInstall: "external", PluginDir: "/opt/dc/plugin"}, "named defenseclaw"},
		{"dir without external", OpenClawConnectorConfig{PluginDir: "/opt/dc/defenseclaw"}, "only with plugin_install"},
		{"token file without account", OpenClawConnectorConfig{PluginTokenFile: "/etc/dc/oc.token"}, "need plugin_account"},
		{"separate user", OpenClawConnectorConfig{PluginAccount: "openclaw", PluginTokenFile: "/etc/dc/oc.token", PluginTokenGroup: "openclaw"}, ""},
		{"bad account", OpenClawConnectorConfig{PluginAccount: "a b"}, "not an account"},
	}
	for _, tc := range cases {
		cfg := &Config{}
		cfg.Connectors.OpenClaw = tc.oc
		err := cfg.ValidateOpenClawConnector()
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	cfg := &Config{}
	if !cfg.OpenClawOperatorAdmin() || cfg.OpenClawPluginInstall() != "managed" || cfg.OpenClawExternalPluginDir() != "" {
		t.Fatal("absent block must keep the 1.0.9 behaviour")
	}
	if got := cfg.UsesMinProductVersion110Keys(); got != nil {
		t.Fatalf("absent block reports 1.0.10 keys %v", got)
	}
}
