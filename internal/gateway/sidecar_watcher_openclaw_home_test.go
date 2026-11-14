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
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-10 GAP-0203: the watcher watches the OpenClaw tree of
// claw.home_dir (in the separate-user layout another account's home), not
// the gateway account's ~/.openclaw.
func TestResolveWatcherDirsOpenClawFollowsClawHomeDir(t *testing.T) {
	home := filepath.Join(t.TempDir(), "oc-account", ".openclaw")
	cfg := &config.Config{}
	cfg.Claw.HomeDir = home
	cfg.Claw.ConfigFile = filepath.Join(home, "openclaw.json")
	wcfg := config.GatewayWatcherConfig{
		Skill:  config.GatewayWatcherSkillConfig{Enabled: true},
		Plugin: config.GatewayWatcherPluginConfig{Enabled: true},
	}
	skills, plugins, _ := resolveWatcherDirs(cfg, connector.NewOpenClawConnector(), wcfg)
	if !slices.Contains(skills, filepath.Join(home, "skills")) {
		t.Fatalf("skill dirs %v do not include %s", skills, filepath.Join(home, "skills"))
	}
	if !slices.Contains(plugins, filepath.Join(home, "extensions")) {
		t.Fatalf("plugin dirs %v do not include %s", plugins, filepath.Join(home, "extensions"))
	}
}
