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

package setup

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0906: the schema takes push_branch and key_replay in any case, as Go
// does (it lowercases them), so a value rel rendered (push_branch=Deny)
// still passes helm upgrade; the dedicated values follow the same rule.
func TestGAP0906ChartTakesAnyCase(t *testing.T) {
	helm := helmBinary(t)
	for name, extra := range map[string][]string{
		"config":    {"--set", "config.substrate.git.push_branch=Deny", "--set", "config.substrate.launcher.key_replay=OFF"},
		"dedicated": {"--set", "substrate.git.pushBranch=Deny", "--set", "substrate.launcher.keyReplay=OFF"},
	} {
		t.Run(name, func(t *testing.T) {
			sub := renderedSubstrate(t, renderChart(t, helm, "default", extra...))
			git, _ := sub["git"].(map[string]any)
			launcher, _ := sub["launcher"].(map[string]any)
			pb, _ := git["push_branch"].(string)
			kr, _ := launcher["key_replay"].(string)
			s := config.SubstrateConfig{Git: config.SubstrateGitConfig{PushBranch: pb}, Launcher: config.SubstrateLauncherConfig{KeyReplay: kr}}
			if s.Git.EffectivePushBranch() != config.SubstrateGitPushDeny || s.Launcher.EffectiveKeyReplay() != config.SubstrateKeyReplayOff {
				t.Errorf("rendered push_branch %q key_replay %q, want deny and off once Go reads them", pb, kr)
			}
		})
	}
}
