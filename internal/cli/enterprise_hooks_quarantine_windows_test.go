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

//go:build windows

package cli

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0491: a running guardian uses the protected config's latest watcher
// settings after a config-only ensure, and refuses removals if reload fails.
func TestEnterpriseHookQuarantineReloadsWatcherConfig(t *testing.T) {
	previous := enterpriseHooksWindowsConfigLoader
	t.Cleanup(func() { enterpriseHooksWindowsConfigLoader = previous })
	startup := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: "C:\\data"}
	startup.Enterprise.Profile = managed.ProfileStandalone
	latest := *startup
	latest.Gateway.Watcher.Skill.Enabled = true
	enterpriseHooksWindowsConfigLoader = func() (*config.Config, error) { return &latest, nil }
	got, err := enterpriseHookQuarantineCurrentConfig(startup)
	if err != nil || !got.Gateway.Watcher.Skill.Enabled {
		t.Fatalf("guardian kept stale watcher config: %+v, %v", got, err)
	}
	enterpriseHooksWindowsConfigLoader = func() (*config.Config, error) { return nil, errors.New("reload failed") }
	if _, err := enterpriseHookQuarantineCurrentConfig(startup); err == nil {
		t.Fatal("guardian accepted a removal without a current protected config")
	}
}
