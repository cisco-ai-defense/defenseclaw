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

//go:build !windows

package packs

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func managedTestConfig(edit func(*config.OpenShellConfig)) *config.Config {
	cfg := testConfig(edit)
	cfg.DeploymentMode = "managed_enterprise"
	return cfg
}

// GAP-0487: a managed run that names no pack gets balanced, the pack ensure
// judges profile packs against; elsewhere the default stays open.
func TestManagedDefaultPackIsBalanced(t *testing.T) {
	me := ownSubject(t, t.TempDir())
	cfg := managedTestConfig(nil)
	floor := config.OpenShellAdminConfig{}
	eff, _ := mustResolve(t, cfg, Flags{Subject: me, Floor: &floor, Harness: "claudecode"})
	if eff.Pack.Name != ManagedDefaultPack || eff.NetworkMode != NetworkAllowlist || eff.Approvals != ApprovalsTriage {
		t.Fatalf("managed default: pack %s network %s approvals %s", eff.Pack.Name, eff.NetworkMode, eff.Approvals)
	}
	if got := DefaultPackFor(cfg); got != ManagedDefaultPack {
		t.Fatalf("DefaultPackFor(managed) = %s", got)
	}
	oss := testConfig(nil)
	if eff, _ := mustResolve(t, oss, Flags{}); eff.Pack.Name != DefaultPack || DefaultPackFor(oss) != DefaultPack {
		t.Fatalf("OSS default: pack %s", eff.Pack.Name)
	}
}
