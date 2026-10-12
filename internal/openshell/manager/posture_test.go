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

package manager

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-0458: a managed daemon restarted under a running sandbox resolves it
// first under its closed floor (strict, no sandboxes) and then under the
// floor the managed gateway names, and announced "profile strict → open;
// network deny → open; approvals manual → auto", a loosening that never
// happened. The closed floor is no baseline, so an unchanged policy says
// nothing; a real change says what moved without the OpenShell profile,
// whose built-in pack names are not the organization's profile.
func TestManagedRestartAnnouncesNoPolicyChange(t *testing.T) {
	e, _ := managedEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileOpen })
	e.live(sandboxapi.CreateRequest{Name: "rsbox"})
	e.register("rsbox")
	real := e.config().OpenShell.Admin
	moved := func() []sandboxapi.ActivityEvent {
		return e.events("rsbox", sandboxapi.ActivityLifecycle, sandboxapi.ReasonPolicyChanged)
	}

	// The restart: a new daemon has heard nothing of the sandbox's policy
	// and holds the closed floor until the managed gateway answers.
	b := e.boxOf("rsbox")
	e.m.mu.Lock()
	b.posture = nil
	e.m.mu.Unlock()
	no := false
	e.setConfig(func(c *config.Config) {
		c.OpenShell.Admin = config.OpenShellAdminConfig{MinProfile: "strict", Allowed: &no, AllowUnblock: &no, AllowHostPorts: &no}
	})
	e.m.refreshEgress()
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin = real })
	e.m.refreshEgress()
	if got := moved(); len(got) != 0 {
		t.Fatalf("an unchanged policy announced a change across a restart: %+v", got)
	}

	e.setConfig(func(c *config.Config) {
		c.OpenShell.Admin.MinProfile = config.OpenShellProfileBalanced
		c.OpenShell.Admin.EgressAllowOnly = []string{"github.com"}
	})
	e.m.refreshEgress()
	got := moved()
	if len(got) != 1 || strings.Contains(got[0].Message, "profile open") ||
		!strings.Contains(got[0].Message, "egress_allow_only now includes github.com") ||
		!strings.HasSuffix(got[0].Message, "; applied to rsbox; details: defenseclaw sandbox policy explain") {
		t.Fatalf("policy-change feed = %+v", got)
	}
}
