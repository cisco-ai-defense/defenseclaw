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
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// rel-1-0-2:GAP-0462: after a managed daemon's restart, a sandbox's status
// is judged against the closed start-up floor until the managed gateway
// confirms its registration, and said "your organization does not let you
// run sandboxes (openshell.admin.allowed)" with a strict, deny-all policy
// for a sandbox the organization allows. The view is built from the policy
// resolved before, so the confirmed floor showed only after the next
// configuration check: RefreshPolicies re-resolves at once, and
// ConfirmingView says the policy is being confirmed instead of the deny.
func TestConfirmingViewAndRefreshPoliciesAfterARestart(t *testing.T) {
	e, _ := managedEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileOpen })
	e.live(sandboxapi.CreateRequest{Name: "cfbox"})
	e.register("cfbox")
	real := e.config().OpenShell.Admin
	configured, err := e.m.Get(t.Context(), "cfbox")
	must(t, err)
	if configured.NetworkMode == packs.NetworkDeny || orgViolation(configured) != "" {
		t.Fatalf("the sandbox does not start under an allowing floor: %+v", configured)
	}

	// The restart: the closed floor, as the configuration check resolves it.
	no := false
	e.setConfig(func(c *config.Config) {
		c.OpenShell.Admin = config.OpenShellAdminConfig{MinProfile: "strict", Allowed: &no, AllowUnblock: &no, AllowHostPorts: &no, AllowYolo: &no}
	})
	e.m.RefreshPolicies()
	closed, err := e.m.Get(t.Context(), "cfbox")
	must(t, err)
	if !slices.ContainsFunc(closed.Violations, func(v sandboxapi.Violation) bool { return v.Constraint == "openshell.admin.allowed" }) || closed.NetworkMode != packs.NetworkDeny || closed.Profile != "strict" {
		t.Fatalf("the closed floor's view is not the deny this test rewrites: %+v %+v", closed.Violations, closed)
	}

	const note = "confirming; try again in a moment"
	v := *closed
	e.m.ConfirmingView(&v, note)
	if orgViolation(&v) != "" || v.Profile != configured.Profile || v.NetworkMode != configured.NetworkMode || v.Approvals != configured.Approvals {
		t.Fatalf("confirming view = profile %q network %q approvals %q violations %+v, want the created policy %q %q %q",
			v.Profile, v.NetworkMode, v.Approvals, v.Violations, configured.Profile, configured.NetworkMode, configured.Approvals)
	}
	if !slices.Contains(v.Warnings, note) || slices.ContainsFunc(v.Warnings, func(w string) bool {
		return strings.Contains(w, "now runs under") || strings.Contains(w, "your organization")
	}) {
		t.Fatalf("confirming view warnings = %q", v.Warnings)
	}
	unknown := sandboxapi.Sandbox{Name: "not-held", Profile: "strict"}
	e.m.ConfirmingView(&unknown, note)
	if unknown.Profile != "strict" || len(unknown.Warnings) != 0 {
		t.Fatalf("rewrote a sandbox the manager does not hold: %+v", unknown)
	}

	// The confirmation: the next view has the organization's policy without
	// waiting for the configuration check.
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin = real })
	e.m.RefreshPolicies()
	after, err := e.m.Get(t.Context(), "cfbox")
	must(t, err)
	if orgViolation(after) != "" || after.Profile != configured.Profile || after.NetworkMode != configured.NetworkMode {
		t.Fatalf("after the confirmation: profile %q network %q violations %+v", after.Profile, after.NetworkMode, after.Violations)
	}
}

// orgViolation is the constraint of a view's first organization violation.
func orgViolation(sb *sandboxapi.Sandbox) string {
	for _, v := range sb.Violations {
		if v.Admin {
			return v.Constraint
		}
	}
	return ""
}
