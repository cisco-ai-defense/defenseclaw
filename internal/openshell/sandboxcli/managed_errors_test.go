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

package sandboxcli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// On a managed computer a launch refusal read "blocked by …: <sentence>:
// sandbox_not_allowed", an egress refusal named openshell.admin.egress_allow_only,
// and every refusal on a MicroVM first boot ended with the 5-8 GB disk hint
// (GAP-0483, GAP-0486, GAP-0493). Each now reads in the plan §7.1 shape.
func TestManagedLaunchRefusalsReadInTheOrganizationsWords(t *testing.T) {
	withManagedHost(t)
	const contact = "Need an exception? Contact it-security@example.com"
	busy := &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Detail: "sandbox_account_busy",
		Message: "Sandboxes aren't available for your account on this computer right now: they are in use by another account. Try again later."}
	for _, c := range []struct {
		name string
		err  *sandboxapi.Error
		want string
	}{
		{"second account", busy, busy.Message},
		{"outdated service", &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Detail: sandboxrelay.ReasonDaemonOutdated,
			Message: "Your sandbox service is outdated; stop your sandboxes with defenseclaw sandbox stop NAME, then retry."},
			"Your sandbox service is outdated; stop your sandboxes with defenseclaw sandbox stop NAME, then retry."},
		{"authorized driver switch", &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Detail: sandboxrelay.DetailSetupChanging,
			Message: "Stop your sandboxes with defenseclaw sandbox stop NAME, then retry to finish the authorized update."},
			"Stop your sandboxes with defenseclaw sandbox stop NAME, then retry to finish the authorized update."},
		{"profile revoked", &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Detail: "sandbox_not_allowed",
			Message: "Your organization doesn't allow sandboxes for your account."},
			"Blocked by your organization's DefenseClaw policy: Your organization doesn't allow sandboxes for your account (profile contractors).\n" + contact},
		{"model endpoint off the allow list", &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: sandboxapi.AdminMessage,
			Violation: &sandboxapi.Violation{Key: "llm", Attempted: "bedrock.example.net", Constraint: "openshell.admin.egress_allow_only", Fatal: true,
				Detail: "bedrock.example.net is not on your organization's list of allowed destinations"}},
			sandboxapi.AccessRefused("egress_allow_only", "bedrock.example.net", "contractors", "", "it-security@example.com")},
		{"settings drift", &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Detail: "settings_drift", Message: sandboxapi.SettingsDrift("compute driver")},
			sandboxapi.SettingsDrift("compute driver")},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.status.Managed = managedStatusFixture()
			ta.daemon.status.Gateway.Driver = "vm"
			ta.daemon.explain.VMFirstBoot = true
			ta.daemon.errors["POST "+sandboxapi.PathSandboxes] = c.err
			err := ta.ManagedError(bg, ta.Run(bg, RunOptions{Harness: "claude"}))
			if err == nil || err.Error() != c.want {
				t.Fatalf("Run = %v\nwant %s", err, c.want)
			}
		})
	}
	// A first-start failure keeps the disk hint; a computer that is not
	// managed keeps the daemon's words.
	ta := newTestApp(t, "")
	ta.daemon.status.Gateway.Driver = "vm"
	ta.daemon.explain.VMFirstBoot = true
	ta.daemon.errors["POST "+sandboxapi.PathSandboxes] = &sandboxapi.Error{Code: sandboxapi.CodeUpstream, Message: "OpenShell: create failed"}
	err := ta.Run(bg, RunOptions{Harness: "claude"})
	if err == nil {
		t.Fatal("Run succeeded")
	}
	has(t, err.Error(), "a MicroVM first start prepares a 5-8 GB disk")
	if !firstStartFailure(err) || firstStartFailure(busy) {
		t.Fatal("firstStartFailure misjudges an upstream failure or the account-busy refusal")
	}
}

// `sandbox run amp` and `run opencode` printed only the managed gateway's
// enterprise_managed_uid_unregistered: the preflight of a connector the
// account is not set up for is refused before any policy is read. The run
// now reads the caller's own policy and names the profile's harness limit,
// or the setup only IT can do (GAP-0459).
func TestManagedRunOfAnUnenrolledHarnessNamesTheLimit(t *testing.T) {
	withManagedHost(t)
	for _, c := range []struct{ harness, want string }{
		{"amp", sandboxapi.HarnessNotAllowed("amp", "engineering", "it-security@example.com")},
		{"opencode", sandboxapi.HarnessNotEnabled("opencode", "engineering", "it-security@example.com")},
	} {
		ta := newTestApp(t, "")
		ta.daemon.status.Managed = managedStatusFixture()
		me := managedExplainFixture()
		me.Profile, me.AllowedHarnesses = "engineering", []string{"claudecode", "codex", "opencode", "hermes"}
		ta.daemon.explain.Managed = me
		ta.daemon.explainErr = func(req sandboxapi.ExplainRequest) *sandboxapi.Error {
			if req.Harness == "" {
				return nil
			}
			return &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: sandboxapi.AdminMessage, Detail: "enterprise_managed_uid_unregistered"}
		}
		err := ta.ManagedError(bg, ta.Run(bg, RunOptions{Harness: c.harness}))
		if err == nil || err.Error() != c.want {
			t.Fatalf("run %s = %v\nwant %s", c.harness, err, c.want)
		}
		if ta.creates() != 0 {
			t.Fatalf("run %s created a sandbox", c.harness)
		}
	}
}
