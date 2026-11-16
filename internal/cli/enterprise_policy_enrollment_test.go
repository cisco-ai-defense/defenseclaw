//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	osuser "os/user"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// `enterprise policy show --user svc-sync`, an account listed in
// enterprise.enrollment.exclude_users, printed the same connector table as
// for an enrolled account and never said the account is excluded.
func TestEnterprisePolicyShowSaysWhyTheUserIsNotEnrolled(t *testing.T) {
	ctx := withEnterprisePolicyTree(t)
	if _, err := enterprisepolicy.Publish(ctx.opts, ctx.connectors); err != nil {
		t.Fatal(err)
	}
	current, err := osuser.Current()
	if err != nil {
		t.Fatal(err)
	}
	previous := cfg
	t.Cleanup(func() { cfg = previous })
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	enterprisePolicyUser = current.Username

	cfg.Enterprise.Enrollment.ExcludeUsers = []string{"someone-else", current.Username}
	t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(false) })
	out, _ := runPolicyCommand(t, runEnterprisePolicyShow)
	if !strings.Contains(out, "\n    enrollment: excluded by enterprise.enrollment.exclude_users: never enrolled") {
		t.Fatalf("show does not say the account is excluded:\n%s", out)
	}
	// The hooks step resolves the target uid with the standalone rules, which
	// fall back to NSS for a directory account (GAP-0740).
	if !enterprisehooks.StandaloneUnix() {
		t.Fatal("policy show --user did not switch the hooks step to the standalone account rules")
	}
	// A uid names the account too.
	if target, err := enterprisePolicyTarget(current.Uid); err != nil || strconv.Itoa(target.UID) != current.Uid {
		t.Fatalf("policy target by uid %s = %+v, %v", current.Uid, target, err)
	}
	// The resolver the hooks step uses still answers after the lookup
	// context of the policy target has ended: it was bound to it, so every
	// directory account failed with "getent timed out: context canceled"
	// (GAP-0740).
	t.Cleanup(func() { enterprisehooks.SetStandaloneResolver(nil) })
	uid, _ := strconv.Atoi(current.Uid)
	if _, err := enterprisehooks.StandaloneResolver().LookupUID(uid); err != nil {
		t.Fatalf("the hooks step resolver fails after policy target returned: %v", err)
	}
	enterprisePolicyJSON = true
	out, _ = runPolicyCommand(t, runEnterprisePolicyShow)
	var report enterprisePolicyReport
	if err := json.Unmarshal([]byte(out), &report); err != nil || report.User == nil || !strings.Contains(report.User.Enrollment, "exclude_users") {
		t.Fatalf("show --json does not carry the exclusion: %v\n%s", err, out)
	}
	enterprisePolicyJSON = false

	// exempt_users also matches the decimal uid, as the enumerator does.
	cfg.Enterprise.Enrollment.ExcludeUsers = nil
	cfg.Enterprise.Enrollment.ExemptUsers = []string{current.Uid}
	out, _ = runPolicyCommand(t, runEnterprisePolicyShow)
	if !strings.Contains(out, "enrollment: exempt by enterprise.enrollment.exempt_users") {
		t.Fatalf("show does not say the account is exempt:\n%s", out)
	}

	cfg.Enterprise.Enrollment.ExemptUsers = nil
	out, _ = runPolicyCommand(t, runEnterprisePolicyShow)
	if strings.Contains(out, "enrollment:") != (current.Uid == "0") {
		t.Fatalf("an account no rule excludes got an enrollment line:\n%s", out)
	}

	// macOS resolves a differently cased --user to the same account. The
	// rules match the name the account database returns, as the enumerator
	// does, not the text typed.
	previousResolve := enterprisePolicyResolveTarget
	t.Cleanup(func() { enterprisePolicyResolveTarget = previousResolve })
	enterprisePolicyResolveTarget = func(string) (enterprisehooks.TargetCredentials, error) {
		target, err := enterprisePolicyTarget(current.Username)
		target.Username = current.Username
		return target, err
	}
	enterprisePolicyUser = strings.ToUpper(current.Username) + "-TYPED"
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{current.Username}
	out, _ = runPolicyCommand(t, runEnterprisePolicyShow)
	if !strings.Contains(out, "enrollment: excluded by enterprise.enrollment.exclude_users") {
		t.Fatalf("a differently typed name of an excluded account must still show the exclusion:\n%s", out)
	}
}

// GAP-2456: `enterprise policy show --user <unknown> --json` printed the
// report and then cobra's "Error: look up user ..." line; the report now
// carries the failure in errors[] and the line is silenced, exit 1 stays.
// Text mode keeps the line.
func TestEnterprisePolicyJSONUnknownUserPrintsOnlyJSON(t *testing.T) {
	resetEnterprisePolicyFlags(t)
	ctx := withEnterprisePolicyTree(t)
	if _, err := enterprisepolicy.Publish(ctx.opts, ctx.connectors); err != nil {
		t.Fatal(err)
	}
	previous := cfg
	t.Cleanup(func() { cfg = previous })
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	enterprisePolicyUser = "dc-no-such-user-gap2456"
	for _, run := range []func(*cobra.Command, []string) error{runEnterprisePolicyShow, runEnterprisePolicyVerify} {
		for _, asJSON := range []bool{false, true} {
			enterprisePolicyJSON = asJSON
			var out bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&out)
			err := run(cmd, nil)
			if err == nil || !strings.Contains(err.Error(), "dc-no-such-user-gap2456") || commandExitCode(err) != 1 {
				t.Fatalf("json %t: error %v", asJSON, err)
			}
			if cmd.SilenceErrors != asJSON {
				t.Fatalf("json %t: SilenceErrors %t", asJSON, cmd.SilenceErrors)
			}
			if !asJSON {
				continue
			}
			var report enterprisePolicyReport
			if jsonErr := json.Unmarshal(out.Bytes(), &report); jsonErr != nil || report.Complete ||
				len(report.Errors) != 1 || report.Errors[0] != err.Error() {
				t.Fatalf("--json report: %v\n%s", jsonErr, out.String())
			}
		}
	}
}

func TestUnixEnrollmentExclusion(t *testing.T) {
	enrollment := config.EnterpriseEnrollmentConfig{
		ExcludeUsers: []string{" svc-sync ", "1234401103"},
		ExemptUsers:  []string{"svc-release", "svc-sync"},
		Root:         config.EnterpriseRootDeny,
	}
	for _, tc := range []struct {
		name string
		uid  int
		want string
	}{
		{"svc-sync", 501, "excluded by enterprise.enrollment.exclude_users"},
		{"CORP\\jdoe", 1234401103, "excluded by enterprise.enrollment.exclude_users"},
		{"svc-release", 502, "exempt by enterprise.enrollment.exempt_users"},
		{"root", 0, "enterprise.enrollment.root (deny)"},
		{"alice", 503, ""},
	} {
		got := unixEnrollmentExclusion(enrollment, tc.name, tc.uid)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Fatalf("%s (uid %d): %q, want %q", tc.name, tc.uid, got, tc.want)
		}
	}
	if got := unixEnrollmentExclusion(config.EnterpriseEnrollmentConfig{}, "root", 0); !strings.Contains(got, "(inspect)") {
		t.Fatalf("root without enrollment.root: %q", got)
	}
}

// GAP-0949: the install scan skips an exclude_users account before it finds
// the OpenCode it runs, so a covered OpenCode machine-policy row must not be
// the last word for that account in the administrator status. Text and JSON
// state that V1 is not protected and V2 is required; an enrolled account, an
// account no rule excludes, and a deployment with no OpenCode row stay as
// they were.
func TestEnterprisePolicyShowExcludedAccountSaysOpenCodeV1IsNotProtected(t *testing.T) {
	saved := enterprisePolicyJSON
	t.Cleanup(func() { enterprisePolicyJSON = saved })
	excluded := unixEnrollmentExclusion(config.EnterpriseEnrollmentConfig{ExcludeUsers: []string{"alice"}}, "alice", 501)
	exempt := unixEnrollmentExclusion(config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"alice"}}, "alice", 501)
	openCode := enterprisepolicy.State{Connector: "opencode", Route: enterprisepolicy.RouteMachinePolicy, Covered: true, OwnedEntries: 1}
	claude := enterprisepolicy.State{Connector: "claudecode", Route: enterprisepolicy.RouteMachinePolicy, Covered: true, OwnedEntries: 1}
	off := openCode
	off.Ownership = config.MachinePolicyOwnershipOff
	for _, tc := range []struct {
		name       string
		enrollment string
		states     []enterprisepolicy.State
		want       bool
		// claimsCoverage: the line says the machine policy covers V2 calls.
		claimsCoverage bool
	}{
		{"excluded with a covered OpenCode row", excluded, []enterprisepolicy.State{claude, openCode}, true, true},
		{"excluded with an uncovered OpenCode row", excluded, []enterprisepolicy.State{{Connector: "opencode", Route: enterprisepolicy.RouteMachinePolicy}}, true, false},
		{"excluded, OpenCode ownership off", excluded, []enterprisepolicy.State{off}, false, false},
		{"excluded, no OpenCode row", excluded, []enterprisepolicy.State{claude}, false, false},
		{"enrolled account", "", []enterprisepolicy.State{claude, openCode}, false, false},
		{"exempt account", exempt, []enterprisepolicy.State{claude, openCode}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := enterprisePolicyReport{
				Complete: true, HookBinary: "/opt/defenseclaw/bin/defenseclaw-hook", goos: "linux",
				Result: enterprisepolicy.Result{States: tc.states},
				User:   &enterprisePolicyUserReport{User: "alice", Enrollment: tc.enrollment},
			}
			report.User.OpenCodeNote = excludedOpenCodeNote(tc.enrollment, tc.states)
			for _, asJSON := range []bool{false, true} {
				enterprisePolicyJSON = asJSON
				var out bytes.Buffer
				if err := writeEnterprisePolicyReport(&out, report); err != nil {
					t.Fatal(err)
				}
				text := out.String()
				got := strings.Contains(text, "OpenCode V1 (opencode-ai) is not protected") && strings.Contains(text, "V2 is required")
				if got != tc.want {
					t.Fatalf("json %t: V1 warning present=%t, want %t:\n%s", asJSON, got, tc.want, text)
				}
				// The line may say the machine policy covers V2 calls only
				// when the row is verified covered; an uncovered row asks for
				// the repair instead (GAP-0949).
				claims := strings.Contains(text, "the machine policy covers OpenCode V2")
				if tc.want && claims != tc.claimsCoverage {
					t.Fatalf("json %t: coverage claim present=%t, want %t:\n%s", asJSON, claims, tc.claimsCoverage, text)
				}
				if tc.want && !tc.claimsCoverage && !strings.Contains(text, "not covered either") {
					t.Fatalf("json %t: uncovered row does not ask for the repair:\n%s", asJSON, text)
				}
			}
		})
	}
}
