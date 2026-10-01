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
	"encoding/json"
	osuser "os/user"
	"strings"
	"testing"

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
	out, _ := runPolicyCommand(t, runEnterprisePolicyShow)
	if !strings.Contains(out, "\n    enrollment: excluded by enterprise.enrollment.exclude_users: never enrolled") {
		t.Fatalf("show does not say the account is excluded:\n%s", out)
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
