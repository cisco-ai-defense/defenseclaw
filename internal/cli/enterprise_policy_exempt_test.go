// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os/user"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

// Captured from TestProfileResolveWithoutProfilesReportsHookExemption/alice
// against the real no-profile gateway handler. The CLI asks this route with
// no connector, and enterprisePolicySandboxProfile decodes its enrollment.
const noProfileExemptResolveJSON = `{"agent":"","connector":"","effective":{"alert_at":"","block_at":"","hilt":{"enabled":false,"min_severity":""},"mode":"observe","resolved_block_at":"CRITICAL","rule_pack_dir":""},"enrollment":{"exempt":true},"match":"","profile":"","profiles_configured":false,"subject":{"directory":"","group_count":0,"groups":null,"principal":"","upn":"","user_id":"2201","user_name":"alice"},"user":"alice","warnings":["this account is in enterprise.enrollment.exempt_users: it is not enrolled and required_for never refuses its host runs, but its calls are still inspected under the guardrail settings and logged (defenseclaw.user.enrollment: exempt)"]}`

func noProfileResolveJSONFor(t *testing.T, account string, uid int, exempt bool) []byte {
	t.Helper()
	var answer map[string]any
	if err := json.Unmarshal([]byte(noProfileExemptResolveJSON), &answer); err != nil {
		t.Fatal(err)
	}
	answer["user"] = account
	subject := answer["subject"].(map[string]any)
	subject["user_id"] = strconv.Itoa(uid)
	subject["user_name"] = account
	if !exempt {
		delete(answer, "enrollment")
		delete(answer, "warnings")
	}
	body, err := json.Marshal(answer)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func stubNoProfileResolve(t *testing.T, responses map[string][]byte) {
	t.Helper()
	previous := enterpriseIdentityViewGet
	t.Cleanup(func() { enterpriseIdentityViewGet = previous })
	enterpriseIdentityViewGet = func(path string, out any) (string, error) {
		u, err := url.Parse(path)
		if err != nil || u.Path != "/api/v1/guardrail/profiles/resolve" {
			return "", fmt.Errorf("unexpected profile resolve path %q: %v", path, err)
		}
		body, ok := responses[u.Query().Get("user")]
		if !ok {
			return "", fmt.Errorf("unexpected profile resolve account %q", u.Query().Get("user"))
		}
		return "", json.Unmarshal(body, out)
	}
}

func requiredSandboxRow(t *testing.T, sb *enterprisePolicySandbox, connector string) enterprisePolicySandboxRow {
	t.Helper()
	if sb == nil {
		t.Fatal("missing sandbox policy")
	}
	for _, row := range sb.Rows {
		if row.Check == "required" && row.Connector == connector {
			return row
		}
	}
	t.Fatalf("missing required row for %s: %+v", connector, sb.Rows)
	return enterprisePolicySandboxRow{}
}

func TestPolicySandboxDecodesNoProfileResolveExemption(t *testing.T) {
	previousGroups := enterpriseAccountGroups
	t.Cleanup(func() { enterpriseAccountGroups = previousGroups })
	enterpriseAccountGroups = func(int) ([]string, error) { return []string{"docker"}, nil }
	states := []enterprisepolicy.State{{Connector: "claudecode", Route: enterprisepolicy.RouteMachinePolicy, Covered: true}}
	for _, tc := range []struct {
		name, account string
		uid           int
		listed        []string
		gatewayExempt bool
		wantExempt    bool
	}{
		{"gateway directory name", "alice@corp.example", 2201, []string{`CORP\alice`}, true, true},
		{"non-exempt", "bob", 2202, []string{"alice"}, false, false},
		{"older gateway by uid", "carol", 2203, []string{"2203"}, false, true},
		{"older gateway by account name", "dave", 2204, []string{"dave"}, false, true},
		{"root", "root", 0, []string{"root", "0"}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &config.Config{DeploymentMode: string(config.DeploymentModeManagedEnterprise)}
			c.Enterprise.Profile = managed.ProfileStandalone
			c.OpenShell.Enabled = true
			c.OpenShell.Admin.RequiredFor = []string{"claudecode"}
			c.Enterprise.Enrollment.ExemptUsers = tc.listed
			if tc.name == "gateway directory name" && gateway.EnrollmentExemptFromSandbox(c.Enterprise.Enrollment, tc.uid, tc.account) {
				t.Fatal("directory-name case must need the gateway's verified facts")
			}
			stubNoProfileResolve(t, map[string][]byte{tc.account: noProfileResolveJSONFor(t, tc.account, tc.uid, tc.gatewayExempt)})
			sb := buildEnterprisePolicySandbox(c, "linux", tc.account, tc.uid, states)
			row := requiredSandboxRow(t, sb, "claudecode")
			if sb.EnrollmentExempt != tc.wantExempt || (row.State == sandboxRowWarn) != tc.wantExempt {
				t.Fatalf("sandbox exempt=%t, row=%+v, want exempt=%t", sb.EnrollmentExempt, row, tc.wantExempt)
			}
			if tc.wantExempt {
				if !strings.Contains(row.Detail, "required_for doesn't apply: a host run is allowed") || strings.Contains(row.Detail, "a host run is refused") {
					t.Fatalf("exempt row: %+v", row)
				}
			} else if !strings.Contains(row.Detail, "a host run is refused") {
				t.Fatalf("non-exempt row: %+v", row)
			}
		})
	}
}

// GAP-0555: `enterprise linux policy show --user ACCOUNT --connector
// claudecode` printed "enrollment: exempt" and, two lines below, "sandbox ok
// claudecode runs only in a sandbox; a host run is refused" for an account
// whose host Claude Code run the hook allowed. The row now comes from the
// hook's gate rule with the gateway's exemption answer.
func TestPolicyShowSandboxRowsOfAnExemptAccount(t *testing.T) {
	prevProfile, prevGroups := enterprisePolicySandboxProfile, enterpriseAccountGroups
	t.Cleanup(func() { enterprisePolicySandboxProfile, enterpriseAccountGroups = prevProfile, prevGroups })
	c := &config.Config{}
	c.OpenShell.Enabled = true
	c.Guardrail.Profiles = map[string]config.GuardrailProfile{"contractors": {Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"claudecode", "codex"}}}}
	const account = "contractor@corp.example"
	c.Enterprise.Enrollment.ExemptUsers = []string{account}
	var gatewayErr error
	enterprisePolicySandboxProfile = func(name string) (string, string, string, bool, error) {
		return "contractors", "group", `CORP\Contractors`,
			gateway.EnrollmentExemptFromSandbox(c.Enterprise.Enrollment, 2201, name), gatewayErr
	}
	enterpriseAccountGroups = func(int) ([]string, error) { return []string{"users"}, nil }
	states := []enterprisepolicy.State{
		{Connector: "claudecode", Route: enterprisepolicy.RouteMachinePolicy, Covered: true},
		{Connector: "codex", Route: enterprisepolicy.RoutePerUser},
	}
	rows := func(goos string) (*enterprisePolicySandbox, map[string]enterprisePolicySandboxRow) {
		sb := buildEnterprisePolicySandbox(c, goos, account, 2201, states)
		byCheck := map[string]enterprisePolicySandboxRow{}
		for _, r := range sb.Rows {
			byCheck[r.Check+" "+r.Connector] = r
		}
		return sb, byCheck
	}

	sb, byCheck := rows("linux")
	for _, conn := range []string{"claudecode", "codex"} {
		r := byCheck["required "+conn]
		if r.State != sandboxRowWarn || !strings.Contains(r.Detail, "exempt from enrollment") || !strings.Contains(r.Detail, "a host run is allowed") ||
			strings.Contains(r.Detail, "refused") {
			t.Errorf("exempt %s row = %+v", conn, r)
		}
		// The view says what the hook's own rule decides.
		if gateway.RequireSandboxHostGate([]string{"claudecode", "codex"}, conn, true) != gateway.RequireSandboxHostRunExempt {
			t.Fatalf("the gate refuses an exempt account's %s", conn)
		}
	}
	// Its required agents run on the host, so a missing docker group no
	// longer means they run nowhere.
	if !sb.EnrollmentExempt || sb.failed() {
		t.Errorf("exempt account: enrollment_exempt %t, failed %t: %+v", sb.EnrollmentExempt, sb.failed(), sb.Rows)
	}
	var out bytes.Buffer
	if err := writeEnterprisePolicyReport(&out, enterprisePolicyReport{User: &enterprisePolicyUserReport{User: account, Sandbox: sb}}); err != nil {
		t.Fatal(err)
	}
	if text := out.String(); strings.Contains(text, "a host run is refused") || !strings.Contains(text, "exempt from enrollment") {
		t.Errorf("policy show text:\n%s", text)
	}
	oldJSON := enterprisePolicyJSON
	enterprisePolicyJSON = true
	t.Cleanup(func() { enterprisePolicyJSON = oldJSON })
	out.Reset()
	if err := writeEnterprisePolicyReport(&out, enterprisePolicyReport{User: &enterprisePolicyUserReport{User: account, Sandbox: sb}}); err != nil {
		t.Fatal(err)
	}
	var doc enterprisePolicyReport
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.User == nil || doc.User.Sandbox == nil ||
		!doc.User.Sandbox.EnrollmentExempt || len(doc.User.Sandbox.Rows) == 0 ||
		!strings.Contains(doc.User.Sandbox.Rows[0].Detail, "host run is allowed") {
		t.Fatalf("policy show JSON: %v\n%s", err, out.String())
	}
	enterprisePolicyJSON = false
	if mac, macRows := rows("darwin"); !mac.EnrollmentExempt || macRows["required claudecode"].State != sandboxRowWarn {
		t.Errorf("macOS admin view: %+v", mac)
	}

	// A non-exempt account keeps the refusal rows.
	c.Enterprise.Enrollment.ExemptUsers = nil
	sb, byCheck = rows("linux")
	if r := byCheck["required claudecode"]; r.State != sandboxRowOK || !strings.Contains(r.Detail, "a host run is refused") {
		t.Errorf("non-exempt claudecode row = %+v", r)
	}
	if sb.EnrollmentExempt || !sb.failed() {
		t.Errorf("non-exempt account: enrollment_exempt %t, failed %t", sb.EnrollmentExempt, sb.failed())
	}
	c.Enterprise.Enrollment.ExcludeUsers = []string{account}
	if excluded, excludedRows := rows("linux"); excluded.EnrollmentExempt ||
		excludedRows["required claudecode"].State != sandboxRowOK ||
		!strings.Contains(unixEnrollmentExclusion(c.Enterprise.Enrollment, account, 2201), "exclude_users") {
		t.Errorf("excluded, non-exempt account: %+v", excluded)
	}
	c.Enterprise.Enrollment.ExcludeUsers = nil
	if mac, macRows := rows("darwin"); mac.EnrollmentExempt || macRows["required claudecode"].State != sandboxRowOK {
		t.Errorf("macOS non-exempt admin view: %+v", mac)
	}
	// A connector outside required_for and an empty required_for make no
	// host-run claim, even for an exempt account.
	c.Enterprise.Enrollment.ExemptUsers = []string{account}
	c.Guardrail.Profiles["contractors"] = config.GuardrailProfile{Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}}
	_, byCheck = rows("linux")
	if _, ok := byCheck["required claudecode"]; ok {
		t.Error("unlisted Claude Code got a required row")
	}
	c.Guardrail.Profiles["contractors"] = config.GuardrailProfile{Sandbox: &config.OpenShellAdminConfig{}}
	_, byCheck = rows("linux")
	if _, ok := byCheck["required codex"]; ok {
		t.Error("empty required_for got a required row")
	}
	c.Guardrail.Profiles["contractors"] = config.GuardrailProfile{Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"claudecode", "codex"}}}

	// Without the gateway's answer the account's uid or name decides, as
	// the hook socket matches them; root is never exempt.
	gatewayErr = errors.New("gateway down")
	c.Enterprise.Enrollment.ExemptUsers = []string{account, "root"}
	if sb, byCheck = rows("linux"); !sb.EnrollmentExempt || byCheck["required claudecode"].State != sandboxRowWarn {
		t.Errorf("gateway down, listed account: %+v", sb)
	}
	if sb := buildEnterprisePolicySandbox(c, "linux", "root", 0, states); sb.EnrollmentExempt {
		t.Errorf("root is exempt: %+v", sb)
	}
	// A failed gateway lookup must not leave an unverified exemption from
	// its partial response in the host-run answer.
	enterprisePolicySandboxProfile = func(string) (string, string, string, bool, error) {
		return "contractors", "group", "contractors", true, errors.New("gateway down")
	}
	if sb := buildEnterprisePolicySandbox(c, "linux", "other", 2202, states); sb.EnrollmentExempt {
		t.Errorf("gateway down, unlisted account: %+v", sb)
	}
}

// Root in exempt_users is not exempt: the hook socket answers root by
// enterprise.enrollment.root, so the enrollment line names that rule.
func TestUnixEnrollmentExclusionRootInExemptUsers(t *testing.T) {
	enrollment := config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"root", "0"}, ExcludeUsers: []string{"root"}, Root: config.EnterpriseRootDeny}
	got := unixEnrollmentExclusion(enrollment, "root", 0)
	if strings.Contains(got, "exempt") || !strings.Contains(got, "enterprise.enrollment.root (deny)") {
		t.Fatalf("root in exempt_users: %q", got)
	}
}

// The administrator's preview of what a registration's user sees says when
// exempt_users lifts required_for, as the managed gateway tells that user.
func TestRegistrationExplainOfAnExemptAccount(t *testing.T) {
	previousFloor := sandboxFloorFor
	t.Cleanup(func() { sandboxFloorFor = previousFloor })
	sandboxFloorFor = func(c *config.Config, _ string) (config.OpenShellAdminConfig, string, error) {
		return c.OpenShell.Admin, "sha256:fixture", nil
	}
	for _, tc := range []struct {
		name, account string
		uid           int
		listed        []string
		gatewayExempt bool
		wantExempt    bool
		gatewayCalls  int
	}{
		{"gateway directory name", "contractor@corp.example", 94404076, []string{`CORP\contractor`}, true, true, 1},
		{"non-exempt", "employee", 94404077, []string{`CORP\contractor`}, false, false, 1},
		{"root", "root", 0, []string{"root", "0"}, true, false, 0},
		{"older gateway local name", "local", 94404078, []string{"local"}, false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &config.Config{DeploymentMode: string(config.DeploymentModeManagedEnterprise)}
			c.Enterprise.Profile = managed.ProfileStandalone
			c.OpenShell.Enabled = true
			c.OpenShell.Admin.RequiredFor = []string{"claudecode"}
			c.Enterprise.Enrollment.ExemptUsers = tc.listed
			if tc.name == "gateway directory name" && gateway.EnrollmentExemptFromSandbox(c.Enterprise.Enrollment, tc.uid, tc.account) {
				t.Fatal("directory-name case must need the gateway's verified facts")
			}
			stubNoProfileResolve(t, map[string][]byte{tc.account: noProfileResolveJSONFor(t, tc.account, tc.uid, tc.gatewayExempt)})
			get := enterpriseIdentityViewGet
			calls := 0
			enterpriseIdentityViewGet = func(path string, out any) (string, error) {
				calls++
				return get(path, out)
			}
			e := explainRegistration(c, sandboxreg.Registration{ID: "r1", UID: tc.uid, UserName: tc.account})
			gate := gateway.RequireSandboxHostRunRefused
			if tc.wantExempt {
				gate = gateway.RequireSandboxHostRunExempt
			}
			if e.Managed == nil || e.Managed.EnrollmentExempt != tc.wantExempt || e.Managed.HostRunGate != gate ||
				e.Managed.HostRunRefused("claudecode") == tc.wantExempt || calls != tc.gatewayCalls {
				t.Fatalf("%s: preview %+v, gateway calls %d (want %d)", tc.name, e.Managed, calls, tc.gatewayCalls)
			}
		})
	}
}

// Exercise the command's real show path, including the --user selection and
// the renderer, not only the sandbox row builder used by show and verify.
func TestPolicyShowCommandReportsExemptHostRun(t *testing.T) {
	ctx := withEnterprisePolicyTree(t)
	if _, err := enterprisepolicy.Publish(ctx.opts, ctx.connectors); err != nil {
		t.Fatal(err)
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(current.Uid)
	if err != nil {
		t.Fatal(err)
	}
	previousConfig := cfg
	t.Cleanup(func() { cfg = previousConfig })
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.OpenShell.Enabled = true
	cfg.OpenShell.Admin.RequiredFor = []string{"claudecode"}
	cfg.Enterprise.Enrollment.ExemptUsers = []string{current.Username, current.Uid}
	responses := map[string][]byte{current.Username: noProfileResolveJSONFor(t, current.Username, uid, true)}
	stubNoProfileResolve(t, responses)
	_, show, _, _ := newEnterprisePolicyGroup("linux")
	if err := show.Flags().Set("user", current.Username); err != nil {
		t.Fatal(err)
	}
	if err := show.Flags().Set("connector", "claudecode"); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	show.SetOut(&output)
	if err := show.RunE(show, nil); err != nil {
		t.Fatal(err)
	}
	out := output.String()
	if !strings.Contains(out, "enrollment: exempt by enterprise.enrollment.exempt_users") ||
		!strings.Contains(out, "required_for doesn't apply: a host run is allowed") ||
		strings.Contains(out, "a host run is refused") {
		t.Fatalf("show --user --connector, uid %d:\n%s", uid, out)
	}
	cfg.Enterprise.Enrollment.ExemptUsers = nil
	responses[current.Username] = noProfileResolveJSONFor(t, current.Username, uid, false)
	output.Reset()
	if err := show.RunE(show, nil); err != nil {
		t.Fatal(err)
	}
	if out := output.String(); !strings.Contains(out, "a host run is refused") || strings.Contains(out, "required_for doesn't apply: a host run is allowed") {
		t.Fatalf("non-exempt show --user --connector, uid %d:\n%s", uid, out)
	}
}
