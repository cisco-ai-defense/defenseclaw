// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enrollmentConfig is machinePolicyConfig with enterprise.enrollment lines
// (each indented four spaces).
func enrollmentConfig(t *testing.T, h *testHost, enrollment string, connectors ...string) string {
	t.Helper()
	body := string(DefaultConfig(h.env.Layout))
	const enterprise = "enterprise:\n  profile: standalone\n"
	if !strings.Contains(body, enterprise) {
		t.Fatal("default config has no standalone enterprise block")
	}
	body = strings.Replace(body, enterprise, enterprise+"  enrollment:\n"+enrollment, 1) + "  connectors:\n"
	for _, name := range connectors {
		body += "    " + name + ": {}\n"
	}
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// publishEnrollment writes the enumerator's manifest and eligible-accounts
// record: eligible and identity-only accounts by uid.
func publishEnrollment(t *testing.T, h *testHost, manifest string, eligible, identityOnly []int) {
	t.Helper()
	writeHostFile(t, h, h.env.Layout.ManifestPath, manifest)
	account := func(uid int) string {
		return fmt.Sprintf(`{"user":"u%d","uid":%d,"gid":%d,"home":"/Users/u%d"}`, uid, uid, uid, uid)
	}
	var accounts, identities []string
	for _, uid := range eligible {
		accounts = append(accounts, account(uid))
	}
	for _, uid := range identityOnly {
		identities = append(identities, account(uid))
	}
	record := enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath)
	writeHostFile(t, h, record, fmt.Sprintf(
		`{"version":1,"accounts":[%s],"identity_only":[%s]}`, strings.Join(accounts, ","), strings.Join(identities, ",")))
	// The enumerator publishes it root-owned 0600.
	if err := os.Chmod(h.env.P(record), 0o600); err != nil {
		t.Fatal(err)
	}
	h.owners[h.env.P(record)] = [2]int{0, 0}
}

// darwinOpenCodeSessions publishes OpenCode processes by pid and owner uid.
func darwinOpenCodeSessions(t *testing.T, h *testHost, argv map[int][]string, owners map[int]int, home string) {
	t.Helper()
	var lines []string
	for pid, uid := range owners {
		lines = append(lines, fmt.Sprintf("%d %d 00:00:05 %s", pid, uid, strings.Join(argv[pid], " ")))
	}
	slices.Sort(lines)
	h.runner.ps = strings.Join(lines, "\n")
	setDarwinProcessArgv(t, func(pid int) ([]string, error) {
		if args, ok := argv[pid]; ok {
			return args, nil
		}
		return nil, fmt.Errorf("no process %d", pid)
	})
	previous := darwinProcessEnv
	darwinProcessEnv = func(int) (map[string]string, error) { return map[string]string{"HOME": home}, nil }
	t.Cleanup(func() { darwinProcessEnv = previous })
}

func flaggedPIDs(warning string, pids ...int) []int {
	var out []int
	for _, pid := range pids {
		if strings.Contains(warning, fmt.Sprintf("(pid %d)", pid)) {
			out = append(out, pid)
		}
	}
	return out
}

// Only an enrolled account's launch is judged: an account that
// enterprise.enrollment excludes or exempts, or that no filter admits, is
// unprotected by design and must not fail a healthy deployment's verify or
// be audited as an uninspected session.
func TestManagedLaunchCoverageJudgesOnlyEnrolledAccounts(t *testing.T) {
	// alice is the test user, whose account and home resolve, so her
	// normal launch is provably inspected.
	alice := os.Getuid()
	current, err := user.Current()
	if alice == 0 || err != nil || !filepath.IsAbs(current.HomeDir) {
		t.Skip("needs a non-root test user with a home")
	}
	const bob, carol, dave, erin = 4102, 4103, 4104, 4105
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
		ConfigFile: enrollmentConfig(t, h, "    exclude_users: [\"4102\"]\n    exempt_users: [\"4104\"]\n", "opencode")}))
	// bob is still in the record the enumerator published before the
	// exclusion: the administrator's current decision wins.
	publishEnrollment(t, h, "version: 1\ntargets: []\n", []int{alice, bob}, []int{erin})
	h.publishLedger([]byte("ledger\n"))
	var audited []int
	h.env.ReportLaunchCoverage = func(_ context.Context, report managed.LaunchCoverageReport) error {
		audited = append(audited, report.PID)
		return nil
	}
	pure := []string{"opencode", "--pure"}

	// The reported scenario: alice runs OpenCode normally, the excluded bob
	// with --pure.
	darwinOpenCodeSessions(t, h, map[int][]string{7401: {"opencode"}, 7402: pure},
		map[int]int{7401: alice, 7402: bob}, current.HomeDir)
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		if warning := messagesOf(result.Warnings, codeManagedLaunchUninspected); warning != "" {
			t.Fatalf("%s judged an excluded account's launch: %s", action, warning)
		}
		requireOK(t, result)
		if !result.CoverageComplete || !result.SecurityComplete {
			t.Fatalf("%s lowered health for an excluded account: %+v", action, result)
		}
	}
	if len(audited) != 0 {
		t.Fatalf("excluded account's launch was audited: %v", audited)
	}

	all := []int{7401, 7402, 7403, 7404, 7405}
	darwinOpenCodeSessions(t, h, map[int][]string{7401: pure, 7402: pure, 7403: pure, 7404: pure, 7405: pure},
		map[int]int{7401: alice, 7402: bob, 7403: carol, 7404: dave, 7405: erin}, current.HomeDir)
	check := func(phase string, want []int) {
		t.Helper()
		audited = nil
		for _, action := range []string{ActionStatus, ActionVerify} {
			result := h.run(Options{Action: action})
			warning := messagesOf(result.Warnings, codeManagedLaunchUninspected)
			if got := flaggedPIDs(warning, all...); !slices.Equal(got, want) || result.CoverageComplete || result.SecurityComplete {
				t.Fatalf("%s %s flagged %v, want %v: %+v", phase, action, got, want, result)
			}
			if action == ActionVerify {
				requireError(t, result, codeManagedLaunchUninspected)
			}
		}
		slices.Sort(audited)
		var wantAudit []int
		for _, pid := range want {
			wantAudit = append(wantAudit, pid, pid)
		}
		if !slices.Equal(audited, wantAudit) {
			t.Fatalf("%s audited %v, want %v", phase, audited, wantAudit)
		}
	}
	// Eligible and identity-only accounts are enrolled; carol, outside every
	// filter, is not; bob is excluded and dave exempt.
	check("published enrollment", []int{7401, 7405})
	// An unreadable record cannot prove anyone unenrolled, but the
	// administrator's exclusions still apply.
	if err := os.Remove(h.env.P(enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath))); err != nil {
		t.Fatal(err)
	}
	check("record unreadable", []int{7401, 7403, 7405})
}

// The Linux process owner is the kernel's: the same launch is judged or not
// by the account's enrollment alone.
func TestManagedLaunchCoverageLinuxOwnerEnrollment(t *testing.T) {
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("the fixture process is owned by the test user; root is never judged")
	}
	for _, tc := range []struct {
		name, enrollment string
		eligible         []int
		manifest         string
		want             bool
	}{
		{name: "eligible", enrollment: "    unenrolled_users: inspect\n", eligible: []int{uid}, manifest: "version: 1\ntargets: []\n", want: true},
		{name: "not admitted", enrollment: "    unenrolled_users: inspect\n", eligible: []int{uid + 1}, manifest: "version: 1\ntargets: []\n"},
		{name: "excluded by uid", enrollment: fmt.Sprintf("    exclude_users: [\"%d\"]\n", uid), eligible: []int{uid}, manifest: "version: 1\ntargets: []\n"},
		{name: "exempt by uid", enrollment: fmt.Sprintf("    exempt_users: [\"%d\"]\n", uid), eligible: []int{uid}, manifest: "version: 1\ntargets: []\n"},
		{name: "manifest unreadable", enrollment: "    unenrolled_users: inspect\n", eligible: []int{uid + 1}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"),
				ConfigFile: enrollmentConfig(t, h, tc.enrollment, "opencode")}))
			if tc.manifest != "" {
				publishEnrollment(t, h, tc.manifest, tc.eligible, nil)
			} else {
				publishEnrollment(t, h, "version: 1\ntargets: []\n", tc.eligible, nil)
				if err := os.Remove(h.env.P(h.env.Layout.ManifestPath)); err != nil {
					t.Fatal(err)
				}
			}
			h.publishLedger([]byte("ledger\n"))
			h.env.ReportLaunchCoverage = func(context.Context, managed.LaunchCoverageReport) error { return nil }
			const pid = 7411
			writeHostFile(t, h, "/proc/stat", fmt.Sprintf("btime %d\n", time.Now().Unix()))
			writeHostFile(t, h, fmt.Sprintf("/proc/%d/cmdline", pid), "opencode\x00--pure\x00")
			writeHostFile(t, h, fmt.Sprintf("/proc/%d/environ", pid), "HOME=/home/ubuntu\x00")
			writeHostFile(t, h, fmt.Sprintf("/proc/%d/stat", pid),
				fmt.Sprintf("%d (opencode) S 1 %d %s1000 0 0", pid, pid, strings.Repeat("0 ", 16)))
			result := h.run(Options{Action: ActionVerify})
			warning := messagesOf(result.Warnings, codeManagedLaunchUninspected)
			if got := strings.Contains(warning, fmt.Sprintf("(pid %d)", pid)); got != tc.want {
				t.Fatalf("judged=%t, want %t: %+v", got, tc.want, result)
			}
		})
	}
}

// Under manifest enrollment the manifest names the enrolled accounts, by
// uid, user or home; the idle enumerator's record is stale.
func TestManagedLaunchEnrollmentReadsManifestTargets(t *testing.T) {
	h := newTestHost(t, "darwin")
	publishEnrollment(t, h, `version: 1
targets:
  - uid: 4201
    user: alice
    user_home: /Users/alice
    connector: opencode
  - user: frank
    connector: opencode
  - user_home: /Users/gina
    connector: opencode
  - uid: 4204
    user: hank
    user_home: /Users/hank
    connector: opencode
    enabled: false
`, []int{4205}, nil)
	account := func(user, home string) func() (string, string) {
		return func() (string, string) { return user, home }
	}
	cfg := &config.Config{}
	cfg.Enterprise.Enrollment.Mode = config.EnterpriseEnrollmentManifest
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{"ivan"}
	e := h.env.launchEnrollment(cfg)
	for _, tc := range []struct {
		name       string
		uid        int
		user, home string
		want       bool
	}{
		{"target uid", 4201, "uid 4201", "", true},
		{"target user", 4202, "frank", "/Users/frank", true},
		{"target home", 4203, "uid 4203", "/Users/gina", true},
		{"disabled row", 4204, "hank", "/Users/hank", false},
		{"stale record", 4205, "u4205", "/Users/u4205", false},
		{"excluded by name", 4201, "ivan", "/Users/ivan", false},
	} {
		if got := e.covers(tc.uid, account(tc.user, tc.home)); got != tc.want {
			t.Errorf("manifest mode %s: covers = %t, want %t", tc.name, got, tc.want)
		}
	}
	cfg.Enterprise.Enrollment.Mode = config.EnterpriseEnrollmentAuto
	if e := h.env.launchEnrollment(cfg); !e.covers(4205, account("u4205", "")) || e.covers(4206, account("u4206", "")) {
		t.Fatal("auto enrollment ignored the eligible-accounts record")
	}
	if err := os.Remove(h.env.P(h.env.Layout.ManifestPath)); err != nil {
		t.Fatal(err)
	}
	if e := h.env.launchEnrollment(cfg); !e.covers(4206, account("u4206", "")) || e.covers(4206, account("ivan", "")) {
		t.Fatal("an unreadable manifest must judge every account but the excluded ones")
	}
}
