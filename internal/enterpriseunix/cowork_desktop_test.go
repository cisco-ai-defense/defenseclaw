// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/codesig"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Claude Code is a machine-policy connector on Linux and macOS, so an
// account whose only Claude Code is Claude Desktop (Cowork) has no
// enrollment row, and its engine was trusted or not only while it ran:
// status showed the account nowhere (cowork-1-0-8 GAP-0031). The cowork
// block now lists every included account's Claude Desktop data folders, the
// newest engine build in each and its trust, from disk, as root only.
func TestDescribeCoworkListsEachIncludedAccountsClaudeDesktop(t *testing.T) {
	stubCoworkEligibleAccounts(t)
	old := coworkLastEvents
	coworkLastEvents = func(context.Context, string) ([]enterprisestatus.CoworkAccountEvent, bool, error) {
		return nil, false, nil
	}
	t.Cleanup(func() { coworkLastEvents = old })
	describe := func(h *testHost, goos string) *enterprisestatus.Result {
		result := enterprisestatus.New(ActionStatus, managed.ProfileStandalone, goos, "1.0.8")
		l := lifecycle{env: h.env, result: result, opts: Options{Action: ActionStatus}}
		block := map[string]enterprisestatus.ConnectorState{"claudecode": {Enabled: true, HooksInstalled: enterprisestatus.HooksInstalledAll}}
		l.describeCowork(&config.Config{}, DefaultConfig(h.env.Layout), block, &Deployment{MachinePolicyConnectors: []string{"claudecode"}}, nil)
		return result
	}
	mkdir := func(t *testing.T, h *testHost, canonical string) {
		t.Helper()
		if err := os.MkdirAll(h.env.P(canonical), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	eligible := `{"version":1,"accounts":[{"user":"ec2-user","uid":501,"gid":20,"home":"/Users/ec2-user"},{"user":"bob","uid":502,"gid":20,"home":"/Users/bob"}]}`

	h := newTestHost(t, "darwin")
	writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath), eligible)
	data1p := "/Users/ec2-user/Library/Application Support/Claude"
	data3p := "/Users/ec2-user/Library/Application Support/Claude-3p"
	mkdir(t, h, data1p) // a first-party folder with no engine build yet
	mkdir(t, h, "/Users/bob")
	var newest string
	for _, version := range []string{"2.1.309", "2.1.317"} {
		newest = filepath.Join(data3p, "claude-code", version, "91184d3d9ba3", "claude.app")
		writeHostFile(t, h, filepath.Join(newest, "Contents", "MacOS", "claude"), "engine")
		writeHostFile(t, h, filepath.Join(newest, "Contents", "Info.plist"), strings.Replace(desktopEnginePlist, "%s", version, 1))
	}
	fake := stubDesktopVerify(t, codesig.Result{Verified: true})
	result := describe(h, "darwin")
	want := &enterprisestatus.CoworkDesktopState{AccountsKnown: true, Trusted: 1, NotFound: 1, Accounts: []enterprisestatus.CoworkDesktopAccount{
		{Account: "bob"},
		{Account: "ec2-user", Installs: []enterprisestatus.CoworkDesktopInstall{
			{Deployment: "1p", Path: data1p, Trust: enterprisestatus.CoworkEngineNotFound},
			{Deployment: "3p", Path: data3p, EngineVersion: "2.1.317", EnginePath: newest, Trust: enterprisestatus.CoworkEngineTrusted},
		}},
	}}
	if got := result.Cowork.ClaudeDesktop; !reflect.DeepEqual(got, want) {
		t.Fatalf("claude_desktop = %+v, want %+v", got, want)
	}
	// Only the newest build is checked, by signature, as the account.
	if fake.calls != 1 || fake.path != h.env.P(newest) || fake.opts.UID != 501 || fake.opts.GID != 20 {
		t.Fatalf("signature checks = %+v", fake)
	}
	lines := strings.Join(enterprisestatus.CoworkLines(result.Cowork), "\n")
	for _, line := range []string{
		"  cowork bob: no Claude Desktop data folder",
		"  cowork ec2-user: Claude Desktop 1p (" + data1p + "), no engine build",
		"  cowork ec2-user: Claude Desktop 3p (" + data3p + "), engine 2.1.317 trusted",
	} {
		if !slices.Contains(strings.Split(lines, "\n"), line) {
			t.Fatalf("status lines miss %q:\n%s", line, lines)
		}
	}
	result.Finish("darwin", 0)
	contracttest.Compile(t).ValidateValue(t, "lifecycle-result.schema.json", result)

	for _, tc := range []struct {
		name   string
		result codesig.Result
		trust  string
	}{
		{"unsigned", codesig.Result{Reason: "code object is not signed at all", Unsigned: true}, enterprisestatus.CoworkEngineUnsigned},
		{"another signer", codesig.Result{Reason: "is not signed by Apple Developer ID team Q6L2SF6YDW"}, enterprisestatus.CoworkEngineUntrusted},
	} {
		fake.result = tc.result
		got := describe(h, "darwin").Cowork.ClaudeDesktop
		if install := got.Accounts[1].Installs[1]; install.Trust != tc.trust || !strings.Contains(install.Reason, tc.result.Reason) || got.Trusted != 0 {
			t.Fatalf("%s: claude_desktop = %+v", tc.name, got)
		}
	}

	// Not root: no account names and no codesign.
	h.env.Geteuid = func() int { return 501 }
	if got := describe(h, "darwin").Cowork; got == nil || got.ClaudeDesktop != nil {
		t.Fatalf("unprivileged cowork = %+v", got)
	}

	// Linux builds carry no vendor signature: a version folder alone is no
	// build, and a build with an executable engine is unsigned. Nothing is
	// run.
	h = newTestHost(t, "linux")
	writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath),
		`{"version":1,"accounts":[{"user":"dccw-u1","uid":1001,"gid":1001,"home":"/home/dccw-u1"}]}`)
	versionDir := "/home/dccw-u1/.config/Claude-3p/claude-code/2.1.317"
	mkdir(t, h, versionDir)
	fake = stubDesktopVerify(t, codesig.Result{Verified: true})
	got := describe(h, "linux").Cowork.ClaudeDesktop
	if got == nil || got.Unsigned != 0 || len(got.Accounts) != 1 || len(got.Accounts[0].Installs) != 1 ||
		got.Accounts[0].Installs[0] != (enterprisestatus.CoworkDesktopInstall{Deployment: "3p", Path: "/home/dccw-u1/.config/Claude-3p", EngineVersion: "2.1.317",
			EnginePath: versionDir, Trust: enterprisestatus.CoworkEngineUntrusted, Reason: "no executable claude engine in the 2.1.317 folder"}) {
		t.Fatalf("linux claude_desktop without an engine file = %+v", got)
	}
	engine := filepath.Join(versionDir, "a33aa5518497", "claude")
	writeHostFile(t, h, engine, "ELF")
	if err := os.Chmod(h.env.P(engine), 0o755); err != nil {
		t.Fatal(err)
	}
	got = describe(h, "linux").Cowork.ClaudeDesktop
	if got == nil || got.Unsigned != 1 || len(got.Accounts) != 1 || len(got.Accounts[0].Installs) != 1 || fake.calls != 0 ||
		got.Accounts[0].Installs[0] != (enterprisestatus.CoworkDesktopInstall{Deployment: "3p", Path: "/home/dccw-u1/.config/Claude-3p", EngineVersion: "2.1.317",
			EnginePath: engine, Trust: enterprisestatus.CoworkEngineUnsigned,
			Reason: "Linux engine builds carry no vendor signature, and the folder is the user's own"}) {
		t.Fatalf("linux claude_desktop = %+v (checks %d)", got, fake.calls)
	}
}

// stubCoworkEligibleAccounts reads the test host's eligible-accounts record
// without the root-owner checks an unprivileged test cannot meet.
func stubCoworkEligibleAccounts(t *testing.T) {
	t.Helper()
	old := coworkEligibleAccounts
	coworkEligibleAccounts = func(path string) ([]enterprisehooks.UnixEligibleAccount, error) {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var record struct {
			Accounts []enterprisehooks.UnixEligibleAccount `json:"accounts"`
		}
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, err
		}
		return record.Accounts, nil
	}
	t.Cleanup(func() { coworkEligibleAccounts = old })
}

// GAP-0031 review: under manifest enrollment (and with unenrolled_users
// deny) the eligible-accounts record is what the enumerator's last auto pass
// published, so an account the administrator has since left out of the
// manifest is not listed and gets no codesign run as it. Auto enrollment
// still lists every eligible account. The record itself is read through
// enterprisehooks.LoadUnixEligibleAccounts: a record that is not a
// root-owned 0600 file is refused and reported as unknown.
func TestDescribeCoworkDesktopKeepsOnlyManifestAccountsUnderManifestEnrollment(t *testing.T) {
	old := coworkLastEvents
	coworkLastEvents = func(context.Context, string) ([]enterprisestatus.CoworkAccountEvent, bool, error) {
		return nil, false, nil
	}
	t.Cleanup(func() { coworkLastEvents = old })
	h := newTestHost(t, "darwin")
	writeHostFile(t, h, enterprisehooks.UnixEligibleAccountsPath(h.env.Layout.ManifestPath),
		`{"version":1,"accounts":[{"user":"ec2-user","uid":501,"gid":20,"home":"/Users/ec2-user"},{"user":"bob","uid":502,"gid":20,"home":"/Users/bob"}]}`)
	var engines []string
	for _, home := range []string{"/Users/ec2-user", "/Users/bob"} {
		bundle := filepath.Join(home, "Library/Application Support/Claude-3p", "claude-code", "2.1.317", "91184d3d9ba3", "claude.app")
		writeHostFile(t, h, filepath.Join(bundle, "Contents", "MacOS", "claude"), "engine")
		writeHostFile(t, h, filepath.Join(bundle, "Contents", "Info.plist"), strings.Replace(desktopEnginePlist, "%s", "2.1.317", 1))
		engines = append(engines, h.env.P(bundle))
	}
	uid := 501
	disabled := false
	// bob's row is disabled: the administrator left him out.
	targets := []enterprisehooks.ManifestTarget{
		{Connector: "codex", User: "ec2-user", UserHome: "/Users/ec2-user", UID: &uid},
		{Connector: "codex", User: "bob", UserHome: "/Users/bob", Enabled: &disabled},
	}
	describe := func(cfg *config.Config) (*enterprisestatus.CoworkDesktopState, *fakeDesktopVerify) {
		t.Helper()
		fake := stubDesktopVerify(t, codesig.Result{Verified: true})
		claudeDesktopAccountGID = func(int) (uint32, bool) { return 20, true } // both accounts exist
		l := lifecycle{env: h.env, result: enterprisestatus.New(ActionStatus, managed.ProfileStandalone, "darwin", "1.0.8"), opts: Options{Action: ActionStatus}}
		return l.describeCoworkDesktop(context.Background(), cfg, targets), fake
	}
	accountsOf := func(state *enterprisestatus.CoworkDesktopState) []string {
		var names []string
		for _, account := range state.Accounts {
			names = append(names, account.Account)
		}
		return names
	}

	stubCoworkEligibleAccounts(t)
	for name, enrollment := range map[string]config.EnterpriseEnrollmentConfig{
		"manifest enrollment":   {Mode: config.EnterpriseEnrollmentManifest},
		"unenrolled users deny": {UnenrolledUsers: config.EnterpriseUnenrolledDeny},
	} {
		cfg := &config.Config{}
		cfg.Enterprise.Enrollment = enrollment
		state, fake := describe(cfg)
		if got := accountsOf(state); !state.AccountsKnown || !reflect.DeepEqual(got, []string{"ec2-user"}) {
			t.Fatalf("%s: accounts = %q (known %v), want only ec2-user", name, got, state.AccountsKnown)
		}
		if fake.calls != 1 || fake.path != engines[0] || fake.opts.UID != 501 {
			t.Fatalf("%s: codesign ran %d times, last %s as %d; want once, for ec2-user only", name, fake.calls, fake.path, fake.opts.UID)
		}
	}
	// Auto enrollment: every eligible account, as before.
	if state, fake := describe(&config.Config{}); !reflect.DeepEqual(accountsOf(state), []string{"bob", "ec2-user"}) || fake.calls != 2 {
		t.Fatalf("auto enrollment: accounts = %q, codesign calls %d", accountsOf(state), fake.calls)
	}

	// The real loader refuses this 0644 record of an unprivileged test:
	// nothing from it is listed, and the account list is not known.
	coworkEligibleAccounts = enterprisehooks.LoadUnixEligibleAccounts
	state, _ := describe(&config.Config{})
	if state.AccountsKnown || !reflect.DeepEqual(accountsOf(state), []string{"ec2-user"}) {
		t.Fatalf("refused record: accounts = %q (known %v), want only the manifest row and unknown", accountsOf(state), state.AccountsKnown)
	}
}
