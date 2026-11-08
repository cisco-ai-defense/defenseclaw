// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func openCodeRecordWarnings(t *testing.T, env *Env) map[string]string {
	t.Helper()
	r := &enterprisestatus.Result{}
	env.warnOpenCodePortsRecord(r)
	codes := map[string]string{}
	for _, warning := range r.Warnings {
		codes[warning.Code] = warning.Message
	}
	return codes
}

// gas-ux-r1 GAP-0053, REVIEW-gx053-4/5 MF2: status and verify warn when the
// guardian's OpenCode ports record cannot be read; a non-root status that
// cannot open the guardian folder says it could not check, where OpenCode is
// on the machine policy.
func TestStatusWarnsOnAnUnreadableOpenCodePortsRecord(t *testing.T) {
	root := t.TempDir()
	env := &Env{GOOS: "linux", Root: root, Layout: mustLayout(t, "linux")}
	record := env.P(filepath.Join(env.Layout.GuardianAuthDir, enterprisehooks.UnixOpenCodeServicePortsFileName))
	if err := os.MkdirAll(filepath.Dir(record), 0o750); err != nil {
		t.Fatal(err)
	}
	previous := openCodePortsRecordGeteuid
	t.Cleanup(func() { openCodePortsRecordGeteuid = previous })
	openCodePortsRecordGeteuid = func() int { return 0 }

	if codes := openCodeRecordWarnings(t, env); len(codes) != 0 {
		t.Fatalf("no record: %v", codes)
	}
	if err := os.WriteFile(record, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if codes := openCodeRecordWarnings(t, env); codes["opencode_port_record_unreadable"] == "" {
		t.Fatalf("a corrupt record is not reported: %v", codes)
	}

	if os.Geteuid() == 0 {
		t.Skip("the non-root case needs a non-root test runner")
	}
	openCodePortsRecordGeteuid = func() int { return 1000 }
	folder := filepath.Dir(record)
	if err := os.Chmod(folder, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(folder, 0o750) })
	if codes := openCodeRecordWarnings(t, env); len(codes) != 0 {
		t.Fatalf("without OpenCode on the machine policy nothing is said: %v", codes)
	}
	plugin := env.P(filepath.Join(openCodePluginDir(env.Layout), "index.js"))
	if err := os.MkdirAll(filepath.Dir(plugin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plugin, []byte("//"), 0o644); err != nil {
		t.Fatal(err)
	}
	codes := openCodeRecordWarnings(t, env)
	if msg := codes["opencode_port_record_unchecked"]; msg == "" || !filepath.IsAbs(env.Layout.GuardianAuthDir) {
		t.Fatalf("a non-root status says nothing: %v", codes)
	}
}

// Status, verify (and doctor, from status) name each contested port, its
// claimants and the exact clear command.
func TestStatusNamesContestedOpenCodePorts(t *testing.T) {
	root := t.TempDir()
	env := &Env{GOOS: "linux", Root: root, Layout: mustLayout(t, "linux")}
	record := env.P(filepath.Join(env.Layout.GuardianAuthDir, enterprisehooks.UnixOpenCodeServicePortsFileName))
	if err := os.MkdirAll(filepath.Dir(record), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := loadOpenCodePortsRecord
	t.Cleanup(func() { loadOpenCodePortsRecord = previous })
	loadOpenCodePortsRecord = func(string) (enterprisehooks.UnixOpenCodeServicePortsState, error) {
		return enterprisehooks.UnixOpenCodeServicePortsState{Exists: true,
			Contested: []enterprisehooks.UnixOpenCodeContestedPort{{Port: 25003, UIDs: []int{1001, 1002}}}}, nil
	}
	msg := openCodeRecordWarnings(t, env)["opencode_port_contested"]
	for _, want := range []string{"port 25003", "uids 1001, 1002", "sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux opencode-port-clear 25003 --yes"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the contested line %q lacks %q", msg, want)
		}
	}
}

// The record unknown list is the last guardian pass snapshot. Status drops an
// entry only when the host proves the recorded account (name and uid) gone: a
// lookup miss alone is the answer for a live directory account too while the
// directory does not answer, and a name given to another uid no longer names
// the recorded account. An account that still exists keeps its entry with its
// own clear step.
func TestStatusDropsOpenCodePortUnknownEntriesOnlyOnProofTheAccountIsGone(t *testing.T) {
	unknown := func(uid int, user string) enterprisehooks.UnixOpenCodeServicePortUnknown {
		return enterprisehooks.UnixOpenCodeServicePortUnknown{UID: uid, User: user, Reason: "its home is not available",
			Path: "/home/" + user + "/.config/opencode/service.json", Fix: "clear " + user}
	}
	enumeratorState := func(t *testing.T, env *Env, state enterprisehooks.UnixEnumeratorState) {
		t.Helper()
		state.Version = 1
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		path := env.P(filepath.Join(filepath.Dir(env.Layout.ManifestPath), enumeratorStateFile))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name     string
		accounts AccountManager
		entry    enterprisehooks.UnixOpenCodeServicePortUnknown
		state    *enterprisehooks.UnixEnumeratorState
		fresh    bool // the fresh search-policy read says the account is gone
		reported bool
	}{
		{name: "deleted local account, enumerator saw it in the local database",
			entry: unknown(1001, "gone"), state: &enterprisehooks.UnixEnumeratorState{Sources: map[string]string{"gone": "files"}}},
		{name: "deleted account, enumerator counted a miss for the row",
			entry: unknown(1001, "gone"), state: &enterprisehooks.UnixEnumeratorState{Misses: map[string]int{"gone\x00opencode": 1}}},
		{name: "deleted account, fresh read of the search policy",
			entry: unknown(1001, "gone"), fresh: true},
		{name: "lookup miss alone: a live directory account while the directory does not answer",
			entry: unknown(1001, "gone"), reported: true},
		{name: "lookup miss, the enumerator saw the user only through a directory",
			entry: unknown(1001, "gone"), state: &enterprisehooks.UnixEnumeratorState{Sources: map[string]string{"gone": "directory"}}, reported: true},
		{name: "lookup fails",
			accounts: &failingAccounts{}, entry: unknown(1001, "kept"), state: &enterprisehooks.UnixEnumeratorState{Sources: map[string]string{"kept": "files"}}, reported: true},
		{name: "account exists with the recorded uid",
			entry: unknown(1002, "kept"), reported: true},
		{name: "deleted uid whose login name was given to another uid",
			entry: unknown(1001, "kept")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			previousGone, previousFresh, previousLoad := guardianAccountConfirmedGone, guardianFreshAccountRecordGone, loadOpenCodePortsRecord
			t.Cleanup(func() {
				guardianAccountConfirmedGone, guardianFreshAccountRecordGone, loadOpenCodePortsRecord = previousGone, previousFresh, previousLoad
			})
			guardianAccountConfirmedGone = func(string, int) bool { return tc.fresh }
			guardianFreshAccountRecordGone = func(context.Context, string) bool { return false }
			var accounts AccountManager = &fakeAccounts{accounts: map[string]Account{"kept": {Name: "kept", UID: 1002}}}
			if tc.accounts != nil {
				accounts = tc.accounts
			}
			env := &Env{GOOS: "linux", Root: t.TempDir(), Layout: mustLayout(t, "linux"), Accounts: accounts}
			record := env.P(filepath.Join(env.Layout.GuardianAuthDir, enterprisehooks.UnixOpenCodeServicePortsFileName))
			if err := os.MkdirAll(filepath.Dir(record), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(record, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.state != nil {
				enumeratorState(t, env, *tc.state)
			}
			loadOpenCodePortsRecord = func(string) (enterprisehooks.UnixOpenCodeServicePortsState, error) {
				return enterprisehooks.UnixOpenCodeServicePortsState{Exists: true, Unknown: []enterprisehooks.UnixOpenCodeServicePortUnknown{tc.entry}}, nil
			}
			msg := openCodeRecordWarnings(t, env)["opencode_port_account_unknown"]
			if tc.reported {
				want := fmt.Sprintf("%s (uid %d)", tc.entry.User, tc.entry.UID)
				if !strings.Contains(msg, want) || !strings.Contains(msg, tc.entry.Fix) {
					t.Fatalf("the entry is not reported with its clear step: %q", msg)
				}
			} else if msg != "" {
				t.Fatalf("an entry of an account the host proves gone is reported: %q", msg)
			}
		})
	}
}

// A gone account does not hide an account that still exists.
func TestStatusListsLiveOpenCodePortUnknownEntryBesideAGoneOne(t *testing.T) {
	previousGone, previousFresh, previousLoad := guardianAccountConfirmedGone, guardianFreshAccountRecordGone, loadOpenCodePortsRecord
	t.Cleanup(func() {
		guardianAccountConfirmedGone, guardianFreshAccountRecordGone, loadOpenCodePortsRecord = previousGone, previousFresh, previousLoad
	})
	guardianAccountConfirmedGone = func(user string, _ int) bool { return user == "gone" }
	guardianFreshAccountRecordGone = func(context.Context, string) bool { return false }
	env := &Env{GOOS: "linux", Root: t.TempDir(), Layout: mustLayout(t, "linux"),
		Accounts: &fakeAccounts{accounts: map[string]Account{"kept": {Name: "kept", UID: 1002}}}}
	record := env.P(filepath.Join(env.Layout.GuardianAuthDir, enterprisehooks.UnixOpenCodeServicePortsFileName))
	if err := os.MkdirAll(filepath.Dir(record), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	loadOpenCodePortsRecord = func(string) (enterprisehooks.UnixOpenCodeServicePortsState, error) {
		return enterprisehooks.UnixOpenCodeServicePortsState{Exists: true, Unknown: []enterprisehooks.UnixOpenCodeServicePortUnknown{
			{UID: 1001, User: "gone", Reason: "its home is not available", Path: "/home/gone/.config/opencode/service.json", Fix: "clear gone"},
			{UID: 1002, User: "kept", Reason: "not a regular file", Path: "/home/kept/.config/opencode/service.json", Fix: "clear kept"},
		}}, nil
	}
	msg := openCodeRecordWarnings(t, env)["opencode_port_account_unknown"]
	if !strings.Contains(msg, "kept (uid 1002)") || !strings.Contains(msg, "clear kept") || strings.Contains(msg, "gone") {
		t.Fatalf("a gone account must not be listed beside a live one: %q", msg)
	}
}

// failingAccounts is an account lookup that never answers.
type failingAccounts struct{ fakeAccounts }

func (*failingAccounts) Lookup(context.Context, string) (Account, bool, error) {
	return Account{}, false, errors.New("lookup failed")
}
