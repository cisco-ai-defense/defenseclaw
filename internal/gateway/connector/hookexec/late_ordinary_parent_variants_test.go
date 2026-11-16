// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"os"
	osuser "os/user"
	"path/filepath"
	"testing"
)

// The OSS open tier of a late call allows an ordinary file reached by a parent
// step in every spelling and stays closed for a protected target.
func TestLateOrdinaryLookAllowsOrdinaryParentSpellings(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	plain := filepath.Join(root, "plain")
	child := filepath.Join(plain, "child")
	other := filepath.Join(root, "other")
	linkedChild := filepath.Join(other, "child")
	for _, dir := range []string{filepath.Join(home, ".ssh"), child, linkedChild} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, data := range map[string]string{
		filepath.Join(home, ".ssh", "authorized_keys"): "decoy",
		filepath.Join(plain, "status"):                 "ordinary",
		filepath.Join(other, "status"):                 "ordinary",
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(plain, "jump")
	if err := os.Symlink(linkedChild, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(plain, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, row := range []struct {
		name, cwd, command string
		wantOpen           bool
	}{
		{"plain parent", child, "cat ../status", true},
		{"plain parent dot prefix", child, "cat ./../status", true},
		{"plain parent file option", child, "grep --file=../status x", true},
		{"linked parent", link, "cat ../status", true},
		{"direct protected", plain, "cat ../home/.ssh/authorized_keys", false},
		{"protected link", plain, "cat keylink", false},
		{"protected link by a parent step", child, "cat ../keylink", false},
		{"protected known value", plain, `f="$HOME/.ssh/authorized_keys"; cat "$f"`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			opts := Options{
				Connector: "claudecode", Event: "PreToolUse", Home: home,
				FailMode: "open", OutageFailModeNow: func() string { return "open" },
				failurePayload: gap0641Payload(row.cwd, row.command),
			}
			if got := lateOrdinaryLook(opts); got != row.wantOpen {
				t.Errorf("late ordinary open=%v, want %v for %q", got, row.wantOpen, row.command)
			}
		})
	}
}

// The reader asks the protected files of every home the call can mean: a hard
// link to a protected file of the account home is not ordinary when the process
// reports another HOME.
func TestOrdinaryNoAnswerPayloadReadsEveryHome(t *testing.T) {
	root := t.TempDir()
	account := filepath.Join(root, "account")
	scratch := filepath.Join(root, "scratch")
	project := filepath.Join(root, "project")
	for _, dir := range []string{filepath.Join(account, ".ssh"), scratch, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(account, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("decoy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "plain.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(keys, filepath.Join(project, "alias")); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	for _, row := range []struct {
		name, command string
		homes         []string
		ordinary      bool
	}{
		{"alias, both homes", "cat alias", []string{scratch, account}, false},
		{"alias by absolute path, both homes", "cat " + filepath.Join(project, "alias"), []string{scratch, account}, false},
		{"alias, account home first", "cat alias", []string{account, scratch}, false},
		{"plain file, both homes", "cat plain.txt", []string{scratch, account}, true},
		{"plain file, one home listed twice", "cat plain.txt", []string{scratch, scratch}, true},
		{"no usable home", "cat plain.txt", []string{"relative"}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := ordinaryNoAnswerPayloadInHomes(gap0641Payload(project, row.command), row.homes); got != row.ordinary {
				t.Errorf("ordinary=%v, want %v", got, row.ordinary)
			}
		})
	}
}

// With the real account and a scratch HOME, neither reader may call a hard link
// to the account's own protected file ordinary. The account is only read: the
// link is made in a temporary folder and removed with it.
func TestProtectedAccountHomeHardLinkStaysClosedUnderAScratchHome(t *testing.T) {
	account, err := osuser.Current()
	if err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(account.HomeDir, ".ssh", "authorized_keys")
	if _, err := os.Stat(keys); err != nil {
		t.Skipf("account protected file unavailable: %v", err)
	}
	project := t.TempDir()
	alias := filepath.Join(project, "alias")
	if err := os.Link(keys, alias); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	t.Setenv("HOME", t.TempDir())
	for _, command := range []string{"cat alias", "cat " + alias} {
		payload := gap0641Payload(project, command)
		if OrdinaryNoAnswerPayload(payload) {
			t.Errorf("shared reader called the account's protected alias ordinary: %q", command)
		}
		opts := Options{Connector: "claudecode", Event: "PreToolUse", failurePayload: payload,
			OutageFailModeNow: func() string { return "open" }}
		if lateOrdinaryLook(opts) {
			t.Errorf("OSS open tier would allow the account's protected alias: %q", command)
		}
	}
}
