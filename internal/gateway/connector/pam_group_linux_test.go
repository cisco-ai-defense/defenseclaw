// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// pamStackFixture points the PAM stack lookup at an empty temp tree: one stack
// directory and a pam.conf path that does not exist.
func pamStackFixture(t *testing.T) (dir, conf string) {
	t.Helper()
	root := t.TempDir()
	dir, conf = filepath.Join(root, "pam.d"), filepath.Join(root, "pam.conf")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	oldDirs, oldConf := privateGroupPAMStackDirs, privateGroupPAMConfFile
	privateGroupPAMStackDirs, privateGroupPAMConfFile = []string{dir, filepath.Join(root, "absent.d")}, conf
	t.Cleanup(func() { privateGroupPAMStackDirs, privateGroupPAMConfFile = oldDirs, oldConf })
	return dir, conf
}

// GAP-0905: the proof asks whether the PAM stack loads pam_group, never what
// its rule files say or where the module reads them from. Rounds 3 to 6 parsed
// group.conf and its vendor, local and module-chosen paths and each left one
// source out; here the rule files do not matter at all.
func TestPAMGroupLoadedReadsOnlyTheStackFiles(t *testing.T) {
	const stock = "auth required pam_unix.so\n@include common-account\n"
	for _, tc := range []struct {
		name  string
		files map[string]string
		conf  string
		want  bool
	}{
		{name: "no stack files", want: false},
		{name: "a stock stack", files: map[string]string{"login": stock, "sshd": stock}, want: false},
		{name: "the module loaded by name", files: map[string]string{"login": stock + "auth required pam_group.so\n"}, want: true},
		{name: "the module loaded by path", files: map[string]string{"su": "auth optional /lib/x86_64-linux-gnu/security/pam_group.so\n"}, want: true},
		{name: "the module with options after a tab", files: map[string]string{"sddm": "auth\toptional\tpam_group.so\tuse_first_pass\n"}, want: true},
		{name: "a commented line", files: map[string]string{"login": "# auth required pam_group.so\n" + stock}, want: false},
		{name: "an indented commented line", files: map[string]string{"login": "   #auth required pam_group.so\n"}, want: false},
		{name: "a trailing comment on another module", files: map[string]string{"login": "auth required pam_unix.so # pam_group.so later\n"}, want: false},
		{name: "pam.conf loads it", conf: "login auth required pam_group.so\n", want: true},
		{name: "pam.conf without it", conf: "login auth required pam_unix.so\n", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, conf := pamStackFixture(t)
			for name, content := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.conf != "" {
				if err := os.WriteFile(conf, []byte(tc.conf), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := pamGroupLoaded(); got != tc.want {
				t.Fatalf("pamGroupLoaded = %v, want %v", got, tc.want)
			}
		})
	}
}

// A link in a stack directory is read the way the PAM library reads it (many
// distributions link system-auth to a generated file); what cannot be read
// counts as loaded, so the answer never falls on the trusting side.
func TestPAMGroupLoadedFollowsLinksAndCountsWhatItCannotRead(t *testing.T) {
	dir, _ := pamStackFixture(t)
	target := filepath.Join(t.TempDir(), "generated")
	if err := os.WriteFile(target, []byte("auth required pam_unix.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "system-auth")); err != nil {
		t.Fatal(err)
	}
	if pamGroupLoaded() {
		t.Fatal("a link to a stock file counted as loading pam_group")
	}
	if err := os.WriteFile(target, []byte("auth required pam_group.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pamGroupLoaded() {
		t.Fatal("pam_group loaded through a link was not seen")
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if !pamGroupLoaded() {
		t.Fatal("a dangling link in the stack directory was taken as empty")
	}
	if err := os.Remove(filepath.Join(dir, "system-auth")); err != nil {
		t.Fatal(err)
	}
	if pamGroupLoaded() {
		t.Fatal("the stock layout stayed loaded after the link went away")
	}
	if err := os.Mkdir(filepath.Join(dir, "other.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if pamGroupLoaded() {
		t.Fatal("a subdirectory, which PAM never reads, counted as loading pam_group")
	}
	big := make([]byte, privateGroupPAMStackMaxBytes+1)
	if err := os.WriteFile(filepath.Join(dir, "huge"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	if !pamGroupLoaded() {
		t.Fatal("an oversize stack file was taken as empty")
	}
	if err := os.Remove(filepath.Join(dir, "huge")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if os.Geteuid() != 0 && !pamGroupLoaded() {
		t.Fatal("an unreadable stack directory was taken as empty")
	}
}

// The production stack locations are the three the PAM library reads, and the
// answer is the same whatever the rule files hold: the source of the rules is
// not part of the question.
func TestPAMGroupLoadedIgnoresRuleFiles(t *testing.T) {
	want := []string{"/etc/pam.d", "/usr/lib/pam.d", "/usr/share/pam.d"}
	for i, dir := range want {
		if i >= len(privateGroupPAMStackDirs) || privateGroupPAMStackDirs[i] != dir {
			t.Fatalf("stack directories %v, want %v", privateGroupPAMStackDirs, want)
		}
	}
	dir, _ := pamStackFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "login"), []byte("auth required pam_unix.so\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	security := filepath.Join(t.TempDir(), "security")
	if err := os.MkdirAll(filepath.Join(security, "group.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"group.conf", "group.d/devs.conf"} {
		if err := os.WriteFile(filepath.Join(security, name), []byte("*;*;*;Al0000-2400;devs\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if pamGroupLoaded() {
		t.Fatal("a rule file counted although no stack file loads the module")
	}
}
