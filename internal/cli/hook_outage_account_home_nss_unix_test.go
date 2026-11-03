// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rel-1-0-6 GAP-0308: release builds have no cgo, so on Linux os/user reads
// /etc/passwd only and an SSSD, AD or LDAP account had no home: every outage
// of a custom data_dir closed. nssAccountHome asks getent, at a fixed path,
// owned by the trusted account in a folder it owns, neither writable by
// others, with a fixed environment and a timeout, and takes only one passwd
// line for this uid whose absolute home exists and is owned by this uid.
// Every other answer is "" (the outage stays closed). The fake getent here
// is owned by the test account, which the test makes the trusted owner.
func TestNSSAccountHomeAsksAFixedTrustedGetent(t *testing.T) {
	uid := os.Getuid()
	me := strconv.Itoa(uid)
	home := t.TempDir()
	for _, tc := range []struct {
		name    string
		script  string
		mode    os.FileMode
		link    bool
		owner   int
		dirMode os.FileMode
		timeout time.Duration
		want    string
	}{
		{name: "one entry for this uid", script: "echo \"ad.user:*:" + me + ":100:AD User:" + home + ":/bin/bash\"", want: home},
		{name: "argument is passwd and this uid", script: "[ \"$1 $2\" = \"passwd " + me + "\" ] && echo \"u:*:" + me + ":1::" + home + ":/bin/sh\"", want: home},
		{name: "another uid", script: "echo \"u:*:" + strconv.Itoa(uid+1) + ":1::" + home + ":/bin/sh\"", want: ""},
		{name: "relative home", script: "echo \"u:*:" + me + ":1::home/u:/bin/sh\"", want: ""},
		{name: "unclean home", script: "echo \"u:*:" + me + ":1::" + home + "/../x:/bin/sh\"", want: ""},
		{name: "missing home", script: "echo \"u:*:" + me + ":1::" + home + "/none:/bin/sh\"", want: ""},
		{name: "two lines", script: "echo \"u:*:" + me + ":1::" + home + ":/bin/sh\"; echo \"u:*:" + me + ":1::" + home + ":/bin/sh\"", want: ""},
		{name: "short entry", script: "echo \"u:*:" + me + ":" + home + "\"", want: ""},
		{name: "lookup fails", script: "exit 2", want: ""},
		{name: "getent writable by others", script: "echo \"u:*:" + me + ":1::" + home + ":/bin/sh\"", mode: 0o757, want: ""},
		{name: "getent folder writable by others", script: "echo \"u:*:" + me + ":1::" + home + ":/bin/sh\"", dirMode: 0o777, want: ""},
		{name: "getent owned by another account", script: "echo \"u:*:" + me + ":1::" + home + ":/bin/sh\"", owner: uid + 1, want: ""},
		{name: "getent is a link", script: "echo \"u:*:" + me + ":1::" + home + ":/bin/sh\"", link: true, want: ""},
		{name: "hung lookup times out", script: "sleep 20", timeout: 300 * time.Millisecond, want: ""},
		// Review 3 P4 rows: each reaches the check it pins.
		{name: "home not owned by this uid", script: "echo \"u:*:" + me + ":1::/:/bin/sh\"", want: notRoot(uid, "")},
		// The padding is in the last (shell) field, so the line cut at 4 KiB
		// still has 7 fields and a valid home: only the size cap refuses it.
		{name: "answer over 4 KiB", script: "printf 'u:*:" + me + ":1::" + home + ":/bin/" + strings.Repeat("s", 5000) + "\\n'", want: ""},
		{name: "answers only under the fixed environment", script: "[ \"$PATH\" = /usr/bin:/bin ] && [ \"$LC_ALL\" = C ] && [ -z \"$HOME\" ] && [ \"$(pwd)\" = / ] && echo \"u:*:" + me + ":1::" + home + ":/bin/sh\"", want: home},
		{name: "home that exists but is not clean", script: "echo \"u:*:" + me + ":1::" + home + "/.:/bin/sh\"", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bin")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			real := filepath.Join(dir, "getent-real")
			mode := tc.mode
			if mode == 0 {
				mode = 0o755
			}
			if err := os.WriteFile(real, []byte("#!/bin/sh\n"+tc.script+"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(real, mode); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "getent")
			if tc.link {
				if err := os.Symlink(real, path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Rename(real, path); err != nil {
				t.Fatal(err)
			}
			if tc.dirMode != 0 {
				if err := os.Chmod(dir, tc.dirMode); err != nil {
					t.Fatal(err)
				}
			}
			owner := uid
			if tc.owner != 0 {
				owner = tc.owner
			}
			timeout := 2 * time.Second
			if tc.timeout != 0 {
				timeout = tc.timeout
			}
			oldPaths, oldOwner, oldTimeout := outageGetentPaths, outageGetentOwner, outageGetentTimeout
			outageGetentPaths = []string{filepath.Join(dir, "absent"), path}
			outageGetentOwner, outageGetentTimeout = owner, timeout
			t.Cleanup(func() { outageGetentPaths, outageGetentOwner, outageGetentTimeout = oldPaths, oldOwner, oldTimeout })
			t.Setenv("HOME", t.TempDir())
			t.Setenv("PATH", "/nonexistent:"+os.Getenv("PATH"))
			t.Setenv("LC_ALL", "en_US.UTF-8")
			start := time.Now()
			if got := nssAccountHome(uid); got != tc.want {
				t.Fatalf("nssAccountHome = %q, want %q", got, tc.want)
			}
			if time.Since(start) > 5*time.Second {
				t.Fatalf("lookup took %s", time.Since(start))
			}
		})
	}
	t.Run("no getent at any path", func(t *testing.T) {
		oldPaths := outageGetentPaths
		outageGetentPaths = []string{filepath.Join(t.TempDir(), "getent")}
		t.Cleanup(func() { outageGetentPaths = oldPaths })
		if got := nssAccountHome(uid); got != "" {
			t.Fatalf("nssAccountHome = %q, want empty", got)
		}
	})
}

// The real getent of a Linux host passes the trust checks and agrees with
// the account database for this account.
func TestNSSAccountHomeRealGetentAgreesWithTheAccountDatabase(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("getent fallback is Linux-only")
	}
	if _, err := os.Lstat("/usr/bin/getent"); err != nil {
		if _, err := os.Lstat("/bin/getent"); err != nil {
			t.Skip("no getent on this host")
		}
	}
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Skip("this account is not in /etc/passwd")
	}
	if got := nssAccountHome(os.Getuid()); got != filepath.Clean(account.HomeDir) {
		t.Fatalf("nssAccountHome = %q, want %q", got, account.HomeDir)
	}
}

// notRoot is want for a non-root test run; as root "/" is owned by the uid.
func notRoot(uid int, want string) string {
	if uid == 0 {
		return "/"
	}
	return want
}

// Review 3 P3: outageAccountHome is looked up once per process, so a
// decision that asks for it several times (stale hooks after a data_dir move
// ask about seven times) runs at most one lookup, and every part of the
// decision sees the same home.
func TestOutageAccountHomeIsLookedUpOncePerProcess(t *testing.T) {
	calls := 0
	account := t.TempDir()
	moved := t.TempDir()
	oldAccount, oldRoot := outageAccountHome, outageInstalledDataRoot
	outageAccountHome = newOutageAccountHome(func() string { calls++; return account })
	outageInstalledDataRoot = func() (string, bool) { return "", false }
	t.Cleanup(func() { outageAccountHome, outageInstalledDataRoot = oldAccount, oldRoot })
	t.Setenv("HOME", account)
	t.Setenv("DEFENSECLAW_HOME", "")
	t.Setenv("DEFENSECLAW_CONFIG", "")
	own := filepath.Join(account, ".defenseclaw")
	writeOutageNowConfig(t, own, "data_dir: "+moved+"\n"+outageNowDefaultConfig)
	mkdirAll(t, filepath.Join(own, "hooks"))
	mkdirAll(t, filepath.Join(moved, "hooks"))
	for i := 0; i < 3; i++ {
		if got := hookOutageFailModeNow("claudecode", filepath.Join(own, "hooks")); got != "open" {
			t.Fatalf("stale hooks = %q, want open", got)
		}
	}
	if calls != 1 {
		t.Fatalf("account home looked up %d times, want 1", calls)
	}
}
