// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// shellInstallLockFunctions is the install-lock rule every shell hook
// carries: from defenseclaw_install_lock_held to defenseclaw_install_held.
func shellInstallLockFunctions(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("hooks", name))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start := strings.Index(text, "# defenseclaw_install_lock_held DATA returns 0 (true)")
	end := strings.Index(text, "# defenseclaw_install_held returns 0 (true)")
	if start < 0 || end < start {
		t.Fatalf("%s has no install-lock rule", name)
	}
	return text[start:end]
}

// oss-outage-open round i (stale lock class): the shell hooks closed every
// outage under any .install.lock, so a killed installer's lock closed a
// default-tier account's outages for good. Every shell hook now carries the
// same rule as hookexec installLockStale: only a lock whose installer is
// proven gone (its pid names no process, or one that started after the pid
// was written: a reused pid) is no lock; a live installer keeps it however
// long it runs (round j).
func TestShellHooksIgnoreAStaleInstallLock(t *testing.T) {
	want := shellInstallLockFunctions(t, "_hardening.sh")
	entries, err := os.ReadDir("hooks")
	if err != nil {
		t.Fatal(err)
	}
	copies := 0
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join("hooks", entry.Name()))
		if err != nil || !strings.HasSuffix(entry.Name(), ".sh") || !strings.Contains(string(raw), "defenseclaw_install_lock_held() {") {
			continue
		}
		copies++
		if got := shellInstallLockFunctions(t, entry.Name()); got != want {
			t.Errorf("%s carries another install-lock rule than _hardening.sh", entry.Name())
		}
	}
	if copies < 13 {
		t.Fatalf("found %d shell hooks with the install-lock rule, want every one (13)", copies)
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	exited := exec.Command("true")
	if err := exited.Run(); err != nil {
		t.Fatal(err)
	}
	dead := strconv.Itoa(exited.ProcessState.Pid())
	live := strconv.Itoa(os.Getpid())
	now := time.Now()
	past := strconv.FormatInt(now.Add(-time.Minute).Unix(), 10)
	for _, tc := range []struct {
		name          string
		pid, deadline string
		age, pidAge   time.Duration
		record        string
		held          bool
	}{
		{name: "installer exited", pid: dead + "\n", held: false},
		{name: "installer exited, Windows line end", pid: dead + "\r\n", held: false},
		{name: "installer running", pid: live + "\n", held: true},
		{name: "installer running, an earlier build's deadline passed", pid: live, deadline: past, held: true},
		{name: "installer running, made seven hours ago", pid: live, age: 7 * time.Hour, held: true},
		{name: "pid reused: its process started after the pid was written", pid: live, age: 7 * time.Hour, pidAge: 7 * time.Hour, held: false},
		{name: "1.0.2/1.0.3 PID-only lock, pid reused an hour after it was written (GAP-1465)", pid: live, age: time.Hour, pidAge: time.Hour, held: false},
		{name: "1.0.2/1.0.3 PID-only lock, pid reused", pid: live, age: 30 * 24 * time.Hour, pidAge: 30 * 24 * time.Hour, held: false},
		{name: "no pid yet", held: true},
		{name: "no pid for eleven minutes", age: 11 * time.Minute, held: false},
		{name: "pid not a number", pid: "abc", held: true},
		{name: "pid out of range, fresh", pid: "99999999999", held: true},
		{name: "interrupted install kept previous.new", pid: dead, record: "previous.new", held: true},
		{name: "interrupted install, an earlier build's deadline passed", pid: dead, record: "previous.new", deadline: past, held: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := t.TempDir()
			lock := filepath.Join(data, ".install.lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, value := range map[string]string{"pid": tc.pid, "deadline": tc.deadline} {
				if value != "" {
					if err := os.WriteFile(filepath.Join(lock, name), []byte(value), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc.pidAge > 0 {
				then := now.Add(-tc.pidAge)
				if err := os.Chtimes(filepath.Join(lock, "pid"), then, then); err != nil {
					t.Fatal(err)
				}
			}
			if tc.record != "" {
				if err := os.Mkdir(filepath.Join(data, tc.record), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.age > 0 {
				then := now.Add(-tc.age)
				if err := os.Chtimes(lock, then, then); err != nil {
					t.Fatal(err)
				}
			}
			script := want + "if defenseclaw_install_lock_held \"$1\"; then echo held; else echo none; fi\n"
			out, err := exec.Command(bash, "-c", script, "hook", data).CombinedOutput()
			if err != nil {
				t.Fatalf("bash: %v: %s", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != map[bool]string{true: "held", false: "none"}[tc.held] {
				t.Fatalf("defenseclaw_install_lock_held = %q, want held %v", got, tc.held)
			}
		})
	}
	for _, etime := range []struct{ text, seconds string }{
		{"05:23", "323"}, {"1:02:03", "3723"}, {"2-01:02:03", "176523"}, {"  08:09\n", "489"}, {"00:00", "0"},
		{"1:2:3:4", ""}, {"abc", ""}, {"", ""},
	} {
		t.Run("process age of ps etime "+strconv.Quote(etime.text), func(t *testing.T) {
			fake := t.TempDir()
			if err := os.WriteFile(filepath.Join(fake, "ps"), []byte("#!/bin/sh\nprintf '%s' \""+etime.text+"\"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			script := "PATH=" + fake + ":$PATH\n" + want + "defenseclaw_process_age 1 || echo none\n"
			out, _ := exec.Command(bash, "-c", script).CombinedOutput()
			got := strings.TrimSpace(string(out))
			if wanted := map[bool]string{true: "none", false: etime.seconds}[etime.seconds == ""]; got != wanted {
				t.Fatalf("defenseclaw_process_age of %q = %q, want %q", etime.text, got, wanted)
			}
		})
	}
	t.Run("lock that is a file", func(t *testing.T) {
		data := t.TempDir()
		if err := os.WriteFile(filepath.Join(data, ".install.lock"), []byte(dead), 0o600); err != nil {
			t.Fatal(err)
		}
		script := want + "defenseclaw_install_lock_held \"$1\" && echo held\n"
		if out, _ := exec.Command(bash, "-c", script, "hook", data).CombinedOutput(); strings.TrimSpace(string(out)) != "held" {
			t.Fatalf("a lock that is not a folder = %q, want held", out)
		}
	})
}
