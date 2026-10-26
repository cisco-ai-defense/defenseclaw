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
// proven gone (its pid names no process, or another process than its
// proc-start record names: a reused pid) is no lock; a live installer keeps
// it however long it runs (round j), and no clock is read (round k).
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
	// Round k (no clock): every row runs with the lock and its pid file dated
	// now, a week back and a week ahead (a wall-clock step either way).
	for _, tc := range []struct {
		name          string
		pid, deadline string
		record        string
		held          bool
	}{
		{name: "installer exited", pid: dead + "\n", held: false},
		{name: "installer exited, Windows line end", pid: dead + "\r\n", held: false},
		{name: "installer running", pid: live + "\n", held: true},
		{name: "installer running, an earlier build's deadline", pid: live, deadline: "1", held: true},
		// Without a proc-start record no clock may tell a reused pid from a
		// live owner: a 1.0.2/1.0.3 PID-only lock holds while its pid names
		// a process, on every system.
		{name: "1.0.2/1.0.3 PID-only lock, its pid names a process", pid: live, held: true},
		{name: "no pid", held: true},
		{name: "pid not a number", pid: "abc", held: true},
		{name: "pid out of range", pid: "99999999999", held: true},
		// GAP-1024: the record does not hold a lock whose installer is gone.
		{name: "interrupted install kept previous.new", pid: dead, record: "previous.new", held: false},
		{name: "interrupted install, an earlier build's deadline", pid: dead, record: "previous.new", deadline: "1", held: false},
	} {
		for _, step := range []time.Duration{0, -7 * 24 * time.Hour, 7 * 24 * time.Hour} {
			t.Run(tc.name+"/times "+step.String(), func(t *testing.T) {
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
				if tc.record != "" {
					if err := os.Mkdir(filepath.Join(data, tc.record), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if step != 0 {
					then := time.Now().Add(step)
					for _, path := range []string{filepath.Join(lock, "pid"), lock} {
						if err := os.Chtimes(path, then, then); err != nil && !os.IsNotExist(err) {
							t.Fatal(err)
						}
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
	}
	// Round l loop 1 (P2): an installer that exited but is not reaped (a
	// zombie) keeps its pid and its start; its lock is no lock, with its
	// proc-start record or without one.
	ended, endedIdentity := endedInstallerPid(t)
	for _, record := range []bool{true, false} {
		t.Run("installer exited, not reaped (zombie), record "+strconv.FormatBool(record), func(t *testing.T) {
			data := t.TempDir()
			lock := filepath.Join(data, ".install.lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(lock, "pid"), []byte(ended+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if record && endedIdentity != "" {
				if err := os.WriteFile(filepath.Join(lock, "proc-start"), []byte(endedIdentity+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			script := want + "if defenseclaw_install_lock_held \"$1\"; then echo held; else echo none; fi\n"
			out, err := exec.Command(bash, "-c", script, "hook", data).CombinedOutput()
			if err != nil {
				t.Fatalf("bash: %v: %s", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != "none" {
				t.Fatalf("defenseclaw_install_lock_held = %q for an exited, unreaped installer", got)
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
	// Loop round 2 (P2): a lock naming the hook's own pid is a reused pid.
	t.Run("lock names the hook's own pid", func(t *testing.T) {
		data := t.TempDir()
		if err := os.Mkdir(filepath.Join(data, ".install.lock"), 0o700); err != nil {
			t.Fatal(err)
		}
		script := want + "echo $$ > \"$1/.install.lock/pid\"\nif defenseclaw_install_lock_held \"$1\"; then echo held; else echo none; fi\n"
		if out, _ := exec.Command(bash, "-c", script, "hook", data).CombinedOutput(); strings.TrimSpace(string(out)) != "none" {
			t.Fatalf("a lock naming the hook's own pid = %q, want none (stale)", out)
		}
	})
	// Loop round 2 (P1) and round k: the proc-start record (the Linux boot id
	// and kernel start, the macOS creation second), compared as it is, tells
	// a live owner from a reused pid however the clock stepped (a pid file
	// written a week before stands in for the step), on Linux and macOS.
	for _, tc := range []struct {
		name   string
		reused bool
		held   bool
	}{
		{name: "live owner with its proc-start record, clock stepped", held: true},
		{name: "reused pid: another proc-start", reused: true, held: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identity, other := installLockIdentityOf(t, os.Getpid())
			if tc.reused {
				identity = other
			}
			data := t.TempDir()
			lock := filepath.Join(data, ".install.lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, value := range map[string]string{"pid": live + "\n", "proc-start": identity + "\n"} {
				if err := os.WriteFile(filepath.Join(lock, name), []byte(value), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			then := time.Now().Add(-7 * 24 * time.Hour)
			if err := os.Chtimes(filepath.Join(lock, "pid"), then, then); err != nil {
				t.Fatal(err)
			}
			script := want + "if defenseclaw_install_lock_held \"$1\"; then echo held; else echo none; fi\n"
			out, _ := exec.Command(bash, "-c", script, "hook", data).CombinedOutput()
			if got := strings.TrimSpace(string(out)); got != map[bool]string{true: "held", false: "none"}[tc.held] {
				t.Fatalf("defenseclaw_install_lock_held = %q, want held %v", got, tc.held)
			}
		})
	}
	t.Run("process identity matches the Go reader", func(t *testing.T) {
		identity, _ := installLockIdentityOf(t, os.Getpid())
		out, err := exec.Command(bash, "-c", want+"defenseclaw_process_identity \"$1\"", "hook", live).CombinedOutput()
		if err != nil || string(out) != identity {
			t.Fatalf("defenseclaw_process_identity = %q (%v), want %q", out, err, identity)
		}
	})
}
