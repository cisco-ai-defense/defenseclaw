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

package enterpriseunix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scriptRunner records every command and answers it from a function.
type scriptRunner struct {
	calls  []string
	answer func(line string) (CommandResult, error)
}

func (s *scriptRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	line := filepath.Base(name) + " " + strings.Join(args, " ")
	s.calls = append(s.calls, line)
	if s.answer != nil {
		return s.answer(line)
	}
	return CommandResult{}, nil
}

func (s *scriptRunner) called(sub string) bool {
	for _, c := range s.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func opsHost(t *testing.T, goos string, answer func(string) (CommandResult, error)) (*commandUserOps, *scriptRunner, SandboxAccount) {
	t.Helper()
	h := newTestHost(t, goos)
	runner := &scriptRunner{answer: answer}
	h.env.Runner = runner
	home := "/home/alice"
	if goos == "darwin" {
		home = "/Users/alice"
	}
	return &commandUserOps{env: h.env}, runner, SandboxAccount{Name: "alice", UID: 1001, GID: 1001, Home: home}
}

func TestCommandOpsLinuxRunAsTheUser(t *testing.T) {
	status := `{"enabled":true,"running":2,"sandboxes":3,"managed":{"pending_restart":true}}`
	ops, runner, alice := opsHost(t, "linux", func(line string) (CommandResult, error) {
		switch {
		case strings.HasSuffix(line, "systemctl --user is-active defenseclaw-sandbox.service"):
			return CommandResult{Stdout: []byte("active\n")}, nil
		case strings.HasSuffix(line, "sandbox status --output json"):
			return CommandResult{Stdout: []byte(status)}, nil
		}
		return CommandResult{}, nil
	})
	st, err := ops.Status(context.Background(), alice)
	if err != nil || !st.Active || st.Running != 2 || !st.PendingRestart {
		t.Fatalf("Status = %+v %v", st, err)
	}
	// Every command runs as the account, with its home and runtime directory,
	// never as root with the account's name in the arguments.
	for _, call := range runner.calls {
		if !strings.HasPrefix(call, "runuser -u alice -- /usr/bin/env HOME=/home/alice XDG_RUNTIME_DIR=/run/user/1001 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus ") {
			t.Errorf("not run as the account: %s", call)
		}
	}
	if !runner.called(ops.env.launcherTarget() + " sandbox status --output json") {
		t.Errorf("the managed binary was not asked: %v", runner.calls)
	}

	// An inactive daemon is not asked: nothing runs.
	ops2, runner2, alice2 := opsHost(t, "linux", func(string) (CommandResult, error) {
		return CommandResult{ExitCode: 3, Stdout: []byte("inactive\n")}, errors.New("exit 3")
	})
	if st, err := ops2.Status(context.Background(), alice2); err != nil || st.Active || len(runner2.calls) != 2 || runner2.called("sandbox status") {
		t.Fatalf("inactive Status = %+v %v after %v", st, err, runner2.calls)
	}

	// A daemon that is not running while the account's OpenShell gateway unit
	// is: the gateway still hosts sandboxes, so the launcher is asked (it
	// starts the daemon, which counts them) and the count is reported.
	gatewayOnly := func(running string) func(string) (CommandResult, error) {
		return func(line string) (CommandResult, error) {
			switch {
			case strings.HasSuffix(line, "is-active defenseclaw-openshell-gateway.service"):
				return CommandResult{Stdout: []byte("active\n")}, nil
			case strings.HasSuffix(line, "is-active defenseclaw-sandbox.service"):
				return CommandResult{ExitCode: 3, Stdout: []byte("inactive\n")}, errors.New("exit 3")
			case strings.HasSuffix(line, "sandbox status --output json"):
				if running == "" {
					return CommandResult{}, errors.New("the daemon did not start")
				}
				return CommandResult{Stdout: []byte(`{"running":` + running + `}`)}, nil
			}
			return CommandResult{}, nil
		}
	}
	ops4, runner4, alice4 := opsHost(t, "linux", gatewayOnly("2"))
	if st, err := ops4.Status(context.Background(), alice4); err != nil || !st.Active || st.Running != 2 || !runner4.called("sandbox status --output json") {
		t.Fatalf("daemon down, gateway up: Status = %+v %v after %v", st, err, runner4.calls)
	}
	ops5, _, alice5 := opsHost(t, "linux", gatewayOnly(""))
	if _, err := ops5.Status(context.Background(), alice5); err == nil {
		t.Fatal("a gateway that runs without a daemon that answers reads as idle")
	}

	// A daemon that is active but does not answer is an error, which the
	// caller treats as running.
	ops3, _, alice3 := opsHost(t, "linux", func(line string) (CommandResult, error) {
		if strings.HasSuffix(line, "is-active defenseclaw-sandbox.service") {
			return CommandResult{Stdout: []byte("active\n")}, nil
		}
		return CommandResult{}, errors.New("timeout")
	})
	if _, err := ops3.Status(context.Background(), alice3); err == nil {
		t.Fatal("an unanswering daemon reads as idle")
	}
}

func TestCommandOpsLinuxStopAndTeardown(t *testing.T) {
	ops, runner, alice := opsHost(t, "linux", nil)
	if err := ops.Stop(context.Background(), alice, StopDaemon|StopGateway|StopSocket); err != nil {
		t.Fatal(err)
	}
	if !runner.called("/usr/bin/systemctl --user stop defenseclaw-sandbox.socket defenseclaw-sandbox.service defenseclaw-openshell-gateway.service") {
		t.Errorf("calls = %v", runner.calls)
	}
	runner.calls = nil
	if err := ops.Stop(context.Background(), alice, StopDaemon); err != nil || !runner.called("--user stop defenseclaw-sandbox.service") || runner.called("socket") {
		t.Errorf("daemon-only stop: %v %v", err, runner.calls)
	}
	runner.calls = nil
	if err := ops.Teardown(context.Background(), alice); err != nil || !runner.called(ops.env.launcherTarget()+" sandbox teardown --yes") || runner.called("--keep-images") {
		t.Errorf("purge teardown: %v %v", err, runner.calls)
	}
	runner.calls = nil
	if err := ops.Reload(context.Background(), alice); err != nil || !runner.called("--user daemon-reload") {
		t.Errorf("reload: %v %v", err, runner.calls)
	}
	// A user manager that is not running has nothing to stop.
	ops2, _, alice2 := opsHost(t, "linux", func(line string) (CommandResult, error) {
		if strings.Contains(line, " stop ") {
			return CommandResult{ExitCode: 1}, errors.New("Failed to connect to bus")
		}
		return CommandResult{ExitCode: 3, Stdout: []byte("inactive\n")}, errors.New("exit 3")
	})
	if err := ops2.Stop(context.Background(), alice2, StopDaemon); err != nil {
		t.Errorf("stopping an account without a user manager failed: %v", err)
	}
}

func TestCommandOpsMacOS(t *testing.T) {
	ops, runner, alice := opsHost(t, "darwin", func(line string) (CommandResult, error) {
		switch {
		case line == "launchctl print gui/1001":
			return CommandResult{}, errors.New("not found") // an ssh login only: the background domain
		case strings.HasPrefix(line, "launchctl print user/1001/com.cisco.defenseclaw.sandbox"):
			return CommandResult{Stdout: []byte("com.cisco.defenseclaw.sandbox = {\n\tstate = running\n}\n")}, nil
		case strings.HasSuffix(line, "sandbox status --output json"):
			return CommandResult{Stdout: []byte(`{"running":0}`)}, nil
		}
		return CommandResult{}, nil
	})
	st, err := ops.Status(context.Background(), alice)
	if err != nil || !st.Active || st.Running != 0 {
		t.Fatalf("Status = %+v %v", st, err)
	}
	if !runner.called("sudo -n -u alice -H /usr/bin/env HOME=/Users/alice " + ops.env.launcherTarget() + " sandbox status --output json") {
		t.Errorf("calls = %v", runner.calls)
	}
	runner.calls = nil
	if err := ops.Stop(context.Background(), alice, StopDaemon|StopGateway); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"launchctl bootout user/1001/com.cisco.defenseclaw.sandbox", "launchctl bootout user/1001/com.cisco.defenseclaw.openshell-gateway"} {
		if !runner.called(want) {
			t.Errorf("missing %q in %v", want, runner.calls)
		}
	}
	// An agent that is not loaded is stopped already.
	ops2, _, alice2 := opsHost(t, "darwin", func(line string) (CommandResult, error) {
		if strings.HasPrefix(line, "launchctl bootout") {
			return CommandResult{Stderr: []byte("Boot-out failed: 3: No such process")}, errors.New("exit 3")
		}
		return CommandResult{}, errors.New("not found")
	})
	if err := ops2.Stop(context.Background(), alice2, StopDaemon); err != nil {
		t.Errorf("stopping an agent that is not loaded failed: %v", err)
	}
}

func TestCommandOpsAccountsAreTheEnrolledAndTheRegistered(t *testing.T) {
	ops, _, _ := opsHost(t, "linux", func(line string) (CommandResult, error) {
		switch line {
		case "getent passwd 1002":
			return CommandResult{Stdout: []byte("bob:x:1002:1002:Bob:/home/bob:/bin/bash\n")}, nil
		case "getent passwd 1003":
			return CommandResult{Stdout: []byte("defenseclaw:x:1003:1003::/var/lib/defenseclaw:/usr/sbin/nologin\n")}, nil
		case "getent passwd 1004":
			return CommandResult{Stdout: []byte("../evil:x:1004:1004::/home/evil:/bin/sh\n")}, nil
		}
		return CommandResult{ExitCode: 2}, errors.New("not found")
	})
	e := ops.env
	dir := e.P(filepath.Join(e.Layout.DataDir, "sandbox", "registrations"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"1002.json", "1003.json", "1004.json", "0.json", "notes.txt", "9999.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	accounts := ops.Accounts(context.Background())
	if len(accounts) != 1 || accounts[0].Name != "bob" || accounts[0].Home != "/home/bob" {
		t.Fatalf("accounts = %+v, want only bob (the service account, a name with a path and unknown uids are left out)", accounts)
	}
}

func TestCommandOpsGroupsAndLoginctl(t *testing.T) {
	ops, _, alice := opsHost(t, "linux", func(line string) (CommandResult, error) {
		switch line {
		case "id -nG alice":
			return CommandResult{Stdout: []byte("alice docker wheel\n")}, nil
		case "loginctl list-users --no-legend":
			return CommandResult{Stdout: []byte("   0 root     no active\n1001 alice    yes active\n 999 defenseclaw no active\n")}, nil
		case "getent passwd 1001":
			return CommandResult{Stdout: []byte("alice:x:1001:1001::/home/alice:/bin/bash\n")}, nil
		}
		return CommandResult{ExitCode: 2}, errors.New("not found")
	})
	groups, err := ops.Groups(context.Background(), alice)
	if err != nil || !contains(groups, "docker") {
		t.Fatalf("groups = %v %v", groups, err)
	}
	in := ops.LoggedIn(context.Background())
	if len(in) != 1 || in[0].Name != "alice" {
		t.Fatalf("logged in = %+v", in)
	}
	macOps, _, _ := opsHost(t, "darwin", nil)
	if got := macOps.LoggedIn(context.Background()); got != nil {
		t.Errorf("macOS logged in = %v", got)
	}
}

// The files of an account are removed through descriptors that stop at a
// link, a folder of another account or another filesystem.
func TestRemoveBelowHomeStopsAtLinksAndForeignFolders(t *testing.T) {
	h := newTestHost(t, "linux")
	home := "/home/alice"
	a := SandboxAccount{Name: "alice", UID: os.Getuid(), GID: os.Getgid(), Home: home}
	root := h.env.P(home)
	outside := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, ".local", "state"), 0o755))
	must(os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0o644))
	// A link in the middle of the path.
	must(os.Symlink(outside, filepath.Join(root, ".local", "state", "defenseclaw-sandbox")))
	if removed, err := h.env.removeBelowHome(a, ".local/state/defenseclaw-sandbox/keep"); err == nil && removed {
		t.Error("a path through a link was followed")
	}
	if !exists(filepath.Join(outside, "keep")) {
		t.Fatal("the target of a link was removed")
	}
	// A link as the last component is removed itself, its target stays.
	if removed, err := h.env.removeBelowHome(a, ".local/state/defenseclaw-sandbox"); err != nil || !removed {
		t.Errorf("removing the link: %v %v", removed, err)
	}
	if !exists(filepath.Join(outside, "keep")) {
		t.Fatal("the target of the removed link went with it")
	}
	// A tree is removed with its files, a missing path is nothing.
	must(os.MkdirAll(filepath.Join(root, "a", "b", "c"), 0o755))
	must(os.WriteFile(filepath.Join(root, "a", "b", "c", "f"), []byte("x"), 0o644))
	if removed, err := h.env.removeBelowHome(a, "a/b"); err != nil || !removed || exists(filepath.Join(root, "a", "b")) || !exists(filepath.Join(root, "a")) {
		t.Errorf("tree: %v %v", removed, err)
	}
	if removed, err := h.env.removeBelowHome(a, "no/such/path"); err != nil || removed {
		t.Errorf("missing: %v %v", removed, err)
	}
	// Paths that leave the home are refused.
	for _, bad := range []string{"../etc", "/etc", "", ".", "a/../.."} {
		if _, err := h.env.removeBelowHome(a, bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	// A home another account owns is refused.
	other := a
	other.UID = a.UID + 4242
	if _, err := h.env.removeBelowHome(other, "a"); err == nil {
		t.Error("a home owned by another account was accepted")
	}
}

func TestSnapshotLinksRestoreSymlinks(t *testing.T) {
	h := newTestHost(t, "linux")
	e := h.env
	dir := e.P("/opt/links")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	present, absent, foreign := "/opt/links/present", "/opt/links/absent", "/opt/links/foreign"
	if err := os.Symlink("/old/target", e.P(present)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.P(foreign), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := e.takeSnapshot("links", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.snapshotLinks(snap, []string{foreign}); err == nil {
		t.Fatal("a regular file was accepted as a link")
	}
	if err := e.snapshotLinks(snap, []string{present, absent}); err != nil {
		t.Fatal(err)
	}
	// The transaction retargets one link and creates the other.
	if _, err := e.ensureSymlink(present, "/new/target"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ensureSymlink(absent, "/created"); err != nil {
		t.Fatal(err)
	}
	loaded, err := e.loadSnapshot(snap.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.checkBlobs(loaded); err != nil {
		t.Fatal(err)
	}
	if err := e.restore(loaded); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.Readlink(e.P(present)); got != "/old/target" {
		t.Errorf("present -> %q", got)
	}
	if _, err := os.Lstat(e.P(absent)); err == nil {
		t.Error("a link the transaction created stays after the restore")
	}
}

// GAP-0598: the non-purge uninstall stops the account's running sandboxes
// with the daemon unit's ExecStop, run as the account without the
// lifecycle's own INVOCATION_ID, and reads the names it stopped.
func TestCommandOpsStopSandboxes(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			ops, runner, alice := opsHost(t, goos, func(line string) (CommandResult, error) {
				if strings.HasSuffix(line, "sandbox-daemon stop-sandboxes") {
					return CommandResult{Stdout: []byte("stopped sandbox sb-a\nstopped sandbox sb-b\n")}, nil
				}
				return CommandResult{}, nil
			})
			stopped, err := ops.StopSandboxes(context.Background(), alice)
			if err != nil || strings.Join(stopped, ",") != "sb-a,sb-b" {
				t.Fatalf("StopSandboxes = %v, %v", stopped, err)
			}
			want := "/usr/bin/env -u INVOCATION_ID " + filepath.Join(ops.env.Layout.BinDir, binGateway) + " sandbox-daemon stop-sandboxes"
			as := "runuser -u alice -- /usr/bin/env HOME=/home/alice "
			if goos == "darwin" {
				as = "sudo -n -u alice -H /usr/bin/env HOME=/Users/alice "
			}
			if !runner.called(as) || !runner.called(want) {
				t.Errorf("calls = %v", runner.calls)
			}
		})
	}
	t.Run("a failure names its reason and keeps the names it stopped", func(t *testing.T) {
		ops, _, alice := opsHost(t, "linux", func(line string) (CommandResult, error) {
			return CommandResult{ExitCode: 1, Stdout: []byte("stopped sandbox sb-a\n"), Stderr: []byte("stop sb-b: the gateway did not answer\n")}, errors.New("exit 1")
		})
		stopped, err := ops.StopSandboxes(context.Background(), alice)
		if err == nil || !strings.Contains(err.Error(), "exited 1: stop sb-b: the gateway did not answer") || strings.Join(stopped, ",") != "sb-a" {
			t.Fatalf("StopSandboxes = %v, %v", stopped, err)
		}
	})
}
