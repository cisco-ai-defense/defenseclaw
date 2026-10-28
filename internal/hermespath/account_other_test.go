// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hermespath

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// GAP-2374: a directory account's home holds an @ (/home/alice@corp.example).
// The home the account's environment.d names was read as an unresolvable
// reference once $HOME was expanded, so Verify named no home, and a file
// that sets the resolved home failed Verify too. Only the value as written
// is checked for other references.
func TestVerifyAccountHomeResolvesTheEnvironmentOfADirectoryAccount(t *testing.T) {
	root := t.TempDir()
	system := filepath.Join(root, "system")
	t.Cleanup(OverrideAccountEnvironmentForTest(system))
	home := filepath.Join(root, "alice@corp.example")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	resolved := filepath.Join(home, ".hermes")
	work := filepath.Join(home, "work-hermes")
	file := filepath.Join(home, ".config", "environment.d", "10-hermes.conf")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"HERMES_HOME=$HOME/work-hermes\n", "HERMES_HOME=" + work + "\n", "HERMES_HOME=~/work-hermes\n"} {
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		err := VerifyAccountHome(home, resolved, time.Time{})
		if err == nil || !strings.Contains(err.Error(), "names the Hermes home "+work) {
			t.Errorf("%q: VerifyAccountHome = %v, want unproven naming %s", body, err, work)
		}
	}
	for _, body := range []string{"HERMES_HOME=$HOME/.hermes\n", "HERMES_HOME=" + resolved + "\n"} {
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := VerifyAccountHome(home, resolved, time.Time{}); err != nil {
			t.Errorf("%q: VerifyAccountHome = %v, want nil for the resolved home", body, err)
		}
	}
	for _, body := range []string{"HERMES_HOME=${XDG_DATA_HOME}/hermes\n", "HERMES_HOME DEFAULT=@{XDG_DATA_HOME}/hermes\n"} {
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := VerifyAccountHome(home, resolved, time.Time{}); err == nil || !strings.Contains(err.Error(), "cannot resolve") {
			t.Errorf("%q: VerifyAccountHome = %v, want a value a service cannot resolve", body, err)
		}
	}
}

// GAP-0499: on Linux and macOS the account's Hermes home is ~/.hermes only
// while nothing its processes start with sets HERMES_HOME elsewhere. The
// sign-in's environment files, the shell startup files and the environment
// of the account's running processes are read; a value that names another
// home, or that only the shell can evaluate, leaves the home unproven.
func TestVerifyAccountHomeReadsTheAccountsEnvironment(t *testing.T) {
	root := t.TempDir()
	system := filepath.Join(root, "system")
	t.Cleanup(OverrideAccountEnvironmentForTest(system))
	home := filepath.Join(root, "alice")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	resolved := filepath.Join(home, ".hermes")
	work := filepath.Join(home, "work-hermes")
	for _, tc := range []struct {
		name, file, body, want string
	}{
		{"environment.d", filepath.Join(home, ".config", "environment.d", "10-hermes.conf"), "HERMES_HOME=$HOME/work-hermes\n", work},
		{"environment.d braces", filepath.Join(home, ".config", "environment.d", "10-hermes.conf"), "HERMES_HOME=\"${HOME}/work-hermes\"\n", work},
		{"system environment.d", filepath.Join(system, "etc", "environment.d", "50-hermes.conf"), "HERMES_HOME=/srv/hermes\n", "/srv/hermes"},
		{"/etc/environment", filepath.Join(system, "etc", "environment"), "PATH=/usr/bin\nHERMES_HOME=/srv/hermes\n", "/srv/hermes"},
		{"pam_environment", filepath.Join(home, ".pam_environment"), "HERMES_HOME DEFAULT=@{HOME}/work-hermes\n", work},
		{"pam_environment assignment", filepath.Join(home, ".pam_environment"), "HERMES_HOME=" + work + "\n", work},
		{"an unresolvable reference", filepath.Join(home, ".config", "environment.d", "10-hermes.conf"), "HERMES_HOME=${XDG_DATA_HOME}/hermes\n", "cannot resolve"},
		{"a shell startup file", filepath.Join(home, ".bashrc"), "# HERMES_HOME is set below\nexport HERMES_HOME=~/work-hermes\n", "cannot resolve"},
		{"a system profile script", filepath.Join(system, "etc", "profile.d", "hermes.sh"), "export HERMES_HOME=/srv/hermes\n", "cannot resolve"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.MkdirAll(filepath.Dir(tc.file), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tc.file, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(tc.file) })
			err := VerifyAccountHome(home, resolved, time.Time{})
			if err == nil || !strings.Contains(err.Error(), "HERMES_HOME unproven") || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.file) {
				t.Fatalf("VerifyAccountHome = %v, want unproven naming %s and %q", err, tc.file, tc.want)
			}
		})
	}
	for name, body := range map[string]string{
		"the resolved home":      "HERMES_HOME=$HOME/.hermes\n",
		"a comment":              "# HERMES_HOME=/srv/hermes\n",
		"another variable":       "PATH=/usr/bin\nHERMES_HOME_BACKUP=/srv/old\n",
		"a commented shell line": "# export HERMES_HOME=/srv/hermes\n",
	} {
		file := filepath.Join(home, ".config", "environment.d", "10-hermes.conf")
		if strings.Contains(name, "shell") {
			file = filepath.Join(home, ".bashrc")
		}
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := VerifyAccountHome(home, resolved, time.Time{}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		_ = os.Remove(file)
	}
}

// A running process of the account that started with another HERMES_HOME
// (a shell rc export the sign-in files do not show) leaves the home
// unproven, and one of another account does not.
func TestVerifyAccountHomeReadsTheAccountsRunningProcesses(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("running process environments are read from /proc on Linux")
	}
	root := t.TempDir()
	system := filepath.Join(root, "system")
	t.Cleanup(OverrideAccountEnvironmentForTest(system))
	home := filepath.Join(root, "alice")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	process := filepath.Join(system, "proc", "4242")
	if err := os.MkdirAll(process, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(process, "comm"), []byte("hermes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(process, "environ"), []byte("PATH=/usr/bin\x00HERMES_HOME=/srv/hermes\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{})
	if err == nil || !strings.Contains(err.Error(), "running process 4242 (hermes)") || !strings.Contains(err.Error(), "/srv/hermes") {
		t.Fatalf("VerifyAccountHome = %v, want unproven naming the process", err)
	}
	if err := os.WriteFile(filepath.Join(process, "environ"), []byte("PATH=/usr/bin\x00HERMES_HOME="+filepath.Join(home, ".hermes")+"\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{}); err != nil {
		t.Fatalf("a process with the resolved home: %v", err)
	}
}

// A process environment too large to read can set any home, so it leaves
// the home unproven instead of being skipped.
func TestVerifyAccountHomeFailsOnAProcessEnvironmentTooLargeToRead(t *testing.T) {
	root := t.TempDir()
	system := filepath.Join(root, "system")
	t.Cleanup(OverrideAccountEnvironmentForTest(system))
	home := filepath.Join(root, "alice")
	process := filepath.Join(system, "proc", "4243")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(process, 0o700); err != nil {
		t.Fatal(err)
	}
	environ := append(bytes.Repeat([]byte("PAD=x\x00"), accountProcessEnvironLimit/6+1), []byte("HERMES_HOME=/srv/hermes\x00")...)
	if err := os.WriteFile(filepath.Join(process, "environ"), environ, 0o600); err != nil {
		t.Fatal(err)
	}
	err := VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{})
	if err == nil || !strings.Contains(err.Error(), "running process 4243") || !strings.Contains(err.Error(), "cannot resolve") {
		t.Fatalf("VerifyAccountHome = %v, want unproven naming the process", err)
	}
}

// The environment of a macOS kern.procargs2 buffer follows argc arguments;
// an argument that looks like a variable is not one.
func TestProcargs2Environment(t *testing.T) {
	buf := binary.LittleEndian.AppendUint32(nil, 2)
	buf = append(buf, "/opt/hermes/bin/hermes\x00\x00\x00\x00hermes\x00HERMES_HOME=/argument\x00PATH=/usr/bin\x00HERMES_HOME=/srv/hermes\x00\x00ptr_munge=\x00"...)
	got := procargs2Environment(buf)
	if len(got) != 2 || string(got[0]) != "PATH=/usr/bin" || string(got[1]) != "HERMES_HOME=/srv/hermes" {
		t.Fatalf("procargs2Environment = %q, want the two variables", got)
	}
	for name, buf := range map[string][]byte{
		"short":             {1, 0},
		"no path end":       append(binary.LittleEndian.AppendUint32(nil, 1), "/bin/sh"...),
		"too few arguments": append(binary.LittleEndian.AppendUint32(nil, 5), "/bin/sh\x00sh\x00"...),
	} {
		if got := procargs2Environment(buf); got != nil {
			t.Errorf("%s: procargs2Environment = %q, want none", name, got)
		}
	}
}

// GAP-0499 on macOS: a HERMES_HOME exported from a file ~/.zshrc sources,
// a terminal profile or an IDE is in no file the check reads, only in the
// environment of the processes it started. A running process of the
// account with another HERMES_HOME leaves the home unproven.
func TestVerifyAccountHomeReadsTheAccountsRunningProcessesOnMacOS(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("kern.procargs2 is read on macOS")
	}
	// The host's environment files and launchd domain are not read; its
	// processes are.
	previousRoot, previousLaunchd := accountSystemRoot, accountLaunchdHermesHome
	accountSystemRoot = filepath.Join(t.TempDir(), "system")
	accountLaunchdHermesHome = func(int) (string, error) { return "", nil }
	t.Cleanup(func() { accountSystemRoot, accountLaunchdHermesHome = previousRoot, previousLaunchd })
	home := filepath.Join(t.TempDir(), "alice")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(home, "work-hermes")
	// macOS withholds the environment of its own platform binaries
	// (/bin/sleep, /bin/zsh) even from root; Hermes, its Python and an IDE
	// are not ones.
	child := exec.Command(os.Args[0], "-test.run=^TestMacOSProcessHelper$")
	child.Env = []string{"PATH=/usr/bin:/bin", macOSProcessHelper + "=1", "HERMES_HOME=" + other}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	pid := "running process " + strconv.Itoa(child.Process.Pid) + " "
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{})
		if err != nil && strings.Contains(err.Error(), pid) && strings.Contains(err.Error(), other) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("VerifyAccountHome = %v, want unproven naming %s and %s", err, pid, other)
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	if err := VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{}); err != nil && strings.Contains(err.Error(), pid) {
		t.Fatalf("VerifyAccountHome after the process exited = %v", err)
	}
}

const macOSProcessHelper = "HERMESPATH_TEST_PROCESS_HELPER"

// TestMacOSProcessHelper is the running process of
// TestVerifyAccountHomeReadsTheAccountsRunningProcessesOnMacOS.
func TestMacOSProcessHelper(t *testing.T) {
	if os.Getenv(macOSProcessHelper) == "" {
		t.Skip("the running process of another test")
	}
	time.Sleep(time.Minute)
}
