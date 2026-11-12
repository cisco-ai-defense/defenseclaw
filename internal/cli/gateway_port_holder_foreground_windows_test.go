// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

func TestGAP0694ForegroundGatewayHelper(t *testing.T) {
	if os.Getenv("DC_GAP0694_HELPER") == "1" {
		if ready := os.Getenv("DC_GAP0694_READY"); ready != "" {
			if err := os.WriteFile(ready, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(30 * time.Second)
	}
}

// startGAP0694Gateway starts a gateway stand-in from the copy named
// defenseclaw-gateway.exe, with the launch environment env, and returns once
// the stand-in runs its own code: a status check reads a gateway that listens,
// not a process the loader has not finished starting.
func startGAP0694Gateway(t *testing.T, path string, env []string) int {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	child := exec.Command(path, "-test.run=^TestGAP0694ForegroundGatewayHelper$")
	child.Env = append(env, "DC_GAP0694_HELPER=1", "DC_GAP0694_READY="+ready)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			return child.Process.Pid
		}
		if time.Now().After(deadline) {
			t.Fatal("the gateway stand-in did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// foregroundProofFailure explains a foreground proof that did not resolve:
// the read of the stand-in launch environment is the step that can fail
// for a reason other than the home.
func foregroundProofFailure(pid int) string {
	if _, err := agentprocess.LaunchEnvironmentForPID(pid); err != nil {
		return "launch environment read: " + err.Error()
	}
	return "launch environment read succeeded"
}

// gatewayCopyForGAP0694 is a copy of this test binary named
// defenseclaw-gateway.exe, in a temp dir of its own. It is a copy and not a
// hard link: a link names the file this very test process runs from, and a
// name of a running image cannot be deleted on Windows, so the temp dir
// cleanup failed with Access is denied. The stand-in is stopped by the
// cleanup startGAP0694Gateway registers later, which runs first; the copy is
// then removed here, retrying while the kernel still holds the image of a
// process that has just exited.
func gatewayCopyForGAP0694(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "defenseclaw-gateway.exe")
	copyExecutableForGAP0694(t, self, path)
	t.Cleanup(func() {
		deadline := time.Now().Add(20 * time.Second)
		for {
			err := os.Remove(path)
			if err == nil || os.IsNotExist(err) || time.Now().After(deadline) {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	return path
}

func copyExecutableForGAP0694(t *testing.T, from, to string) {
	t.Helper()
	source, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
}

func withoutEnv(env []string, names ...string) []string {
	var kept []string
	for _, entry := range env {
		drop := false
		for _, name := range names {
			if len(entry) > len(name) && strings.EqualFold(entry[:len(name)+1], name+"=") {
				drop = true
			}
		}
		if !drop {
			kept = append(kept, entry)
		}
	}
	return kept
}

// TestGAP0694WindowsForegroundGatewayUsesOwnerImageAndHome starts a gateway
// stand-in from a copy named defenseclaw-gateway.exe, with no gateway.pid:
// status must call it this account's gateway for the home in its own launch
// environment, and not for a different home, image or launch value. A
// runtime record in another home, copied or newly written, naming the live
// PID proves nothing about that home.
func TestGAP0694WindowsForegroundGatewayUsesOwnerImageAndHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	path := gatewayCopyForGAP0694(t)
	pid := startGAP0694Gateway(t, path, os.Environ())

	oldHolder, oldState, oldExecutable := gatewayPortHolder, gatewayManagedState, gatewayExecutable
	t.Cleanup(func() {
		gatewayPortHolder, gatewayManagedState, gatewayExecutable = oldHolder, oldState, oldExecutable
	})
	gatewayExecutable = func() (string, error) { return path, nil }
	gatewayManagedState = func() (bool, int) { return false, 0 }
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: pid, UID: -1}, nil
	}
	if !sameHomeGatewayProcess(pid, home) {
		t.Fatalf("foreground process proof did not resolve (%s)", foregroundProofFailure(pid))
	}
	if problem := foreignGatewayListener(config.DefaultConfig()); problem != "" {
		t.Fatalf("same-home foreground gateway reported foreign: %s", problem)
	}

	// A second private home must not borrow the first home's gateway, whether
	// its runtime record was copied from the first home or written afterwards
	// with the live PID, or has no record at all.
	other := t.TempDir()
	if sameHomeGatewayProcess(pid, other) {
		t.Fatal("a home without a runtime record matched the foreground gateway")
	}
	writeGatewayRuntimeRecordForTest(t, other, pid, 0o600)
	if sameHomeGatewayProcess(pid, other) {
		t.Fatal("a second home's private runtime record naming the live PID matched the foreground gateway")
	}
	writeGatewayRuntimeRecordForTest(t, home, pid, 0o600)
	copied, err := os.ReadFile(filepath.Join(home, "gateway-api.json"))
	if err != nil {
		t.Fatal(err)
	}
	third := t.TempDir()
	if err := os.WriteFile(filepath.Join(third, "gateway-api.json"), copied, 0o600); err != nil {
		t.Fatal(err)
	}
	if sameHomeGatewayProcess(pid, third) {
		t.Fatal("a copy of the first home's runtime record matched the foreground gateway")
	}
	if !sameHomeGatewayProcess(pid, home) {
		t.Fatal("the first home no longer matched")
	}
	if problem := foreignGatewayListener(config.DefaultConfig()); problem != "" {
		t.Fatalf("same-home foreground gateway with a runtime record reported foreign: %s", problem)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	otherImage := filepath.Join(t.TempDir(), "defenseclaw-gateway.exe")
	if err := os.WriteFile(otherImage, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if sameHomeGatewayProcessPlatform(pid, home, otherImage) {
		t.Fatal("a different gateway image matched the foreground gateway")
	}
	if !sameHomeGatewayProcessPlatform(pid, home, path) {
		t.Fatal("the gateway image no longer matched")
	}

	// Launch values that prove nothing: a relative home.
	relative := startGAP0694Gateway(t, path, append(withoutEnv(os.Environ(), "DEFENSECLAW_HOME"), "DEFENSECLAW_HOME=relative"))
	if sameHomeGatewayProcessPlatform(relative, home, path) || sameHomeGatewayProcessPlatform(relative, filepath.Join(home, "relative"), path) {
		t.Fatal("a relative launch home matched")
	}
}

// TestGAP0694WindowsForegroundGatewayOnDefaultHome is the benign twin: a
// gateway launched with no DEFENSECLAW_HOME runs on USERPROFILE's
// .defenseclaw, as config.DefaultDataPath names it.
func TestGAP0694WindowsForegroundGatewayOnDefaultHome(t *testing.T) {
	profile := t.TempDir()
	home := filepath.Join(profile, config.DefaultDataDirName)
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	path := gatewayCopyForGAP0694(t)
	pid := startGAP0694Gateway(t, path, append(withoutEnv(os.Environ(), "DEFENSECLAW_HOME", "USERPROFILE"), "USERPROFILE="+profile))
	if !sameHomeGatewayProcessPlatform(pid, home, path) {
		t.Fatalf("a gateway on the default home was not recognised (%s)", foregroundProofFailure(pid))
	}
	if sameHomeGatewayProcessPlatform(pid, t.TempDir(), path) {
		t.Fatal("a gateway on the default home matched another home")
	}
}

func TestGAP0694SameWindowsAccountComparesTokenUsers(t *testing.T) {
	own, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if !own.User.Sid.IsWellKnown(windows.WinLocalSystemSid) && !sameWindowsAccount(own.User.Sid, own.User.Sid) {
		t.Fatal("this account's own token user did not match")
	}
	if sameWindowsAccount(own.User.Sid, everyone) {
		t.Fatal("another SID matched this account")
	}
	if sameWindowsAccount(system, system) {
		t.Fatal("LocalSystem counted as a per-user account")
	}
	if sameWindowsAccount(nil, own.User.Sid) || sameWindowsAccount(own.User.Sid, nil) {
		t.Fatal("a missing SID matched")
	}
}
