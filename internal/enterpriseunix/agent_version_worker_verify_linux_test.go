// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package enterpriseunix

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprobe"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

const gap0540VerifyWorkerHome = "DC_GAP0540_VERIFY_WORKER_HOME"

func TestGAP0540VerifyWorkerHelper(t *testing.T) {
	home := os.Getenv(gap0540VerifyWorkerHome)
	if home == "" {
		t.Skip("helper process")
	}
	_, _ = enterprisehooks.DiscoverUnixAgentVersion(context.Background(), home, "hermes", true)
	t.Fatal("version discovery returned before the worker stopped")
}

func gap0540LiveProcess(pid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return false
	}
	fields := strings.Fields(string(stat[end+1:]))
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}

func gap0540ProcFields(t *testing.T, pid int) (string, []string, []string) {
	t.Helper()
	dir := fmt.Sprintf("/proc/%d", pid)
	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) []string {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 || data[len(data)-1] != 0 {
			t.Fatalf("%s has no final separator", name)
		}
		return strings.Split(string(data[:len(data)-1]), "\x00")
	}
	return exe, read("cmdline"), read("environ")
}

// The product's version command must not remain for Verify to classify after
// the apply worker that started it is stopped. The user-process control keeps
// the exact argv and environment captured while the product command ran.
func TestGAP0540VerifyAfterVersionWorkerStops(t *testing.T) {
	h, home, uid := gap0540RecoveredHost(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(home, "version.pid")
	command := filepath.Join(bin, "hermes")
	// Publish a complete marker: the reader may run between file creation
	// and the write when the build host is busy.
	program := fmt.Sprintf("#!%s\nimport os, time\nwith open(%q, 'w') as marker:\n marker.write(str(os.getpid()))\nos.replace(%q, %q)\ntime.sleep(60)\n",
		python, pidFile+".tmp", pidFile+".tmp", pidFile)
	if err := os.WriteFile(command, []byte(program), 0o700); err != nil {
		t.Fatal(err)
	}
	worker := exec.Command(os.Args[0], "-test.run=^TestGAP0540VerifyWorkerHelper$", "-test.count=1")
	worker.Env = append(os.Environ(), gap0540VerifyWorkerHome+"="+home)
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	workerReaped := false
	t.Cleanup(func() {
		if !workerReaped {
			_ = worker.Process.Kill()
			_ = worker.Wait()
		}
	})
	var pid int
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 1 {
			t.Fatalf("version pid: %q (%v)", data, err)
		}
		break
	}
	if pid <= 1 || !gap0540LiveProcess(pid) {
		t.Fatal("product version command did not start")
	}
	t.Cleanup(func() {
		if gap0540LiveProcess(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	exe, argv, environ := gap0540ProcFields(t, pid)
	if agentCLIOf(argv) != "hermes" {
		t.Fatalf("product command is not a Hermes session: %q", argv)
	}
	userPID := pid + 1
	gap0540WriteProcess(t, h, userPID, 1, uid, 301, exe, argv, environ)
	if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeManagedLaunchUninspected); got == "" {
		t.Fatal("same-argv user process was not reported")
	}
	if err := os.RemoveAll(h.env.P(fmt.Sprintf("/proc/%d", userPID))); err != nil {
		t.Fatal(err)
	}
	if err := worker.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = worker.Wait()
	workerReaped = true
	for deadline := time.Now().Add(time.Second); gap0540LiveProcess(pid) && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
	}
	if gap0540LiveProcess(pid) {
		gap0540WriteProcess(t, h, pid, 1, uid, 300, exe, argv, environ)
	}
	result := h.run(Options{Action: ActionVerify})
	if got := messagesOf(result.Errors, codeManagedLaunchUninspected); got != "" {
		t.Fatalf("Verify reported a product command after its worker stopped: %s", got)
	}
	if !result.OK {
		t.Fatalf("Verify did not recover: %+v", result.Errors)
	}
}

func TestGAP0540VerifierRecordsHermesIdentity(t *testing.T) {
	h, home, uid := gap0540RecoveredHost(t)
	gap0540WriteProcess(t, h, 9150, 1, uid, 500, "/opt/hermes/bin/python3",
		[]string{"/opt/hermes/bin/python3", "-I", "-c", "from hermes_cli.main import main", "--version"},
		[]string{"HOME=" + home, "HERMES_HOME=/tmp/other"})
	message := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeManagedLaunchUninspected)
	for _, field := range []string{"pid 9150", "parent pid 1", "started ", "image \"python3\"", "argv0 \"python3\"", "version argument true"} {
		if !strings.Contains(message, field) {
			t.Fatalf("verdict has no %q identity field: %s", field, message)
		}
	}
}

// The version child remains live during Verify while its apply worker is
// running. A shell launcher adds PWD and SHLVL before executing Python.
func TestGAP0540LiveWorkerShellVersionSettlesBeforeVerify(t *testing.T) {
	h, home, uid := versionProbeTestHost(t)
	scratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
	if err != nil {
		t.Fatal(err)
	}
	const gateway = "/opt/defenseclaw/bin/defenseclaw-gateway"
	gap0540WriteProcess(t, h, 9301, 1, 0, 100, gateway,
		[]string{gateway, "enterprise", "hooks", "enumerate", "--manifest", "/etc/defenseclaw/hook-guardian/targets.yaml", "--interval", "5m"}, nil)
	gap0540WriteProcess(t, h, 9302, 9301, uid, 200, gateway,
		[]string{gateway, "enterprise", "hooks", "apply-target"}, nil)
	argv := []string{"/opt/hermes/bin/python3", "-I", "-c", "from hermes_cli.main import main\nmain()", "--version"}
	env := []string{
		"HOME=" + home, "PATH=/opt/hermes/bin:/usr/bin:/bin", "LANG=C", "NO_COLOR=1", "TERM=dumb", "CI=1",
		"HERMES_HOME=" + scratch, "TMPDIR=" + scratch, agentprobe.EnvName + "=" + agentprobe.Hermes,
		"PWD=" + home, "SHLVL=0",
	}
	gap0540WriteProcess(t, h, 9303, 9302, uid, 300, "/opt/hermes/bin/python3", argv, env)
	previous := waitManagedHermesVersion
	called := false
	stop := make(chan struct{})
	done := make(chan error, 1)
	waitManagedHermesVersion = func(procRoot string, pid int, accountHome string, maxWait time.Duration) bool {
		if pid != 9303 {
			t.Fatalf("unexpected version process pid %d", pid)
		}
		called = true
		go func() {
			select {
			case <-time.After(time.Second):
				done <- os.RemoveAll(h.env.P("/proc/9303"))
			case <-stop:
				done <- nil
			}
		}()
		return agentprobe.WaitManagedHermesVersion(procRoot, pid, accountHome, maxWait)
	}
	t.Cleanup(func() { waitManagedHermesVersion = previous })
	result := h.run(Options{Action: ActionVerify})
	close(stop)
	if !called {
		t.Fatal("live version process was not checked")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	waitManagedHermesVersion = previous
	if got := messagesOf(result.Errors, codeManagedLaunchUninspected); got != "" {
		t.Fatalf("product version process was reported after it settled: %s", got)
	}
	gap0540WriteProcess(t, h, 9304, 1, uid, 400, "/opt/hermes/bin/python3", argv, env)
	result = h.run(Options{Action: ActionVerify})
	if got := messagesOf(result.Errors, codeManagedLaunchUninspected); got == "" {
		t.Fatal("same-command user process was omitted from verification")
	}
}
