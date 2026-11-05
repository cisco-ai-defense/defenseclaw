// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package enterpriseunix

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
)

func writeVersionProbeProcess(t *testing.T, h *testHost, pid, ppid, uid, start int, exe string, argv, environ []string) {
	t.Helper()
	dir := h.env.P(fmt.Sprintf("/proc/%d", pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeHostFile(t, h, fmt.Sprintf("/proc/%d/stat", pid),
		fmt.Sprintf("%d (process) S %d %d %s%d 0 0", pid, ppid, pid, strings.Repeat("0 ", 16), start))
	writeHostFile(t, h, fmt.Sprintf("/proc/%d/status", pid),
		fmt.Sprintf("Name:\tprocess\nUid:\t%d\t%d\t%d\t%d\n", uid, uid, uid, uid))
	writeHostFile(t, h, fmt.Sprintf("/proc/%d/cmdline", pid), strings.Join(argv, "\x00")+"\x00")
	writeHostFile(t, h, fmt.Sprintf("/proc/%d/environ", pid), strings.Join(environ, "\x00")+"\x00")
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
}

func versionProbeTestHost(t *testing.T) (*testHost, string, int) {
	t.Helper()
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.7"),
		ConfigFile: machinePolicyConfig(t, h, "hermes")}))
	h.publishLedger([]byte("ledger\n"))
	home := t.TempDir()
	uid := os.Getuid()
	h.runner.replies = map[string]fakeReply{
		"getent passwd " + strconv.Itoa(uid): {result: CommandResult{Stdout: []byte(fmt.Sprintf("probe:x:%d:%d::%s:/bin/sh\n", uid, os.Getgid(), home))}},
	}
	t.Cleanup(hermespath.OverrideAccountEnvironmentForTest(h.env.Root))
	return h, home, uid
}

func TestGAP0540ProbeLikeProcessesRemainReportable(t *testing.T) {
	const gateway = "/opt/defenseclaw/bin/defenseclaw-gateway"
	cases := []struct {
		name   string
		exe    string
		argv   []string
		before []string
		extra  []string
	}{
		{
			name: "python command with changed arguments",
			exe:  "/opt/hermes/bin/python3",
			argv: []string{"/opt/hermes/bin/python3", "-I", "-c",
				"import sys; from hermes_cli.main import main; sys.argv=['hermes']; main()", "--version"},
			extra: []string{"HERMES_SAFE_MODE=1"},
		},
		{
			name: "python command with relocated managed directory",
			exe:  "/opt/hermes/bin/python3",
			argv: []string{"/opt/hermes/bin/python3", "-I", "-c",
				"import hermes_cli; exec(open('/tmp/agent-session.py').read())", "--version"},
			extra: []string{"HERMES_MANAGED_DIR=/tmp/foreign"},
		},
		{
			name:  "Hermes executable with changed environment",
			exe:   "/home/probe/bin/hermes",
			argv:  []string{"/home/probe/bin/hermes", "--version"},
			extra: []string{"HERMES_SAFE_MODE=1"},
		},
		{
			name:   "duplicate home values",
			exe:    "/opt/hermes/bin/python3",
			argv:   []string{"/opt/hermes/bin/python3", "-I", "-c", "import hermes_cli", "--version"},
			before: []string{"HERMES_HOME=/tmp/foreign"},
		},
		{
			name: "plain version-shaped process",
			exe:  "/opt/hermes/bin/python3",
			argv: []string{"/opt/hermes/bin/python3", "-I", "-c", "import hermes_cli", "--version"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, home, uid := versionProbeTestHost(t)
			scratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
			if err != nil {
				t.Fatal(err)
			}
			writeVersionProbeProcess(t, h, 7201, 1, 0, 100, gateway,
				[]string{gateway, "enterprise", "hooks", "enumerate", "--manifest", "/etc/defenseclaw/hook-guardian/targets.yaml", "--interval", "5m"}, nil)
			writeVersionProbeProcess(t, h, 7202, 7201, uid, 200, gateway,
				[]string{gateway, "enterprise", "hooks", "apply-target"}, nil)
			env := append(append([]string{}, tc.before...), "HOME="+home, "HERMES_HOME="+scratch,
				"TMPDIR="+scratch, "DC_AGENT_VERSION_PROBE=hermes")
			env = append(env, tc.extra...)
			writeVersionProbeProcess(t, h, 7203, 7202, uid, 300, tc.exe, tc.argv, env)
			if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeManagedLaunchUninspected); got == "" {
				t.Error("running process omitted from launch coverage")
			}
			if err := hermespath.VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{}); err == nil {
				t.Error("running process omitted from account-home evidence")
			}
		})
	}
}

func TestGAP0540OrdinaryHermesSessionAllowed(t *testing.T) {
	h, home, uid := versionProbeTestHost(t)
	writeVersionProbeProcess(t, h, 7204, 1, uid, 400, "/opt/hermes/bin/hermes",
		[]string{"/opt/hermes/bin/hermes"}, []string{"HOME=" + home, "HERMES_HOME=" + filepath.Join(home, ".hermes")})
	if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeManagedLaunchUninspected); got != "" {
		t.Fatalf("ordinary Hermes session reported as uninspected: %s", got)
	}
	if err := hermespath.VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{}); err != nil {
		t.Fatalf("ordinary Hermes session reported as relocated: %v", err)
	}
}

func TestGAP0540VersionCommandInAccountHomeAllowed(t *testing.T) {
	h, home, uid := versionProbeTestHost(t)
	writeVersionProbeProcess(t, h, 7205, 1, uid, 500, "/opt/hermes/bin/python3",
		[]string{"/opt/hermes/bin/python3", "-I", "-c", "import hermes_cli", "--version"},
		[]string{"HOME=" + home, "TMPDIR=/tmp/hermes-version"})
	if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeManagedLaunchUninspected); got != "" {
		t.Fatalf("version command in account home reported as uninspected: %s", got)
	}
	if err := hermespath.VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{}); err != nil {
		t.Fatalf("version command in account home reported as relocated: %v", err)
	}
}

func TestGAP0540FinishedVersionProbeIsRescanned(t *testing.T) {
	h, home, uid := versionProbeTestHost(t)
	scratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
	if err != nil {
		t.Fatal(err)
	}
	const gateway = "/opt/defenseclaw/bin/defenseclaw-gateway"
	writeVersionProbeProcess(t, h, 7401, 1, 0, 100, gateway,
		[]string{gateway, "enterprise", "hooks", "enumerate", "--manifest", "/etc/defenseclaw/hook-guardian/targets.yaml", "--interval", "5m"}, nil)
	writeVersionProbeProcess(t, h, 7402, 7401, uid, 200, gateway,
		[]string{gateway, "enterprise", "hooks", "apply-target"}, nil)
	writeVersionProbeProcess(t, h, 7403, 7402, uid, 300, "/opt/hermes/bin/python3",
		[]string{"/opt/hermes/bin/python3", "-I", "-c", "from hermes_cli.main import main\nmain()", "--version"},
		[]string{"HOME=" + home, "PATH=/opt/hermes/bin:/usr/bin:/bin", "LANG=C", "NO_COLOR=1", "TERM=dumb", "CI=1",
			"HERMES_HOME=" + scratch, "TMPDIR=" + scratch, "DC_AGENT_VERSION_PROBE=hermes"})
	previous := waitManagedHermesVersion
	called := false
	waitManagedHermesVersion = func(_ string, pid int, _ string, _ time.Duration) bool {
		if pid != 7403 {
			t.Fatalf("waited for pid %d, want the version process", pid)
		}
		called = true
		if err := os.RemoveAll(h.env.P("/proc/7403")); err != nil {
			t.Fatal(err)
		}
		return true
	}
	t.Cleanup(func() { waitManagedHermesVersion = previous })
	if result := h.run(Options{Action: ActionVerify}); messagesOf(result.Errors, codeManagedLaunchUninspected) != "" {
		t.Fatalf("completed version process reported as a launch: %+v", result.Errors)
	}
	if !called {
		t.Fatal("version process was not checked before the final scan")
	}
	if err := hermespath.VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{}); err != nil {
		t.Fatalf("completed version process reported as account-home evidence: %v", err)
	}
}
