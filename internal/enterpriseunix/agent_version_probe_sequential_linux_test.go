// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package enterpriseunix

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprobe"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
)

func TestGAP0540SequentialVersionProbesDoNotBlockLaunchVerify(t *testing.T) {
	h, home, uid := versionProbeTestHost(t)
	scratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
	if err != nil {
		t.Fatal(err)
	}
	retryScratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
	if err != nil {
		t.Fatal(err)
	}
	const gateway = "/opt/defenseclaw/bin/defenseclaw-gateway"
	writeVersionProbeProcess(t, h, 8201, 1, 0, 100, gateway,
		[]string{gateway, "enterprise", "hooks", "enumerate", "--manifest", "/etc/defenseclaw/hook-guardian/targets.yaml", "--interval", "5m"}, nil)
	writeVersionProbeProcess(t, h, 8202, 8201, uid, 200, gateway,
		[]string{gateway, "enterprise", "hooks", "apply-target"}, nil)
	argv := []string{"/usr/bin/python3", home + "/.local/bin/hermes", "--version"}
	env := []string{"HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C", "NO_COLOR=1", "TERM=dumb", "CI=1",
		"HERMES_HOME=" + scratch, "TMPDIR=" + scratch, "DC_AGENT_VERSION_PROBE=hermes"}
	retryEnv := []string{"HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C", "NO_COLOR=1", "TERM=dumb", "CI=1",
		"HERMES_HOME=" + retryScratch, "TMPDIR=" + retryScratch, "DC_AGENT_VERSION_PROBE=hermes"}
	writeVersionProbeProcess(t, h, 8203, 8202, uid, 300, "/usr/bin/python3", argv, env)
	previous := waitManagedHermesVersion
	called := map[int]bool{}
	retryDone := make(chan struct{})
	var retryErr error
	waitManagedHermesVersion = func(_ string, pid int, accountHome string, maxWait time.Duration) bool {
		if accountHome != home {
			t.Fatalf("wrong account home")
		}
		called[pid] = true
		switch pid {
		case 8203:
			if err := os.RemoveAll(h.env.P("/proc/8203")); err != nil {
				t.Fatal(err)
			}
			writeVersionProbeProcess(t, h, 8204, 8202, uid, 400, "/usr/bin/python3", argv, retryEnv)
			go func() {
				time.Sleep(500 * time.Millisecond)
				retryErr = os.RemoveAll(h.env.P("/proc/8204"))
				close(retryDone)
			}()
		case 8204:
			return agentprobe.WaitManagedHermesVersion(h.env.P("/proc"), pid, accountHome, maxWait)
		default:
			t.Fatalf("unexpected version probe pid %d", pid)
		}
		return true
	}
	t.Cleanup(func() { waitManagedHermesVersion = previous })
	result := h.run(Options{Action: ActionVerify})
	if !called[8203] {
		t.Fatal("first version probe was not checked")
	}
	<-retryDone
	if retryErr != nil {
		t.Fatal(retryErr)
	}
	if got := messagesOf(result.Errors, codeManagedLaunchUninspected); got != "" {
		t.Errorf("second legitimate version probe blocked launch verification: %s", got)
	}
	if !called[8204] {
		t.Error("second legitimate version probe was not waited for")
	}
}

func TestGAP0540RelocatedConsoleScriptRemainsProtected(t *testing.T) {
	h, home, uid := versionProbeTestHost(t)
	scratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
	if err != nil {
		t.Fatal(err)
	}
	const gateway = "/opt/defenseclaw/bin/defenseclaw-gateway"
	writeVersionProbeProcess(t, h, 8401, 1, 0, 100, gateway,
		[]string{gateway, "enterprise", "hooks", "enumerate", "--manifest", "/etc/defenseclaw/hook-guardian/targets.yaml", "--interval", "5m"}, nil)
	writeVersionProbeProcess(t, h, 8402, 8401, uid, 200, gateway,
		[]string{gateway, "enterprise", "hooks", "apply-target"}, nil)
	writeVersionProbeProcess(t, h, 8403, 8402, uid, 300, "/usr/bin/python3",
		[]string{"/usr/bin/python3", filepath.Join(home, ".local", "bin", "hermes"), "--version"},
		[]string{"HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C", "NO_COLOR=1", "TERM=dumb", "CI=1",
			"HERMES_HOME=" + scratch, "TMPDIR=" + scratch, "DC_AGENT_VERSION_PROBE=hermes", "HERMES_SAFE_MODE=1"})
	result := h.run(Options{Action: ActionVerify})
	if got := messagesOf(result.Errors, codeManagedLaunchUninspected); got == "" {
		t.Error("relocated console-script session omitted from launch coverage")
	}
	if err := hermespath.VerifyAccountHome(home, filepath.Join(home, ".hermes"), time.Time{}); err == nil {
		t.Error("relocated console-script session omitted from account-home evidence")
	}
}
