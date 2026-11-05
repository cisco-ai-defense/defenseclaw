// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package enterpriseunix

import (
	"os"
	"testing"
	"time"
)

// A version process can finish between session capture and lineage proof.
func TestGAP0540ExitedProbeDoesNotRemainLaunchEvidence(t *testing.T) {
	h, home, uid := versionProbeTestHost(t)
	scratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
	if err != nil {
		t.Fatal(err)
	}
	const gateway = "/opt/defenseclaw/bin/defenseclaw-gateway"
	writeVersionProbeProcess(t, h, 7601, 1, 0, 100, gateway,
		[]string{gateway, "enterprise", "hooks", "enumerate", "--manifest", "/etc/defenseclaw/hook-guardian/targets.yaml", "--interval", "5m"}, nil)
	writeVersionProbeProcess(t, h, 7602, 7601, uid, 200, gateway,
		[]string{gateway, "enterprise", "hooks", "apply-target"}, nil)
	writeVersionProbeProcess(t, h, 7603, 7602, uid, 300, "/opt/hermes/bin/python3",
		[]string{"/opt/hermes/bin/python3", "-I", "-c", "from hermes_cli.main import main\nmain()", "--version"},
		[]string{"HOME=" + home, "PATH=/opt/hermes/bin:/usr/bin:/bin", "LANG=C", "NO_COLOR=1", "TERM=dumb", "CI=1",
			"HERMES_HOME=" + scratch, "TMPDIR=" + scratch, "DC_AGENT_VERSION_PROBE=hermes"})
	previous := waitManagedHermesVersion
	called := false
	waitManagedHermesVersion = func(_ string, pid int, accountHome string, _ time.Duration) bool {
		if pid != 7603 || accountHome != home {
			t.Fatalf("unexpected probe pid or account home")
		}
		called = true
		if err := os.RemoveAll(h.env.P("/proc/7603")); err != nil {
			t.Fatal(err)
		}
		return false // provenance cannot be read after exit
	}
	t.Cleanup(func() { waitManagedHermesVersion = previous })
	result := h.run(Options{Action: ActionVerify})
	if got := messagesOf(result.Errors, codeManagedLaunchUninspected); got != "" {
		t.Errorf("finished probe left stale launch evidence: %s", got)
	}
	if !called {
		t.Fatal("the version probe was not considered")
	}
}
