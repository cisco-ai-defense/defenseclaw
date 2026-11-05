// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package agentprobe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGAP0540ShellVersionProbeWaitsForExit(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	scratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
	if err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	const gateway = "/opt/defenseclaw/bin/defenseclaw-gateway"
	writeProbeProcess(t, root, 8101, 1, 0, 100, gateway,
		[]string{gateway, "enterprise", "hooks", "enumerate", "--manifest", "/etc/defenseclaw/hook-guardian/targets.yaml", "--interval", "5m"}, nil)
	writeProbeProcess(t, root, 8102, 8101, uid, 200, gateway,
		[]string{gateway, "enterprise", "hooks", "apply-target"}, nil)
	argv := []string{"/opt/hermes/bin/python3", "-I", "-c", "from hermes_cli.main import main\nmain()", "--version"}
	env := []string{
		"HOME=" + home, "PATH=/opt/hermes/bin:/usr/bin:/bin", "LANG=C", "NO_COLOR=1", "TERM=dumb", "CI=1",
		"HERMES_HOME=" + scratch, "TMPDIR=" + scratch, EnvName + "=" + Hermes,
		"PWD=" + home, "SHLVL=0",
	}
	childDir := filepath.Join(root, "8103")
	writeChild := func(parent int, environment []string) {
		t.Helper()
		if err := os.RemoveAll(childDir); err != nil {
			t.Fatal(err)
		}
		writeProbeProcess(t, root, 8103, parent, uid, 300, "/opt/hermes/bin/python3", argv, environment)
	}
	writeChild(8102, env)
	if _, ok := managedHermesVersion(root, 8103, home); !ok {
		t.Fatal("shell-launched version process was not identified")
	}
	if WaitManagedHermesVersion(root, 8103, home, 0) {
		t.Fatal("live version process was treated as finished")
	}
	if !waitManagedHermesVersion(root, 8103, home, time.Second, func() {
		if err := os.RemoveAll(childDir); err != nil {
			t.Fatal(err)
		}
	}) {
		t.Fatal("completed version process was not recognized")
	}
	writeChild(1, env)
	if _, ok := managedHermesVersion(root, 8103, home); ok {
		t.Fatal("same-command user process was identified as product-owned")
	}
	for _, extra := range []string{"PWD=/tmp/other", "SHLVL=2", "HERMES_SAFE_MODE=1", "XDG_CONFIG_HOME=/tmp/other"} {
		t.Run(extra, func(t *testing.T) {
			candidate := append([]string{}, env...)
			switch {
			case strings.HasPrefix(extra, "PWD="):
				candidate[len(candidate)-2] = extra
			case strings.HasPrefix(extra, "SHLVL="):
				candidate[len(candidate)-1] = extra
			default:
				candidate = append(candidate, extra)
			}
			writeChild(8102, candidate)
			if _, ok := managedHermesVersion(root, 8103, home); ok {
				t.Fatal("unexpected environment was identified as product-owned")
			}
		})
	}
}
