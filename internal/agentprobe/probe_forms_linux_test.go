// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package agentprobe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A Python console script is a regular Hermes CLI installation form.
func TestGAP0540PythonConsoleScriptVersionProbe(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	scratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
	if err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	const gateway = "/opt/defenseclaw/bin/defenseclaw-gateway"
	writeProbeProcess(t, root, 7701, 1, 0, 100, gateway,
		[]string{gateway, "enterprise", "hooks", "enumerate", "--manifest", "/etc/defenseclaw/hook-guardian/targets.yaml", "--interval", "5m"}, nil)
	writeProbeProcess(t, root, 7702, 7701, uid, 200, gateway,
		[]string{gateway, "enterprise", "hooks", "apply-target"}, nil)
	writeProbeProcess(t, root, 7703, 7702, uid, 300, "/opt/hermes/bin/python3",
		[]string{"/opt/hermes/bin/python3", filepath.Join(home, ".local", "bin", "hermes"), "--version"},
		[]string{"HOME=" + home, "PATH=/opt/hermes/bin:/usr/bin:/bin", "LANG=C", "NO_COLOR=1", "TERM=dumb", "CI=1",
			"HERMES_HOME=" + scratch, "TMPDIR=" + scratch, EnvName + "=" + Hermes})
	if _, ok := managedHermesVersion(root, 7703, home); !ok {
		t.Fatal("a normal Python console script --version child was not proven")
	}
	if WaitManagedHermesVersion(root, 7703, home, 0) {
		t.Fatal("a running console script was treated as finished")
	}
	if !waitManagedHermesVersion(root, 7703, home, time.Second, func() {
		if err := os.RemoveAll(filepath.Join(root, "7703")); err != nil {
			t.Fatal(err)
		}
	}) {
		t.Fatal("a completed console script was not recognized")
	}
}

func TestGAP0540ConsoleScriptRequiresExactVersionArguments(t *testing.T) {
	for _, argv := range [][]string{
		{"/usr/bin/python3", "/tmp/hermes", "--version", "--other"},
		{"/usr/bin/python3", "/tmp/hermes", "--other"},
		{"/usr/bin/python3", "/tmp/other", "--version"},
		{"/usr/bin/python3", "hermes", "--version"},
	} {
		if versionCommand(process{argv: argv, exe: "/usr/bin/python3"}) {
			t.Errorf("accepted non-version console script arguments: %q", argv)
		}
	}
}

func TestGAP0540ProtectedVersionShapeMutants(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	scratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
	if err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	const gateway = "/opt/defenseclaw/bin/defenseclaw-gateway"
	writeProbeProcess(t, root, 7801, 1, 0, 100, gateway,
		[]string{gateway, "enterprise", "hooks", "enumerate", "--manifest", "/etc/defenseclaw/hook-guardian/targets.yaml", "--interval", "5m"}, nil)
	writeProbeProcess(t, root, 7802, 7801, uid, 200, gateway,
		[]string{gateway, "enterprise", "hooks", "apply-target"}, nil)
	baseEnv := []string{"HOME=" + home, "PATH=/opt/hermes/bin:/usr/bin:/bin", "LANG=C", "NO_COLOR=1", "TERM=dumb", "CI=1",
		"HERMES_HOME=" + scratch, "TMPDIR=" + scratch, EnvName + "=" + Hermes}
	baseArgv := []string{"/opt/hermes/bin/python3", "-I", "-c", "from hermes_cli.main import main\nmain()", "--version"}
	cases := []struct {
		name  string
		ppid  int
		argv  []string
		extra string
	}{
		{name: "safe mode", ppid: 7802, extra: "HERMES_SAFE_MODE=1"},
		{name: "relocated managed directory", ppid: 7802, extra: "HERMES_MANAGED_DIR=/tmp/foreign"},
		{name: "relocated config home", ppid: 7802, extra: "XDG_CONFIG_HOME=/tmp/foreign"},
		{name: "duplicate home", ppid: 7802, extra: "HERMES_HOME=/tmp/foreign"},
		{name: "extra launch argument", ppid: 7802, argv: append(append([]string{}, baseArgv...), "--safe-mode")},
		{name: "forged marker without parent", ppid: 1},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pid := 7810 + i
			argv := tc.argv
			if argv == nil {
				argv = baseArgv
			}
			env := append([]string{}, baseEnv...)
			if tc.extra != "" {
				env = append(env, tc.extra)
			}
			writeProbeProcess(t, root, pid, tc.ppid, uid, 300, "/opt/hermes/bin/python3", argv, env)
			if _, ok := managedHermesVersion(root, pid, home); ok {
				t.Fatal("protected process accepted as a managed version probe")
			}
		})
	}
}
