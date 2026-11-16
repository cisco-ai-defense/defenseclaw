// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package agentprobe

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func writeProbeProcess(t *testing.T, root string, pid, ppid, uid, start int, exe string, argv, environ []string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"stat":    fmt.Sprintf("%d (process) S %d %d %s%d 0 0", pid, ppid, pid, strings.Repeat("0 ", 16), start),
		"status":  fmt.Sprintf("Name:\tprocess\nUid:\t%d\t%d\t%d\t%d\n", uid, uid, uid, uid),
		"cmdline": strings.Join(argv, "\x00") + "\x00",
		"environ": strings.Join(environ, "\x00") + "\x00",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
}

func TestGAP0540VersionProbeWaitRequiresLineageAndExit(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	scratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
	if err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	const gateway = "/opt/defenseclaw/bin/defenseclaw-gateway"
	writeProbeProcess(t, root, 7101, 1, 0, 100, gateway,
		[]string{gateway, "enterprise", "hooks", "enumerate", "--manifest", "/etc/defenseclaw/hook-guardian/targets.yaml", "--interval", "5m"}, nil)
	writeProbeProcess(t, root, 7102, 7101, uid, 200, gateway,
		[]string{gateway, "enterprise", "hooks", "apply-target"}, nil)
	env := []string{
		"HOME=" + home, "PATH=/opt/hermes/bin:/usr/bin:/bin", "LANG=C", "NO_COLOR=1", "TERM=dumb", "CI=1",
		"HERMES_HOME=" + scratch, "TMPDIR=" + scratch, EnvName + "=" + Hermes,
	}
	childDir := filepath.Join(root, "7103")
	writeChild := func(parent int, args []string, environment []string) {
		t.Helper()
		if err := os.RemoveAll(childDir); err != nil {
			t.Fatal(err)
		}
		writeProbeProcess(t, root, 7103, parent, uid, 300, "/opt/hermes/bin/python3", args, environment)
	}
	argv := []string{"/opt/hermes/bin/python3", "-I", "-c", "from hermes_cli.main import main\nmain()", "--version"}
	writeChild(7102, argv, env)
	if _, ok := managedHermesVersion(root, 7103, home); !ok {
		t.Fatal("version process provenance was not established")
	}
	if WaitManagedHermesVersion(root, 7103, home, 0) {
		t.Fatal("a live version process was treated as finished")
	}
	if !waitManagedHermesVersion(root, 7103, home, time.Second, func() {
		if err := os.RemoveAll(childDir); err != nil {
			t.Fatal(err)
		}
	}) {
		t.Fatal("a completed version process was not recognized")
	}
	writeChild(1, argv, env)
	if WaitManagedHermesVersion(root, 7103, home, 0) {
		t.Fatal("a process outside the enumerator lineage was accepted")
	}
	writeChild(7102, argv, append(append([]string{}, env...), "HERMES_SAFE_MODE=1"))
	if WaitManagedHermesVersion(root, 7103, home, 0) {
		t.Fatal("a process with another state selector was accepted")
	}
	writeChild(7102, argv, append([]string{"HERMES_HOME=/tmp/other"}, env...))
	if WaitManagedHermesVersion(root, 7103, home, 0) {
		t.Fatal("a process with duplicate state selectors was accepted")
	}
	writeChild(7102, []string{"/opt/hermes/bin/python3", "-I", "-c", "import hermes_cli", "--version"}, env)
	if WaitManagedHermesVersion(root, 7103, home, 0) {
		t.Fatal("a different command was accepted")
	}
}
