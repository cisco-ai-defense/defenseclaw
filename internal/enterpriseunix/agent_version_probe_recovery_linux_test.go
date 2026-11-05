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
)

func gap0540RecoveredHost(t *testing.T) (*testHost, string, int) {
	t.Helper()
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.7"),
		ConfigFile: machinePolicyConfig(t, h, "hermes")}))
	snap, err := h.env.takeSnapshot("interrupted", []string{h.env.Layout.ConfigPath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.env.savePending(&Pending{Action: ActionEnsure, StartedAt: "2026-11-03T21:00:00Z",
		SnapshotDir: snap.Dir, Phase: "quiesce"}); err != nil {
		t.Fatal(err)
	}
	if result := h.run(Options{Action: ActionVerify}); !result.TransactionPending {
		t.Fatalf("interrupted quiesce was not reported: %+v", result.Errors)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	h.publishLedger([]byte("ledger\n"))
	if pending, err := h.env.loadPending(); err != nil || pending != nil {
		t.Fatalf("recovery left a pending transaction: %+v (%v)", pending, err)
	}
	home := t.TempDir()
	uid := os.Getuid()
	h.runner.replies = map[string]fakeReply{
		"getent passwd " + strconv.Itoa(uid): {result: CommandResult{Stdout: []byte(fmt.Sprintf("probe:x:%d:%d::%s:/bin/sh\n", uid, os.Getgid(), home))}},
	}
	return h, home, uid
}

func gap0540WriteProcess(t *testing.T, h *testHost, pid, ppid, uid, start int, exe string, argv, environ []string) {
	t.Helper()
	dir := h.env.P(fmt.Sprintf("/proc/%d", pid))
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

func TestGAP0540InterruptedQuiesceLateVersionProbes(t *testing.T) {
	h, home, uid := gap0540RecoveredHost(t)
	const gateway = "/opt/defenseclaw/bin/defenseclaw-gateway"
	gap0540WriteProcess(t, h, 8901, 1, 0, 100, gateway,
		[]string{gateway, "enterprise", "hooks", "enumerate", "--manifest", "/etc/defenseclaw/hook-guardian/targets.yaml", "--interval", "5m"}, nil)
	gap0540WriteProcess(t, h, 8902, 8901, uid, 200, gateway,
		[]string{gateway, "enterprise", "hooks", "apply-target"}, nil)
	proc := h.env.P("/proc")
	stage := filepath.Join(h.env.Root, "staged-version-processes")
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	const count = 25
	for index := 0; index < count; index++ {
		scratch, err := os.MkdirTemp(t.TempDir(), "dc-agent-probe-")
		if err != nil {
			t.Fatal(err)
		}
		pid := 8910 + index
		gap0540WriteProcess(t, h, pid, 8902, uid, 300+index, "/opt/hermes/bin/python3",
			[]string{"/opt/hermes/bin/python3", "-I", "-c", "from hermes_cli.main import main\nmain()", "--version"},
			[]string{"HOME=" + home, "PATH=/opt/hermes/bin:/usr/bin:/bin", "LANG=C", "NO_COLOR=1", "TERM=dumb", "CI=1",
				"HERMES_HOME=" + scratch, "TMPDIR=" + scratch, "DC_AGENT_VERSION_PROBE=hermes"})
		if index > 0 {
			name := strconv.Itoa(pid)
			if err := os.Rename(filepath.Join(proc, name), filepath.Join(stage, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	done := make(chan error, 1)
	go func() {
		for index := 1; index < count; index++ {
			time.Sleep(400 * time.Millisecond)
			prev, next := strconv.Itoa(8909+index), strconv.Itoa(8910+index)
			if err := os.Rename(filepath.Join(stage, next), filepath.Join(proc, next)); err != nil {
				done <- err
				return
			}
			if err := os.RemoveAll(filepath.Join(proc, prev)); err != nil {
				done <- err
				return
			}
		}
		time.Sleep(400 * time.Millisecond)
		done <- os.RemoveAll(filepath.Join(proc, strconv.Itoa(8909+count)))
	}()
	result := h.run(Options{Action: ActionVerify})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if result.TransactionPending || !result.Readiness.Gateway || !result.Readiness.Guardian ||
		!result.Readiness.Enumerator || !result.Readiness.SensorHelper || !result.OK {
		t.Fatalf("recovered verify did not settle: readiness=%+v pending=%v errors=%+v",
			result.Readiness, result.TransactionPending, result.Errors)
	}
}

func TestGAP0540InterruptedQuiesceOrdinarySession(t *testing.T) {
	h, home, uid := gap0540RecoveredHost(t)
	gap0540WriteProcess(t, h, 8950, 1, uid, 500, "/opt/hermes/bin/hermes",
		[]string{"/opt/hermes/bin/hermes"}, []string{"HOME=" + home, "HERMES_HOME=" + filepath.Join(home, ".hermes")})
	result := h.run(Options{Action: ActionVerify})
	if result.TransactionPending || !result.Readiness.Gateway || !result.Readiness.Guardian ||
		!result.Readiness.Enumerator || !result.Readiness.SensorHelper || !result.OK {
		t.Fatalf("ordinary session after recovery did not verify: readiness=%+v pending=%v errors=%+v",
			result.Readiness, result.TransactionPending, result.Errors)
	}
}
