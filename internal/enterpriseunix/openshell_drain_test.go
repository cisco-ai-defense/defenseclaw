// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestAWaitingSwitchChecksAgainUnderTheAccountsDrain: settlePending read
// busy=0, then stopped the account's daemon and gateway with no check
// between; a sandbox that started and completed in that window
// (stop-sandboxes skips a completed one) was ended with the gateway, its
// MicroVM with no flush. Every change that stops the gateway (the pin
// migration's switch, sandboxes turned off) now runs under the account's
// drain, after the account's daemon and its socket are stopped: the drain
// checks again under the account's lifecycle lock, and a refusal keeps the
// change waiting, with the gateway untouched. Once the drain holds, the
// units stop inside it, and it is let go after.
func TestAWaitingSwitchChecksAgainUnderTheAccountsDrain(t *testing.T) {
	old := map[string]any{"install": "setup", "driver": "vm", "version": "0.1.3"}
	h := newOSHost(t, "linux")
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, old)))
	st := h.env.loadOpenShellState()
	st.Applied.Version = "0.1.3"
	if err := h.env.saveOpenShellState(st); err != nil {
		t.Fatal(err)
	}
	h.installTarballFiles(t, h.alice, "0.1.3")
	// The status says nothing runs: then a MicroVM starts and completes.
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
	h.ops.onDrain = func(a SandboxAccount) error {
		return fmt.Errorf("%w (1 MicroVM run as this account, which the gateway's stop would end with no flush); stop them, then try again", openshell.ErrUnflushed)
	}
	ensure := func() *enterprisestatus.Result {
		r := h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.4"), ConfigFile: writeTempConfig(t, sandboxConfig(t, "linux", true, old))})
		requireOK(t, r)
		return r
	}
	r := ensure()
	if containsLine(r.Changes, "switched the sandbox setup of alice") || strings.Join(h.ops.stopped(), ",") != "alice:daemon+socket" {
		t.Fatalf("switched under a MicroVM started after the status: changes %v, stops %v", r.Changes, h.ops.stopped())
	}
	entry, waiting := h.env.loadOpenShellState().Pending[fmt.Sprint(h.alice.UID)]
	if !waiting || entry.Kind != "switch" || entry.Sandboxes != -1 || !strings.Contains(entry.Reason, "1 MicroVM run as this account") {
		t.Fatalf("pending = %+v, %v", entry, waiting)
	}
	if w := messagesOf(r.Warnings, codeSandboxPending); !strings.Contains(w, "the switch change for alice waits") {
		t.Errorf("warnings = %v", r.Warnings)
	}
	if !slices.Equal(h.ops.order, []string{"stop alice:daemon+socket", "drain refused alice"}) {
		t.Fatalf("order = %v", h.ops.order)
	}

	// It has stopped: the drain holds, and the switch runs inside it.
	h.ops.onDrain, h.ops.order = nil, nil
	r = ensure()
	if !containsLine(r.Changes, `switched the sandbox setup of alice (version "0.1.3" -> "`+openshell.InstallerVersion+`")`) {
		t.Fatalf("changes = %v", r.Changes)
	}
	if !slices.Equal(h.ops.order, []string{"stop alice:daemon+socket", "drain alice", "stop alice:daemon+gateway", "release alice"}) {
		t.Fatalf("order = %v", h.ops.order)
	}

	// Sandboxes turned off stops the gateway too: the same drain.
	h2 := newOSHost(t, "linux")
	on := map[string]any{"install": "setup", "driver": "vm", "version": "0.1.5"}
	requireOK(t, h2.ensure(sandboxConfig(t, "linux", true, on)))
	h2.ops.status[h2.alice.UID] = SandboxStatus{Active: true}
	h2.ops.onDrain = func(SandboxAccount) error { return errors.New("gateway openshell: a sandbox is starting") }
	requireOK(t, h2.ensure(sandboxConfig(t, "linux", false, on)))
	if entry := h2.env.loadOpenShellState().Pending[fmt.Sprint(h2.alice.UID)]; entry.Kind != "stop" || strings.Join(h2.ops.stopped(), ",") != "alice:daemon+socket" {
		t.Fatalf("pending = %+v, stops %v", entry, h2.ops.stopped())
	}
	h2.ops.onDrain, h2.ops.order = nil, nil
	requireOK(t, h2.ensure(sandboxConfig(t, "linux", false, on)))
	if !slices.Equal(h2.ops.order, []string{"stop alice:daemon+socket", "drain alice", "stop alice:daemon+gateway+socket", "release alice"}) {
		t.Fatalf("order = %v", h2.ops.order)
	}
}

// oldDaemon models what runs as an account around a managed change: its
// sandbox daemon, started by DefenseClaw 1.0.3 before the package upgrade
// and still running it, which takes no lifecycle lock and, stopped
// (SIGTERM), runs its exit: that stops the account's OpenShell gateway when
// no sandbox runs, a MicroVM that completed counting for none
// (stopOpenShellIfIdle of 1.0.3); killed (StopKill), it runs nothing. The
// socket, which
// starts a daemon of the installed DefenseClaw (one that takes it); the
// drain's lock; and the MicroVMs on the gateway that a stop-sandboxes
// leaves running (one that started and completed: it holds the gateway).
// At its race-th step (each Stop, the drain before and after its check,
// the release), something starts a sandbox through the daemon: the old
// daemon starts it whatever the lock, the installed one only while no
// drain holds. A stop of the gateway ends the MicroVMs left with no flush.
type oldDaemon struct {
	race, step     int
	legacyUp       bool
	held           bool
	lingering      int
	lost, refused  int
	startedByOld   bool
	stoppedGateway bool
	oldExitRan     bool
}

func (d *oldDaemon) tick(op string) {
	d.step++
	if op == "drained" {
		d.held = true
	}
	if d.step == d.race {
		switch {
		case d.legacyUp:
			d.lingering++
			d.startedByOld = true
		case !d.held:
			d.lingering++
		default:
			d.refused++
		}
	}
	if op == "release" {
		d.held = false
	}
	if strings.Contains(op, "daemon") || strings.Contains(op, "socket") {
		if d.legacyUp && !strings.Contains(op, "kill") {
			d.oldExitRan = true
			d.lost += d.lingering
			d.lingering = 0
			d.stoppedGateway = true
		}
		d.legacyUp = false
	}
	if strings.Contains(op, "gateway") {
		d.lost += d.lingering
		d.lingering = 0
		d.stoppedGateway = true
	}
}

// TestAManagedChangeStopsTheGatewayOnlyOnceNoOldDaemonCanStartAnything:
// the drain held the account's lifecycle lock, but a sandbox daemon that
// DefenseClaw 1.0.3 started before the package upgrade does not take it:
// right after the drain's check it could start a MicroVM through its live
// socket, and the gateway's stop then ended that MicroVM with no flush
// (the units were stopped together, after the check). Now the daemon and
// its socket stop first, whatever release the daemon runs; the drain
// checks after that, and the gateway stops while the drain holds the
// starts back. For every step at which something starts a sandbox, for
// the pin switch and for sandboxes turned off, no MicroVM is lost: a
// sandbox started before the check makes the change wait, and none can
// start after it. The old daemon is killed, not stopped: stopped, its exit
// ended the MicroVM it started and that completed right before (at the
// first step) with the gateway, before the drain could see it.
func TestAManagedChangeStopsTheGatewayOnlyOnceNoOldDaemonCanStartAnything(t *testing.T) {
	for _, kind := range []string{"switch", "stop"} {
		for race := 0; race <= 6; race++ {
			t.Run(fmt.Sprintf("%s/race at step %d", kind, race), func(t *testing.T) {
				h := newOSHost(t, "linux")
				var cfg []byte
				switch kind {
				case "switch":
					old := map[string]any{"install": "setup", "driver": "vm", "version": "0.1.3"}
					requireOK(t, h.ensure(sandboxConfig(t, "linux", true, old)))
					st := h.env.loadOpenShellState()
					st.Applied.Version = "0.1.3"
					if err := h.env.saveOpenShellState(st); err != nil {
						t.Fatal(err)
					}
					h.installTarballFiles(t, h.alice, "0.1.3")
					cfg = sandboxConfig(t, "linux", true, old)
				case "stop":
					on := map[string]any{"install": "setup", "driver": "vm", "version": "0.1.5"}
					requireOK(t, h.ensure(sandboxConfig(t, "linux", true, on)))
					cfg = sandboxConfig(t, "linux", false, on)
				}
				h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Legacy: true}
				d := &oldDaemon{race: race, legacyUp: true}
				h.ops.order = nil
				h.ops.onOp = func(_ SandboxAccount, op string) { d.tick(op) }
				h.ops.onDrain = func(SandboxAccount) error {
					if d.lingering > 0 {
						return fmt.Errorf("%w (%d MicroVM run as this account, which the gateway's stop would end with no flush); stop them, then try again",
							openshell.ErrUnflushed, d.lingering)
					}
					return nil
				}
				r := h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.4"), ConfigFile: writeTempConfig(t, cfg)})
				requireOK(t, r)
				if d.lost != 0 || d.oldExitRan {
					t.Fatalf("the gateway's stop ended %d MicroVM(s) with no flush (an old daemon started one: %v, its exit ran: %v); order %v",
						d.lost, d.startedByOld, d.oldExitRan, h.ops.order)
				}
				_, waiting := h.env.loadOpenShellState().Pending[fmt.Sprint(h.alice.UID)]
				if waiting == d.stoppedGateway {
					t.Fatalf("waiting %v, gateway stopped %v; order %v", waiting, d.stoppedGateway, h.ops.order)
				}
				if !waiting && !slices.Equal(h.ops.order[:2], []string{"stop alice:kill+daemon+socket", "drain alice"}) {
					t.Fatalf("order = %v", h.ops.order)
				}
			})
		}
	}
}

// TestARestartOfAnOldDaemonKeepsTheGatewayOfACompletedMicroVM: a waiting
// restart (the daemon's inputs changed) stops only the daemon, and keeps
// the account's OpenShell gateway. Stopped, a daemon before 1.0.4 ran its
// exit, which stopped that gateway under a MicroVM it started after the
// status and that completed, with no flush; it is killed now. A daemon of
// 1.0.4, whose exit checks for MicroVMs, is stopped as before.
func TestARestartOfAnOldDaemonKeepsTheGatewayOfACompletedMicroVM(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			h := newOSHost(t, "linux")
			cfg := sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker"})
			requireOK(t, h.ensure(cfg))
			h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1, Legacy: legacy}
			requireOK(t, h.ensure(sandboxConfigWithTelemetry(t, "linux")))
			if entry := h.env.loadOpenShellState().Pending[fmt.Sprint(h.alice.UID)]; entry.Kind != "restart" {
				t.Fatalf("pending = %+v", entry)
			}
			h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Legacy: legacy}
			d := &oldDaemon{race: 1, legacyUp: legacy}
			h.ops.order = nil
			h.ops.onOp = func(_ SandboxAccount, op string) { d.tick(op) }
			r := h.ensure(sandboxConfigWithTelemetry(t, "linux"))
			requireOK(t, r)
			want := "stop alice:daemon"
			if legacy {
				want = "stop alice:kill+daemon"
			}
			if !slices.Equal(h.ops.order, []string{want}) || d.lost != 0 || d.oldExitRan || d.stoppedGateway {
				t.Fatalf("order %v, lost %d, old exit ran %v, gateway stopped %v", h.ops.order, d.lost, d.oldExitRan, d.stoppedGateway)
			}
			if !containsLine(r.Changes, "restarted the sandbox daemon of alice") {
				t.Fatalf("changes = %v", r.Changes)
			}
		})
	}
}

// TestCommandOpsDrain: the drain runs as the account and holds until the
// lifecycle lets it go; one that refuses says why, and one that does not
// answer in time is ended.
func TestCommandOpsDrain(t *testing.T) {
	restore := drainCommand
	t.Cleanup(func() { drainCommand = restore })
	marker := filepath.Join(t.TempDir(), "released")
	var argv []string
	script := ""
	drainCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		argv = append([]string{name}, args...)
		return exec.CommandContext(ctx, "/bin/sh", "-c", script)
	}
	o := &commandUserOps{env: &Env{GOOS: "linux", Layout: managed.StandaloneLayout{BinDir: "/opt/defenseclaw/bin"}}}
	alice := SandboxAccount{Name: "alice", UID: 1001, Home: "/home/alice"}

	script = "echo '" + openshell.LifecycleDrained + "'; cat >/dev/null; touch " + marker
	release, err := o.Drain(context.Background(), alice)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"runuser", "-u", "alice", "--", "/usr/bin/env", "HOME=/home/alice"}; !slices.Equal(argv[:len(want)], want) ||
		!slices.Equal(argv[len(argv)-3:], []string{"/opt/defenseclaw/bin/" + binGateway, "sandbox-daemon", "drain"}) {
		t.Fatalf("argv = %v", argv)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the drain let go before the lifecycle was done")
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the drain was not let go: %v", err)
	}

	script = "echo 'openshell: the gateway was not restarted: dc-x (completed)' >&2; exit 1"
	if _, err := o.Drain(context.Background(), alice); err == nil || !strings.Contains(err.Error(), "dc-x (completed)") {
		t.Fatalf("a refused drain = %v", err)
	}

	wait := drainReadyWait
	t.Cleanup(func() { drainReadyWait = wait })
	drainReadyWait = 100 * time.Millisecond
	script = "sleep 30"
	start := time.Now()
	if _, err := o.Drain(context.Background(), alice); err == nil || !strings.Contains(err.Error(), "did not answer") || time.Since(start) > 10*time.Second {
		t.Fatalf("a drain that does not answer = %v after %s", err, time.Since(start))
	}
}
