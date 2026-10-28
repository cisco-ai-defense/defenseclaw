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

package sandboxcli

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// `df -Pk /` in a MicroVM whose own 2 GiB disk is full, 93% full and half
// full.
const (
	dfHeader  = "Filesystem     1024-blocks    Used Available Capacity Mounted on\n"
	dfFull    = dfHeader + "/dev/vda           2097152 2097152         0     100% /\n"
	dfFilling = dfHeader + "/dev/vda           2097152 1950352    146800      93% /\n"
	dfHalf    = dfHeader + "/dev/vda           2097152 1048576   1048576      50% /\n"
)

// vmCopySandbox is a running copy-mode sandbox on the MicroVM driver.
func vmCopySandbox(name string) sandboxapi.Sandbox {
	sb := copySandbox(name)
	sb.Phase, sb.Driver = "ready", string(openshell.DriverVM)
	return sb
}

// diskAnswers makes the fake sandbox answer `df` with df and exit status
// code, its run state with state, and everything else with success.
func diskAnswers(ta *testApp, state, df string, code int) {
	ta.stream.answer = func(argv []string) (int, string) {
		cmd := sandboxCommand(argv)
		switch {
		case len(cmd) > 2 && cmd[0] == "sh" && cmd[2] == runStateScript:
			return 0, state
		case len(cmd) > 0 && cmd[0] == "df":
			return code, df
		}
		return 0, ""
	}
}

// ranDF reports whether the CLI looked at the sandbox's own disk.
func ranDF(ta *testApp) bool {
	return slices.Contains(ta.stream.commands(), "df -Pk /")
}

// #1144: `sandbox stop` of a copy-mode MicroVM whose own disk is full kept
// nothing from losing its work that was not pulled: the MicroVM could not
// start again, so that work could not be read any more. The stop keeps it
// running and says what to do first (exit ExitStopKept), also with --yes,
// which the macOS app passes after its own question (deleting it is the
// way to give the work up); a stop that loses nothing goes ahead.
func TestStopKeepsAFullDiskMicroVMWithUnpulledWork(t *testing.T) {
	for _, c := range []struct {
		name  string
		work  workspace.CopyWork
		state string
		df    string
		yes   bool
		stops bool
	}{
		{"unpulled work", workspace.CopyWorkUnpulled, "run=none\n", dfFull, false, false},
		{"a copy that could not be looked at", workspace.CopyWorkUnknown, "run=none\n", dfFull, false, false},
		{"a detached run kept the look from before", workspace.CopyWorkUnpulled, "run_started=1790000000\nrun=running\n", dfFull, false, false},
		{"--yes", workspace.CopyWorkUnpulled, "run=none\n", dfFull, true, false},
		{"everything pulled", workspace.CopyWorkNone, "run=none\n", dfFull, false, true},
		{"a pull not applied, on this machine already", workspace.CopyWorkUnapplied, "run=none\n", dfFull, false, true},
		{"room left", workspace.CopyWorkUnpulled, "run=none\n", dfHalf, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "y\n", vmCopySandbox("vmbox"))
			ta.copy.pending = map[string]workspace.CopyWork{"vmbox": c.work}
			diskAnswers(ta, c.state, c.df, 0)
			err := ta.Stop(bg, StopOptions{Name: "vmbox", Yes: c.yes})
			if c.stops {
				ta.ok(t, err)
				ta.wantCalls(t, 1, "POST", "vmbox/stop")
				return
			}
			wantExit(t, err, ExitStopKept)
			ta.wantCalls(t, 0, "POST", "vmbox/stop")
			has(t, ta.output(), "Sandbox vmbox keeps running: a MicroVM stopped with its disk full cannot start again, and its work that was not pulled would be lost",
				"`defenseclaw sandbox exec vmbox -- df -h /`", "`defenseclaw sandbox pull vmbox`", "to give that work up, delete it: `defenseclaw sandbox delete vmbox`")
			if !ranDF(ta) {
				t.Fatalf("the stop did not look at the disk: %q", ta.stream.commands())
			}
		})
	}
}

// #1144: a MicroVM that does not answer the bounded look is not stopped
// blind on a terminal (it asks, defaulting to no) and is not left waiting
// on either: without a terminal, or with --yes, it stops with a warning.
func TestStopOfAMicroVMWhoseDiskCannotBeRead(t *testing.T) {
	for _, c := range []struct {
		name  string
		in    string
		tty   bool
		yes   bool
		stops bool
	}{
		{"declined", "n\n", true, false, false},
		{"confirmed", "y\n", true, false, true},
		{"no terminal", "", false, false, true},
		{"--yes", "", true, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, c.in, vmCopySandbox("vmbox"))
			ta.IO.TTY = c.tty
			ta.copy.pending = map[string]workspace.CopyWork{"vmbox": workspace.CopyWorkUnpulled}
			// OpenShell's exit status for a command its --timeout ended.
			diskAnswers(ta, "run=none\n", "", 124)
			ta.ok(t, ta.Stop(bg, StopOptions{Name: "vmbox", Yes: c.yes}))
			want := 0
			if c.stops {
				want = 1
			}
			ta.wantCalls(t, want, "POST", "vmbox/stop")
			has(t, ta.output(), "could not read how full vmbox's own disk is (it did not answer within 15s)")
			if strings.Contains(ta.output(), "Stop anyway?") != (c.tty && !c.yes) {
				t.Fatalf("asked = %t:\n%s", !c.tty || c.yes, ta.output())
			}
		})
	}
}

// The disk look is only for a MicroVM's copy: a docker sandbox writes to the
// Docker host's storage, and a mounted folder holds its work already.
func TestStopLooksAtTheDiskOfACopyModeMicroVMOnly(t *testing.T) {
	docker := copySandbox("dkbox")
	docker.Phase = "ready"
	ta := newTestApp(t, "", docker, sampleSandbox("mtbox"))
	ta.copy.pending = map[string]workspace.CopyWork{"dkbox": workspace.CopyWorkUnpulled}
	diskAnswers(ta, "run=none\n", dfFull, 0)
	ta.ok(t, ta.Stop(bg, StopOptions{Name: "dkbox"}))
	ta.ok(t, ta.Stop(bg, StopOptions{Name: "mtbox"}))
	ta.wantCalls(t, 1, "POST", "dkbox/stop")
	ta.wantCalls(t, 1, "POST", "mtbox/stop")
	if ranDF(ta) {
		t.Fatalf("looked at the disk of a sandbox that is not a MicroVM's copy: %q", ta.stream.commands())
	}
}

// #1148: `sandbox status` of a running MicroVM says its own disk is filling
// at 90 percent, with what shows it and the pull that brings the work back
// first; below that it says nothing.
func TestStatusSaysAMicroVMsDiskIsFilling(t *testing.T) {
	ta := newTestApp(t, "", vmCopySandbox("vmbox"))
	diskAnswers(ta, "run=none\n", dfFilling, 0)
	ta.ok(t, ta.Status(bg, "vmbox", OutputText))
	has(t, ta.output(), "vmbox's own disk is 93% full (143.4 MiB of 2.0 GiB free): a MicroVM stopped with its disk full cannot start again",
		"`defenseclaw sandbox exec vmbox -- df -h /` shows it", "`defenseclaw sandbox pull vmbox` brings its work back before it fills")
	ta.out.Reset()
	diskAnswers(ta, "run=none\n", dfHalf, 0)
	ta.ok(t, ta.Status(bg, "vmbox", OutputText))
	lacks(t, ta.output(), "own disk is")
}

// #1148: a session in a copy-mode MicroVM says once, while it runs, that its
// own disk is filling, rather than only at the end once a write failed; it
// stops looking after that.
func TestSessionWarnsOnceThatItsMicroVMDiskIsFilling(t *testing.T) {
	prev, prevSmall := overlayDiskEvery, smallOverlayDiskEvery
	overlayDiskEvery, smallOverlayDiskEvery = time.Millisecond, time.Millisecond
	t.Cleanup(func() { overlayDiskEvery, smallOverlayDiskEvery = prev, prevSmall })
	sb := vmCopySandbox("vmbox")
	ta := newTestApp(t, "", sb)
	ta.IO.TTY = false
	looks := 0
	ta.stream.answer = func(argv []string) (int, string) {
		if cmd := sandboxCommand(argv); len(cmd) > 0 && cmd[0] == "df" {
			looks++
			switch looks {
			case 1:
				return 124, "" // a look that does not answer
			case 2:
				return 0, dfHalf // room left
			}
			return 0, dfFilling
		}
		return 0, ""
	}
	s := &session{app: ta.App, cli: ta.cli("gw"), sb: &sb}
	ctx, cancel := context.WithTimeout(bg, 10*time.Second)
	defer cancel()
	s.watchOverlayDisk(ctx)
	if ctx.Err() != nil {
		t.Fatal("the watch did not end after its warning")
	}
	if looks != 3 {
		t.Fatalf("looked %d times, want 3", looks)
	}
	if got := strings.Count(ta.err.String(), "own disk is 93% full"); got != 1 {
		t.Fatalf("warned %d times:\n%s", got, ta.err.String())
	}
	if len(s.notices) != 1 || !strings.Contains(s.notices[0].summary, "`defenseclaw sandbox pull vmbox`") {
		t.Fatalf("summary notices = %+v", s.notices)
	}
}

// GAP-1140: a small MicroVM disk an agent fills fast is warned about before
// it is full: at the rate it filled since the last look it would be full
// before the look after next, so the session warns at about 70%, not at 90%
// after the write already failed. A disk that does not fill is not.
func TestSessionWarnsAboutAFastFillingSmallDisk(t *testing.T) {
	prev, prevSmall := overlayDiskEvery, smallOverlayDiskEvery
	overlayDiskEvery, smallOverlayDiskEvery = time.Hour, 20*time.Millisecond
	t.Cleanup(func() { overlayDiskEvery, smallOverlayDiskEvery = prev, prevSmall })
	df70 := dfHeader + "/dev/vda           2097152 1468006    629146      70% /\n"
	for _, tc := range []struct {
		name    string
		answers []string
		warn    bool
	}{
		{"filling fast", []string{dfHalf, df70}, true},
		{"steady", []string{dfHalf, dfHalf, dfHalf}, false},
		// The early warning does not end the watch: the disk that then
		// fills is named too (GAP-1785).
		{"filling fast, then full", []string{dfHalf, df70, dfFull}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := vmCopySandbox("vmbox")
			ta := newTestApp(t, "", sb)
			ta.IO.TTY = false
			looks := 0
			ta.stream.answer = func(argv []string) (int, string) {
				if cmd := sandboxCommand(argv); len(cmd) > 0 && cmd[0] == "df" {
					looks++
					return 0, tc.answers[min(looks, len(tc.answers))-1]
				}
				return 0, ""
			}
			s := &session{app: ta.App, cli: ta.cli("gw"), sb: &sb}
			ctx, cancel := context.WithTimeout(bg, time.Duration(len(tc.answers))*smallOverlayDiskEvery+500*time.Millisecond)
			defer cancel()
			s.watchOverlayDisk(ctx)
			warned := strings.Contains(ta.err.String(), "own disk is 69% full")
			if warned != tc.warn || tc.warn && looks < 2 {
				t.Fatalf("warned %v after %d looks:\n%s", warned, looks, ta.err.String())
			}
			if full := strings.Contains(ta.err.String(), "own disk is 100% full"); full != (tc.answers[len(tc.answers)-1] == dfFull) {
				t.Fatalf("full disk named %v after %d looks:\n%s", full, looks, ta.err.String())
			}
		})
	}
}

func TestParseOverlayDF(t *testing.T) {
	for _, c := range []struct {
		out   string
		want  overlayDisk
		full  bool
		known bool
	}{
		{dfFull, overlayDisk{known: true, size: 2 << 30, avail: 0}, true, true},
		{dfHalf, overlayDisk{known: true, size: 2 << 30, avail: 1 << 30}, false, true},
		// A file system name with a space; fields count from the end.
		{dfHeader + "my disk 4194304 1048576 3145728 25% /\n", overlayDisk{known: true, size: 4 << 30, avail: 3 << 30}, false, true},
		{"", overlayDisk{}, false, false},
		{dfHeader, overlayDisk{}, false, false},
		{dfHeader + "overlay x y z 1% /\n", overlayDisk{}, false, false},
	} {
		got := parseOverlayDF(c.out)
		if got != c.want || got.full() != c.full || got.known != c.known {
			t.Errorf("parseOverlayDF(%q) = %+v (full %t), want %+v (full %t)", c.out, got, got.full(), c.want, c.full)
		}
	}
	if ExitStopKept != 5 {
		// The TUI reads this status (sandbox_panel.SANDBOX_STOP_KEPT_EXIT).
		t.Fatalf("ExitStopKept = %d, want 5", ExitStopKept)
	}
}
