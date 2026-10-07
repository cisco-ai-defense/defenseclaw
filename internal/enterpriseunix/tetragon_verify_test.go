// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

var readinessNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// stubTetragonAccounts names the test users through NSS.
func stubTetragonAccounts(t *testing.T) {
	t.Helper()
	old := tetragonAccount
	tetragonAccount = func(uid int) (string, string) {
		switch uid {
		case 1001:
			return "dcr-std1", "/home/dcr-std1"
		case 1002:
			return "dcr-std2", "/home/dcr-std2"
		case 1003:
			return "dcr-std3", "/home/dcr-std3"
		}
		return "", ""
	}
	t.Cleanup(func() { tetragonAccount = old })
}

// readyInputs is a host where mode runs healthy: Tetragon 1.7.1 reachable on
// a trusted socket, the helper running and fresh, Plane C on, claudecode in
// action mode, listeners on loopback.
func readyInputs(mode string) tetragonInputs {
	yes, no := true, false
	in := tetragonInputs{
		GOOS: "linux", HaveIntent: true, Running: true,
		Intent: tetragonIntent{Written: mode != "consume", Configured: mode, Mode: mode, BurnIn: "168h", CustomerEvents: "agent",
			PlaneC: true, ActionCLI: []string{"claudecode"}},
		Host: tetragonHost{Installed: true, Address: "unix:///var/run/tetragon/tetragon.sock", Path: "/var/run/tetragon/tetragon.sock",
			Verdict: "trusted (root-owned unix socket)"},
		State: kernelpolicy.State{FileState: kernelpolicy.FileState{
			UpdatedAt: readinessNow.Add(-30 * time.Second), KernelPolicy: kernelpolicy.Digest(), InSync: true,
			Intent:   kernelpolicy.IntentStatus{Mode: kernelpolicy.Mode(mode), BurnIn: "168h"},
			Tetragon: kernelpolicy.TetragonStatus{Reachable: true, Version: "v1.7.1", PID: 912, LSM: &yes, KeepSensorsOnExit: &no},
		}, BurnIn: kernelpolicy.BurnInFile{UIDs: map[string]*kernelpolicy.UIDRecord{}}},
	}
	in.Extra.Tetragon.MetricsAddress, in.Extra.Tetragon.HealthAddress = "127.0.0.1:2112", "127.0.0.1:6789"
	if mode == "enforce" {
		in.Intent.EnforceConnectors = []string{"claudecode"}
	}
	return in
}

// withUsers adds the promotion fixture: dcr-std1 finished burn-in,
// dcr-std2 is a quarter of the way (~9 days to go at its rate), dcr-std3 was
// reset by a would-block hit.
func withUsers(in tetragonInputs) tetragonInputs {
	hit := time.Date(2026, 10, 7, 9, 12, 0, 0, time.UTC)
	in.State.UIDs = []kernelpolicy.UIDStatus{
		{UID: 1001, User: "dcr-std1", Connectors: []string{"claudecode"}, State: kernelpolicy.UIDMonitor, Reason: "observe mode",
			AnchoredRoots: 1, CoveredSeconds: 168 * 3600, NeededSeconds: 168 * 3600},
		{UID: 1002, User: "dcr-std2", Connectors: []string{"claudecode"}, State: kernelpolicy.UIDMonitor, Reason: "observe mode",
			CoveredSeconds: 40*3600 + 1800, NeededSeconds: 168 * 3600},
		{UID: 1003, User: "dcr-std3", Connectors: []string{"claudecode"}, State: kernelpolicy.UIDMonitor, Reason: "observe mode",
			NeededSeconds: 168 * 3600, WouldBlock: 1},
	}
	in.State.BurnIn.UIDs = map[string]*kernelpolicy.UIDRecord{
		"1001": {WindowStart: readinessNow.Add(-30 * 24 * time.Hour)},
		"1002": {WindowStart: readinessNow.Add(-69 * time.Hour)},
		"1003": {WindowStart: hit, WouldBlock: map[string]*kernelpolicy.HitStats{
			"kernel.ssh_private_key_read": {Count: 1, First: hit, Last: hit,
				Paths:    []kernelpolicy.Counted{{Value: "/home/dcr-std3/.ssh/id_ed25519", Count: 1}},
				Binaries: []kernelpolicy.Counted{{Value: "/usr/bin/python3.11", Count: 1}}},
		}},
	}
	return in
}

var readyProbes = tetragonProbes{TetragonActive: true, LSM: "lockdown,capability,yama,selinux,bpf", LSMKnown: true}

func checkOf(t *testing.T, rep *TetragonReadiness, id string) TetragonCheck {
	t.Helper()
	for _, check := range rep.Checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("no check %s in %+v", id, rep.Checks)
	return TetragonCheck{}
}

func readinessText(t *testing.T, rep *TetragonReadiness) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteTetragonReadiness(&buf, rep, false); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// Every check row: what passes, what fails, warns or informs, and when it
// does not apply.
func TestTetragonReadinessChecks(t *testing.T) {
	stubTetragonAccounts(t)
	yes, no := true, false
	type want struct{ id, status, says string }
	for _, tc := range []struct {
		name     string
		mode     string
		readyFor string
		edit     func(*tetragonInputs, *tetragonProbes)
		want     []want
	}{
		{"healthy consume", "consume", "consume", nil, []want{
			{checkTetragonInstalled, checkPass, "installed"}, {checkTetragonRunning, checkPass, "pid 912"},
			{checkTetragonAPI, checkPass, "unix socket"}, {checkTetragonSocket, checkPass, "root-owned"},
			{checkTetragonVersion, checkPass, "v1.7.1 is supported for consume"}, {checkTetragonStream, checkPass, "reads Tetragon's events"},
			{checkKeepSensorsOnExit, checkSkip, "only enforce"}, {checkBPFLSM, checkSkip, "only enforce"},
			{checkMetricsLoopback, checkPass, "loopback"}, {checkHealthLoopback, checkPass, "loopback"}, {checkPlaneC, checkPass, "on"},
			{checkAgents, checkSkip, ""}, {checkApproval, checkSkip, ""}, {checkOrphans, checkPass, ""},
			{checkTetragonYourPolicy, checkInfo, "never changes your own Tetragon policies"},
		}},
		{"no tetragon: only the install fails", "consume", "consume", func(in *tetragonInputs, p *tetragonProbes) {
			in.Host = tetragonHost{Verdict: "not installed (no " + tetragonInfoPath + ")"}
			in.State.Tetragon = kernelpolicy.TetragonStatus{}
			p.TetragonActive = false
		}, []want{
			{checkTetragonInstalled, checkFail, "install Tetragon 1.7.x"}, {checkTetragonRunning, checkSkip, ""},
			{checkTetragonStream, checkSkip, ""}, {checkPlaneC, checkPass, ""},
		}},
		{"tcp api", "consume", "consume", func(in *tetragonInputs, _ *tetragonProbes) {
			in.Host = tetragonHost{Installed: true, Address: "localhost:54321", TCP: true}
		}, []want{{checkTetragonAPI, checkFail, "localhost:54321"}, {checkTetragonSocket, checkSkip, ""}}},
		{"untrusted socket", "consume", "consume", func(in *tetragonInputs, _ *tetragonProbes) {
			in.Host.Verdict = "refused: /var/run/tetragon is not root-owned or is world-writable"
			in.Host.UntrustedPath, in.Host.UntrustedOwner, in.Host.UntrustedPerm = "/var/run/tetragon", "uid 1000", "0777"
		}, []want{{checkTetragonSocket, checkFail, "found owner uid 1000, mode 0777"}}},
		{"1.6 consumes", "consume", "consume", func(in *tetragonInputs, _ *tetragonProbes) { in.State.Tetragon.Version = "v1.6.2" },
			[]want{{checkTetragonVersion, checkPass, "v1.6.2"}}},
		{"1.6 cannot observe", "consume", "observe", func(in *tetragonInputs, _ *tetragonProbes) { in.State.Tetragon.Version = "1.6.2" },
			[]want{{checkTetragonVersion, checkFail, "Tetragon v1.6.2 is not supported for observe"}}},
		{"version unknown", "consume", "consume", func(in *tetragonInputs, _ *tetragonProbes) { in.State.Tetragon.Version = "" },
			[]want{{checkTetragonVersion, checkWarn, "not known"}}},
		{"helper stopped", "consume", "consume", func(in *tetragonInputs, p *tetragonProbes) { in.Running = false },
			[]want{{checkTetragonStream, checkFail, "not running"}, {checkTetragonRunning, checkPass, ""}}},
		{"stale stream", "consume", "consume", func(in *tetragonInputs, p *tetragonProbes) {
			in.State.UpdatedAt = readinessNow.Add(-10 * time.Minute)
			p.TetragonActive = false
		}, []want{{checkTetragonStream, checkFail, "does not read"}, {checkTetragonRunning, checkFail, "not running"}}},
		{"mode off has no stream to check", "off", "consume", func(in *tetragonInputs, _ *tetragonProbes) {
			in.Intent.Mode, in.Intent.Configured, in.Intent.Written = "off", "off", true
		}, []want{{checkTetragonStream, checkSkip, "mode off"}}},
		{"keep sensors unknown", "observe", "enforce", func(in *tetragonInputs, _ *tetragonProbes) { in.State.Tetragon.KeepSensorsOnExit = nil },
			[]want{{checkKeepSensorsOnExit, checkFail, "not known"}}},
		{"keep sensors on", "observe", "enforce", func(in *tetragonInputs, _ *tetragonProbes) { in.State.Tetragon.KeepSensorsOnExit = &yes },
			[]want{{checkKeepSensorsOnExit, checkFail, "keeps sensors on exit"}}},
		{"no bpf lsm", "observe", "enforce", func(in *tetragonInputs, p *tetragonProbes) {
			in.State.Tetragon.LSM, p.LSM = &no, "lockdown,capability,yama,selinux"
		}, []want{{checkBPFLSM, checkFail, "lockdown,capability,yama,selinux"}}},
		{"lsm probe not reported", "observe", "enforce", func(in *tetragonInputs, _ *tetragonProbes) { in.State.Tetragon.LSM = nil },
			[]want{{checkBPFLSM, checkWarn, "not reported"}}},
		{"listeners on every interface", "consume", "consume", func(in *tetragonInputs, _ *tetragonProbes) {
			in.Extra.Tetragon.MetricsAddress, in.Extra.Tetragon.HealthAddress = ":2112", "0.0.0.0:6789"
		}, []want{{checkMetricsLoopback, checkWarn, "every interface (:2112)"}, {checkHealthLoopback, checkWarn, "0.0.0.0:6789"}}},
		{"ipv6 loopback, unknown metrics", "consume", "consume", func(in *tetragonInputs, _ *tetragonProbes) {
			in.Extra.Tetragon.MetricsAddress, in.Extra.Tetragon.HealthAddress = "", "[::1]:6789"
		}, []want{{checkMetricsLoopback, checkSkip, ""}, {checkHealthLoopback, checkPass, ""}}},
		{"metrics off, health from tetragon.conf.d", "consume", "consume", func(in *tetragonInputs, _ *tetragonProbes) {
			in.Extra.Tetragon.MetricsAddress, in.Extra.Tetragon.HealthAddress = "", ""
			in.Host.MetricsKnown, in.Host.HealthAddress = true, "127.0.0.1:6789"
		}, []want{{checkMetricsLoopback, checkWarn, "serves no metrics endpoint (without metrics, events lost reads unknown)"},
			{checkHealthLoopback, checkPass, "127.0.0.1:6789"}}},
		{"plane c off", "consume", "consume", func(in *tetragonInputs, _ *tetragonProbes) { in.Intent.PlaneC = false },
			[]want{{checkPlaneC, checkFail, "Plane C is off"}}},
		{"agents unknown in consume", "consume", "observe", nil, []want{{checkAgents, checkInfo, "once mode observe runs"}}},
		{"agents in observe", "observe", "observe", func(in *tetragonInputs, _ *tetragonProbes) { *in = withUsers(*in) },
			[]want{{checkAgents, checkPass, "3 enrolled users have an agent (dcr-std1, dcr-std2, dcr-std3)"}}},
		{"nobody enrolled", "observe", "observe", nil, []want{{checkAgents, checkWarn, "no user is enrolled"}}},
		{"no agent for enforce", "enforce", "enforce", func(in *tetragonInputs, _ *tetragonProbes) {
			in.State.UIDs = []kernelpolicy.UIDStatus{{UID: 1001, User: "dcr-std1", Connectors: []string{"claudecode"},
				State: kernelpolicy.UIDInactive, Reason: kernelpolicy.ReasonNoAnchors, NeededSeconds: 3600}}
			in.Intent.ObserveCLI = []string{"codex"}
		}, []want{{checkAgents, checkFail, "no agent seen for dcr-std1; no enrolled user has a row for codex"},
			{checkConnectorsAction, checkWarn, "codex is in observe mode"}}},
		{"approval missing", "observe", "enforce", func(in *tetragonInputs, _ *tetragonProbes) { *in = withUsers(*in) },
			[]want{{checkApproval, checkInfo, "not approved yet"}, {checkBurnIn, checkInfo, "1 of 3"},
				{checkConnectorsAction, checkPass, "claudecode"}}},
		{"approval stale", "enforce", "enforce", func(in *tetragonInputs, _ *tetragonProbes) {
			*in = withUsers(*in)
			in.Intent.EnforceAck = []string{"sha256:000000000000"}
		}, []want{{checkApproval, checkInfo, "does not include this build's"}}},
		{"approval list approves", "enforce", "enforce", func(in *tetragonInputs, _ *tetragonProbes) {
			*in = withUsers(*in)
			in.Intent.EnforceAck = []string{"sha256:000000000000", kernelpolicy.Digest()}
		}, []want{{checkApproval, checkPass, "approves"}}},
		{"paused", "enforce", "enforce", func(in *tetragonInputs, _ *tetragonProbes) {
			in.State.Pause = &kernelpolicy.PauseState{Pause: &kernelpolicy.Pause{Until: readinessNow.Add(2 * time.Hour), SetByUID: 1001,
				SetAt: readinessNow, Reason: "dccert ticket"}}
		}, []want{{checkPause, checkWarn, "set by dcr-std1 (uid 1001)"}}},
		{"operator override", "observe", "observe", func(in *tetragonInputs, _ *tetragonProbes) {
			in.State.Overrides = map[kernelpolicy.Family]kernelpolicy.Override{kernelpolicy.FamilyConnect: {Kind: kernelpolicy.OverrideDeleted}}
		}, []want{{checkOverrides, checkWarn, "connect deleted"}}},
		{"orphaned policies", "consume", "consume", func(in *tetragonInputs, _ *tetragonProbes) {
			in.Running, in.State.Loaded = false, []string{"defenseclaw-controls-0a1b2c3d"}
		}, []want{{checkOrphans, checkFail, "defenseclaw-controls-0a1b2c3d"}}},
		{"your policies", "consume", "consume", func(in *tetragonInputs, _ *tetragonProbes) {
			in.Extra.CustomerPolicies = []customerPolicyStatus{{Name: "10-file-sensitive", Mode: "enforce"}, {Name: "20-net-connect", Mode: "monitor"}}
		}, []want{{checkTetragonYourPolicy, checkInfo, "2 of your Tetragon policies are loaded (1 enforcing)"}}},
		{"a customer policy in DefenseClaw's pattern", "consume", "consume", func(in *tetragonInputs, _ *tetragonProbes) {
			in.State.Warnings = []string{kernelpolicy.WarnForeignName + ":defenseclaw-controls-deadbeef"}
		}, []want{{checkTetragonYourPolicy, checkWarn, "defenseclaw-controls-deadbeef has DefenseClaw's name pattern but is yours"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, probes := readyInputs(tc.mode), readyProbes
			if tc.edit != nil {
				tc.edit(&in, &probes)
			}
			rep := tetragonReadiness(in, tc.readyFor, probes, readinessNow)
			for _, w := range tc.want {
				check := checkOf(t, rep, w.id)
				if check.Status != w.status || !strings.Contains(check.Message, w.says) {
					t.Errorf("%s = %s %q; want %s containing %q", w.id, check.Status, check.Message, w.status, w.says)
				}
			}
			if len(rep.Checks) != len(tetragonCheckIDs) {
				t.Fatalf("%d checks, want %d", len(rep.Checks), len(tetragonCheckIDs))
			}
			failed := false
			for _, check := range rep.Checks {
				failed = failed || check.Status == checkFail
				for _, fix := range check.Fix {
					if strings.HasPrefix(fix, "sudo ") && !runnableHint(fix) && !strings.HasPrefix(fix, "sudo systemctl restart tetragon   # ") {
						t.Errorf("%s fix %q does not run as printed", check.ID, fix)
					}
				}
			}
			if rep.Ready == failed {
				t.Fatalf("ready = %v with failing checks %v", rep.Ready, failed)
			}
		})
	}
}

// Burn-in progress and ETA: percent of the needed hours, "measuring" before
// the window is a day old, an ETA from the rate of agent use so far, and a
// reset after a would-block hit.
func TestBurnInProgressAndETA(t *testing.T) {
	user := kernelpolicy.UIDStatus{UID: 1002, CoveredSeconds: 40*3600 + 1800, NeededSeconds: 168 * 3600}
	p := progressOf(user, &kernelpolicy.UIDRecord{WindowStart: readinessNow.Add(-69 * time.Hour)}, readinessNow)
	if p.Percent != 24 || !p.HasETA || humanDuration(p.ETA) != "~9 days" || p.Ready || p.Measuring {
		t.Fatalf("progress %+v (%s)", p, humanDuration(p.ETA))
	}
	if p := progressOf(user, &kernelpolicy.UIDRecord{WindowStart: readinessNow.Add(-23 * time.Hour)}, readinessNow); !p.Measuring || p.HasETA {
		t.Fatalf("a window younger than a day is still measuring: %+v", p)
	}
	idle := kernelpolicy.UIDStatus{UID: 1002, NeededSeconds: 168 * 3600}
	if p := progressOf(idle, &kernelpolicy.UIDRecord{WindowStart: readinessNow.Add(-72 * time.Hour)}, readinessNow); p.HasETA || p.Percent != 0 {
		t.Fatalf("no agent use gives no ETA: %+v", p)
	}
	if p := progressOf(kernelpolicy.UIDStatus{CoveredSeconds: 3600}, nil, readinessNow); !p.Ready || p.Percent != 100 {
		t.Fatalf("burn_in 0 is ready at once: %+v", p)
	}
	none := kernelpolicy.UIDStatus{State: kernelpolicy.UIDInactive, Reason: kernelpolicy.ReasonNoAnchors, NeededSeconds: 3600}
	if p := progressOf(none, &kernelpolicy.UIDRecord{WindowStart: readinessNow.Add(-72 * time.Hour)}, readinessNow); !p.NoAgent || p.HasETA {
		t.Fatalf("a user without an anchored agent has no ETA: %+v", p)
	}
	for hours, want := range map[float64]string{0.2: "~1 hour", 5: "~5 hours", 47: "~47 hours", 49: "~2 days", 217: "~9 days"} {
		if got := humanDuration(time.Duration(hours * float64(time.Hour))); got != want {
			t.Errorf("humanDuration(%vh) = %q, want %q", hours, got, want)
		}
	}
	in := withUsers(readyInputs("observe"))
	if eta, ok := nextReady(in.State, readinessNow); !ok || humanDuration(eta) != "~9 days" {
		t.Fatalf("next ready %v %v", eta, ok)
	}
}

// The promotion guide as an administrator reads it: the burn-in table with
// progress, ETA and hit details, the approve block and the summary. Every
// line fits 80 columns except a copy-paste command.
func TestTetragonReadyForEnforceText(t *testing.T) {
	stubTetragonAccounts(t)
	rep := tetragonReadiness(withUsers(readyInputs("observe")), "enforce", readyProbes, readinessNow)
	got := readinessText(t, rep)
	digest := kernelpolicy.Digest()
	want := `Tetragon readiness for enforce (this host runs observe)
  ✓ Tetragon is installed (/var/run/tetragon/tetragon-info.json)
  ✓ Tetragon is running (pid 912)
  ✓ API: unix socket /var/run/tetragon/tetragon.sock
  ✓ The socket and its directory are root-owned and not world-writable
  ✓ Tetragon v1.7.1 is supported for enforce
  ✓ The sensor helper reads Tetragon's events
  ✓ Tetragon does not keep sensors on exit
  ✓ BPF LSM is enabled
  ✓ Tetragon's metrics endpoint listens on loopback (127.0.0.1:2112)
  ✓ Tetragon's health endpoint listens on loopback (127.0.0.1:6789)
  ✓ AI Discovery Plane C is on
  ✓ 3 enrolled users have an agent (dcr-std1, dcr-std2, dcr-std3)
  ✓ Every enrolled command-line connector is in action mode (claudecode)
  i This build's kernel controls are not approved yet; approve them (below)
  i 1 of 3 enrolled users finished burn-in on this host
  Burn-in (168h of agent use, no would-block hit, per user on this host):
    USER             PROGRESS              ETA       HITS
    dcr-std1 (1001)   168.0h/168h  ready   -         0
    dcr-std2 (1002)    40.5h/168h   24%    ~9 days   0
    dcr-std3 (1003)     0.0h/168h  reset   -         1
      ssh_private_key_read: ~/.ssh/id_ed25519 by /usr/bin/python3.11
        last 2026-10-07T09:12:00Z. Stays in monitor until 168h pass with no hit.
        If the tool is expected, this user cannot be enforced for this control
        in this release; other users are not affected.
  ✓ Kernel enforcement is not paused
  ✓ No operator override
  ✓ No DefenseClaw policy is left without a sensor helper
  i DefenseClaw never changes your own Tetragon policies; it reads their events
  Approve this build's kernel controls (same value on every host of it):
    enterprise:
      tetragon:
        mode: enforce
        enforce_ack: ` + digest + `
Ready for enforce: 1 of 3 users would be enforced now; the others stay in monitor until their burn-in completes.
Set the approve block above in your admin config and apply it with your config management.
`
	if got != want {
		t.Fatalf("text:\n%s\nwant:\n%s", got, want)
	}
	assertColumns(t, got, 80)
}

// assertColumns: every line fits width, except a copy-paste command or a
// Next: sentence, which keep their own unwrapped line.
func assertColumns(t *testing.T, text string, width int) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if len([]rune(line)) <= width || strings.HasPrefix(trimmed, "sudo ") || strings.HasPrefix(trimmed, "echo ") ||
			strings.HasPrefix(trimmed, "`sudo ") || strings.Contains(trimmed, "enforce_ack: [") ||
			strings.HasPrefix(line, "Ready") || strings.HasPrefix(line, "Not ready") || strings.HasPrefix(line, "Set ") ||
			strings.HasPrefix(line, "Next:") || strings.HasPrefix(line, "and apply") {
			continue
		}
		t.Errorf("line over %d columns (%d): %q", width, len([]rune(line)), line)
	}
}

// The other fixtures: consume ready for observe, a stale approval in
// enforce, a paused host, and a host that fails.
func TestTetragonReadinessTextFixtures(t *testing.T) {
	stubTetragonAccounts(t)
	consume := readinessText(t, tetragonReadiness(readyInputs("consume"), "observe", readyProbes, readinessNow))
	for _, want := range []string{
		"Tetragon readiness for observe (this host runs consume)\n",
		"  i The sensor helper checks enrolled users' agents once mode observe runs;",
		"Ready for observe. Next: in your admin config set\n  enterprise:\n    tetragon:\n      mode: observe\nand apply it with your config management",
	} {
		if !strings.Contains(consume, want) {
			t.Fatalf("consume text lacks %q:\n%s", want, consume)
		}
	}
	assertColumns(t, consume, 80)

	stale := withUsers(readyInputs("enforce"))
	stale.Intent.EnforceAck = []string{"sha256:000000000000"}
	text := readinessText(t, tetragonReadiness(stale, "enforce", readyProbes, readinessNow))
	for _, want := range []string{
		"  i The approval (enforce_ack sha256:000000000000) does not include this build's\n    " + kernelpolicy.Digest(),
		"    # ring upgrade: enforce_ack: [sha256:000000000000, " + kernelpolicy.Digest() + "]\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("stale text lacks %q:\n%s", want, text)
		}
	}
	assertColumns(t, text, 80)

	paused := readyInputs("enforce")
	paused.State.Pause = &kernelpolicy.PauseState{Pause: &kernelpolicy.Pause{UntilReboot: true, SetByUID: 1001, SetAt: readinessNow, Reason: "dccert"}}
	text = readinessText(t, tetragonReadiness(paused, "enforce", readyProbes, readinessNow))
	if !strings.Contains(text, "  ! Kernel enforcement on this host is paused until the next reboot (set by\n    dcr-std1 (uid 1001)") ||
		!strings.Contains(text, "      sudo "+adminBinDir+"/defenseclaw-gateway enterprise linux tetragon resume\n") {
		t.Fatalf("paused text:\n%s", text)
	}
	assertColumns(t, text, 80)

	broken := readyInputs("observe")
	broken.Intent.PlaneC = false
	broken.Host = tetragonHost{Installed: true, Address: "localhost:54321", TCP: true}
	rep := tetragonReadiness(broken, "observe", readyProbes, readinessNow)
	text = readinessText(t, rep)
	for _, want := range []string{
		"  ✗ Tetragon serves its API on localhost:54321",
		"      echo unix:///var/run/tetragon/tetragon.sock | sudo tee /etc/tetragon/tetragon.conf.d/server-address\n",
		"      sudo systemctl restart tetragon   # this drops policies added with tetra; tetragon.tp.d policies reload\n",
		"      ai_discovery:\n        runtime:\n          enabled: true\n          enable_host_plane: true\n",
		"Not ready for observe: 2 checks fail (tetragon.api, defenseclaw.plane_c). Fix them, then run again:\n" +
			"  sudo " + adminBinDir + "/defenseclaw-gateway enterprise linux tetragon verify --ready-for observe\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("failing text lacks %q:\n%s", want, text)
		}
	}
	if rep.Ready {
		t.Fatal("a failing host reads ready")
	}
	assertColumns(t, text, 80)

	if got := readinessText(t, tetragonReadiness(readyInputs("observe"), "observe", readyProbes, readinessNow)); !strings.Contains(got, "Ready: this host runs observe as its config asks.\n") {
		t.Fatalf("a healthy observe host:\n%s", got)
	}
}

func compileTetragonVerifySchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "tetragon_verify.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	if err := compiler.AddResource("tetragon_verify.schema.json", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("tetragon_verify.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func validateReadiness(t *testing.T, schema *jsonschema.Schema, rep *TetragonReadiness) {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteTetragonReadiness(&buf, rep, true); err != nil {
		t.Fatal(err)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("readiness does not match the schema: %v\n%s", err, buf.String())
	}
}

// RunTetragonVerify: exit 0 when no check fails, 1 when one does or when not
// root, 2 for bad arguments and off Linux; the JSON follows the schema.
func TestTetragonVerifyExitCodesAndSchema(t *testing.T) {
	stubTetragonAccounts(t)
	schema := compileTetragonVerifySchema(t)
	ctx := context.Background()
	h := tetragonCLIHost(t)

	// No Tetragon on the host: tetragon.installed fails, exit 1.
	missing := RunTetragonVerify(ctx, h.env, "consume")
	validateReadiness(t, schema, missing)
	if missing.OK || missing.ExitCode != 1 || checkOf(t, missing, checkTetragonInstalled).Status != checkFail {
		t.Fatalf("no tetragon: exit %d %+v", missing.ExitCode, missing.Errors)
	}

	// Tetragon installed and trusted, the helper reachable: ready, exit 0.
	writeHostFile(t, h, tetragonInfoPath, `{"server_address":"unix:///var/run/tetragon/tetragon.sock","pid":912}`)
	writeHostFile(t, h, "/var/run/tetragon/tetragon.sock", "")
	h.owners[h.env.P("/var/run/tetragon/tetragon.sock")] = [2]int{0, 0}
	h.owners[h.env.P("/var/run/tetragon")] = [2]int{0, 0}
	yes, no := true, false
	h.writeTetragonState(kernelpolicy.FileState{Version: 1, UpdatedAt: time.Now().UTC(), KernelPolicy: kernelpolicy.Digest(), Effective: "observe", InSync: true,
		Intent:   kernelpolicy.IntentStatus{Mode: kernelpolicy.ModeObserve, BurnIn: "168h"},
		Tetragon: kernelpolicy.TetragonStatus{Reachable: true, Version: "v1.7.1", PID: 912, LSM: &yes, KeepSensorsOnExit: &no}})
	ready := RunTetragonVerify(ctx, h.env, "")
	validateReadiness(t, schema, ready)
	if !ready.OK || ready.ExitCode != 0 || ready.ReadyFor != "observe" || ready.Mode != "observe" {
		t.Fatalf("ready: exit %d for %s %+v", ready.ExitCode, ready.ReadyFor, ready.Checks)
	}
	enforce := RunTetragonVerify(ctx, h.env, "enforce")
	validateReadiness(t, schema, enforce)
	if enforce.Approve == nil || enforce.Approve.State != "missing" {
		t.Fatalf("enforce approval %+v", enforce.Approve)
	}

	for name, run := range map[string]func() *TetragonReadiness{
		"unknown mode": func() *TetragonReadiness { return RunTetragonVerify(ctx, h.env, "audit") },
		"macos":        func() *TetragonReadiness { return RunTetragonVerify(ctx, newTestHost(t, "darwin").env, "") },
	} {
		rep := run()
		validateReadiness(t, schema, rep)
		if rep.OK || rep.ExitCode != 2 {
			t.Fatalf("%s: exit %d %+v", name, rep.ExitCode, rep.Errors)
		}
	}
	h.env.Geteuid = func() int { return 1000 }
	if rep := RunTetragonVerify(ctx, h.env, ""); rep.OK || rep.ExitCode != 1 || rep.Errors[0].Code != codeNotRoot {
		t.Fatalf("non-root: %+v", rep)
	}
}

// verify reads files only: with a TCP API in the info file and no socket it
// still reports, and no Tetragon source of this package dials anything.
func TestTetragonVerifyNeverOpensASocket(t *testing.T) {
	stubTetragonAccounts(t)
	h := tetragonCLIHost(t)
	writeHostFile(t, h, tetragonInfoPath, `{"server_address":"localhost:54321","pid":912}`)
	rep := RunTetragonVerify(context.Background(), h.env, "consume")
	if check := checkOf(t, rep, checkTetragonAPI); check.Status != checkFail || !strings.Contains(check.Message, "localhost:54321") {
		t.Fatalf("tcp api: %+v", check)
	}
	files, _ := filepath.Glob("tetragon_*.go")
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range parsed.Imports {
			if path := strings.Trim(spec.Path.Value, `"`); strings.Contains(path, "grpc") || path == "net/http" || strings.HasSuffix(path, "sensor/tetragon") {
				t.Errorf("%s imports %s", file, path)
			}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			if sel, ok := node.(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "net" && strings.HasPrefix(sel.Sel.Name, "Dial") {
					t.Errorf("%s calls net.%s", file, sel.Sel.Name)
				}
			}
			return true
		})
	}
}

// Every field the readiness report renders is described by the schema.
func TestTetragonVerifySchemaDescribesEveryField(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "tetragon_verify.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	keys := func(node map[string]any) []string {
		var out []string
		for key := range node["properties"].(map[string]any) {
			out = append(out, key)
		}
		sort.Strings(out)
		return out
	}
	fields := func(value any) []string {
		var out []string
		typ := reflect.TypeOf(value)
		for i := 0; i < typ.NumField(); i++ {
			name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
			out = append(out, name)
		}
		sort.Strings(out)
		return out
	}
	props := schema["properties"].(map[string]any)
	items := func(node any) map[string]any { return node.(map[string]any)["items"].(map[string]any) }
	users := items(props["users"])
	for _, tc := range []struct {
		node  map[string]any
		value any
	}{
		{schema, TetragonReadiness{}},
		{items(props["checks"]), TetragonCheck{}},
		{users, TetragonUserReadiness{}},
		{items(users["properties"].(map[string]any)["hits"]), TetragonHitDetail{}},
		{props["approve"].(map[string]any), TetragonApproval{}},
	} {
		if got, want := keys(tc.node), fields(tc.value); !reflect.DeepEqual(got, want) {
			t.Fatalf("%T: schema properties %v, fields %v", tc.value, got, want)
		}
	}
	ids := items(props["checks"])["properties"].(map[string]any)["id"].(map[string]any)["enum"].([]any)
	if len(ids) != len(tetragonCheckIDs) {
		t.Fatalf("schema check ids %v, code %v", ids, tetragonCheckIDs)
	}
	for i, id := range ids {
		if id != tetragonCheckIDs[i] {
			t.Fatalf("schema check id %d is %v, code %s", i, id, tetragonCheckIDs[i])
		}
	}
}
