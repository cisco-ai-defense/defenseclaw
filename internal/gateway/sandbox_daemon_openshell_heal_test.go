// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// With no tagged plist installed, the job has the bare label of 1.0.0 to
// 1.0.3 (openshell.FindLaunchAgent).
const (
	openShellGatewayLabel = openshell.GatewayAgentBase
	openShellGatewayPlist = openshell.LaunchAgentsDir + "/" + openshell.GatewayAgentBase + ".plist"
)

const gatewayCodeSigningState = "state = not running\nruns = 2\nlast exit reason = OS_REASON_CODESIGNING\n"

func TestAccountOpenShellLaunchAgentPreKickstartHeal(t *testing.T) {
	for _, tc := range []struct {
		name, state     string
		wantReload      bool
		failedBootstrap bool
	}{
		{name: "code signing", state: gatewayCodeSigningState, wantReload: true},
		{name: "spawn error", state: "state = not running\nlast spawn error = operation not permitted\n", wantReload: true},
		{name: "healthy idle", state: "state = not running\nlast exit code = 78\n"},
		{name: "never exited", state: "state = not running\nruns = 0\nlast exit code = (never exited)\n"},
		{name: "running with stale reason", state: "state = running\nlast exit reason = OS_REASON_CODESIGNING\n"},
		{name: "failed bootstrap", state: gatewayCodeSigningState, wantReload: true, failedBootstrap: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newOpenShellRig(t, "darwin")
			var calls []string
			r.o.run = func(_ context.Context, name string, args, _ []string) (string, error) {
				if name != daemonLaunchctl {
					t.Fatalf("unexpected command %q", name)
				}
				line := strings.Join(args, " ")
				calls = append(calls, line)
				if line == "print gui/5001/"+openShellGatewayLabel {
					return tc.state, nil
				}
				if tc.failedBootstrap && line == "bootstrap gui/5001 "+openShellGatewayPlist {
					return "bootstrap failed", errors.New("exit status 1")
				}
				return "", nil
			}
			reloaded, err := r.o.startUnit(context.Background())
			if tc.failedBootstrap {
				if err == nil || !strings.Contains(err.Error(), openShellGatewayRepairCommand) {
					t.Fatalf("bootstrap failure did not name repair: %v", err)
				}
			} else if err != nil || reloaded != tc.wantReload {
				t.Fatalf("startUnit reloaded=%v err=%v", reloaded, err)
			}
			want := []string{"print gui/5001", "print user/5001", "print gui/5001/" + openShellGatewayLabel}
			if tc.wantReload {
				want = append(want, "bootout gui/5001/"+openShellGatewayLabel, "bootstrap gui/5001 "+openShellGatewayPlist)
			}
			if !tc.failedBootstrap {
				want = append(want, "kickstart gui/5001/"+openShellGatewayLabel)
			}
			if strings.Join(calls, "\n") != strings.Join(want, "\n") {
				t.Fatalf("launchctl calls:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

func TestAccountOpenShellReloadFailureReachesPerson(t *testing.T) {
	r := newOpenShellRig(t, "darwin")
	r.o.run = func(_ context.Context, _ string, args, _ []string) (string, error) {
		line := strings.Join(args, " ")
		if line == "print gui/5001/"+openShellGatewayLabel {
			return gatewayCodeSigningState, nil
		}
		if strings.HasPrefix(line, "bootstrap ") {
			return "raw launchctl failure", errors.New("exit status 1")
		}
		return "", nil
	}
	_, err := r.o.ensureRunning(context.Background(), 17670, "")
	if err == nil || !strings.Contains(err.Error(), openShellGatewayRepairCommand) || strings.Contains(err.Error(), "raw launchctl failure") {
		t.Fatalf("person-facing reload error: %v", err)
	}
}

func TestAccountOpenShellFirstUseHealAfterKickstart(t *testing.T) {
	for _, tc := range []struct {
		name, afterKickstart string
		listenAfterReload    bool
		wantReload           int
	}{
		{name: "code signing appears after first kickstart", afterKickstart: gatewayCodeSigningState, listenAfterReload: true, wantReload: 1},
		{name: "healthy job never reloads", afterKickstart: "state = not running\nlast exit code = (never exited)\n"},
		{name: "persistent failure reloads only once", afterKickstart: gatewayCodeSigningState, wantReload: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wait, poll, heal := openShellGatewayStartWait, openShellGatewayPollEvery, openShellGatewayHealAfter
			openShellGatewayStartWait, openShellGatewayPollEvery, openShellGatewayHealAfter = 80*time.Millisecond, 5*time.Millisecond, 0
			t.Cleanup(func() {
				openShellGatewayStartWait, openShellGatewayPollEvery, openShellGatewayHealAfter = wait, poll, heal
			})
			r := newOpenShellRig(t, "darwin")
			kickstarts, bootouts := 0, 0
			var calls []string
			r.o.portHolder = func(int) (int, bool) {
				if tc.listenAfterReload && kickstarts >= 2 {
					return r.o.uid, true
				}
				return 0, false
			}
			r.o.run = func(_ context.Context, name string, args, _ []string) (string, error) {
				if name != daemonLaunchctl {
					t.Fatalf("unexpected command %q", name)
				}
				line := strings.Join(args, " ")
				calls = append(calls, line)
				if line == "print gui/5001/"+openShellGatewayLabel {
					if kickstarts > 0 {
						return tc.afterKickstart, nil
					}
					return "state = not running\nlast exit code = (never exited)\n", nil
				}
				if strings.HasPrefix(line, "kickstart ") {
					kickstarts++
				}
				if strings.HasPrefix(line, "bootout ") {
					bootouts++
				}
				return "", nil
			}
			_, err := r.o.ensureRunning(context.Background(), 17670, "")
			if tc.listenAfterReload {
				if err != nil {
					t.Fatalf("first-use recovery: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "did not start listening") {
				t.Fatalf("timeout wording changed: %v", err)
			}
			if bootouts != tc.wantReload || kickstarts != 1+tc.wantReload {
				t.Fatalf("mutations bootout=%d kickstart=%d, calls %v", bootouts, kickstarts, calls)
			}
			if bootouts == 1 && !strings.Contains(strings.Join(calls, "\n"), "bootstrap gui/5001 "+openShellGatewayPlist) {
				t.Fatalf("the failed job was not bootstrapped: %v", calls)
			}
		})
	}
}

func TestAccountOpenShellListeningBeforeGraceDoesNotInspectAgain(t *testing.T) {
	r := newOpenShellRig(t, "darwin")
	prints, kickstarts := 0, 0
	r.o.portHolder = func(int) (int, bool) {
		if kickstarts > 0 {
			return r.o.uid, true
		}
		return 0, false
	}
	r.o.run = func(_ context.Context, _ string, args, _ []string) (string, error) {
		line := strings.Join(args, " ")
		if line == "print gui/5001/"+openShellGatewayLabel {
			prints++
			return "state = not running\nlast exit code = (never exited)\n", nil
		}
		if strings.HasPrefix(line, "kickstart ") {
			kickstarts++
		}
		return "", nil
	}
	if _, err := r.o.ensureRunning(context.Background(), 17670, ""); err != nil || prints != 1 {
		t.Fatalf("happy path: err=%v job prints=%d", err, prints)
	}
}

// The daemon bootstraps and starts the gateway job of the installed, tagged
// label, not the bare one 1.0.0 to 1.0.3 installed, whose start macOS
// killed for code signing after an upgrade (GAP-0206).
func TestAccountOpenShellStartsTheTaggedGatewayLabel(t *testing.T) {
	fastGatewayWaits(t)
	dir := t.TempDir()
	tagged := openshell.GatewayAgentBase + ".0123456789ab"
	if err := os.WriteFile(filepath.Join(dir, tagged+".plist"), []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := openShellLaunchAgentsDir
	openShellLaunchAgentsDir = dir
	t.Cleanup(func() { openShellLaunchAgentsDir = old })
	r := newOpenShellRig(t, "darwin")
	r.fail["launchctl print"] = "Could not find domain"
	r.holder = func(call int) int {
		if call < 3 {
			return 0
		}
		return 5001
	}
	if _, err := r.o.Prepare(context.Background(), setupSettings()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	got := strings.Join(r.ran(), "\n")
	for _, want := range []string{
		"launchctl bootstrap user/5001 " + filepath.Join(dir, tagged+".plist"),
		"launchctl kickstart user/5001/" + tagged,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("commands lack %q:\n%s", want, got)
		}
	}
}

// TestAccountOpenShellStartsTheGatewayAgentWhereItIsLoaded (GAP-0863): the
// OpenShell gateway job of a fresh AD account was loaded in its background
// domain (user/<uid>), and the daemon's bootstrap of it into gui/<uid>,
// which launchd refuses for a label the account already has, failed with
// "Bootstrap failed: 5: Input/output error". The daemon now starts it in
// the domain that has it.
func TestAccountOpenShellStartsTheGatewayAgentWhereItIsLoaded(t *testing.T) {
	r := newOpenShellRig(t, "darwin")
	var calls []string
	r.o.run = func(_ context.Context, _ string, args, _ []string) (string, error) {
		line := strings.Join(args, " ")
		calls = append(calls, line)
		switch {
		case line == "print gui/5001":
			return "gui/5001 = {\n}\n", nil
		case line == "print user/5001":
			return "user/5001 = {\n\tservices = {\n\t\t0\t-\t" + openShellGatewayLabel + "\n\t}\n}\n", nil
		case line == "print user/5001/"+openShellGatewayLabel:
			return "state = not running\nruns = 0\nlast exit code = (never exited)\n", nil
		case strings.HasPrefix(line, "print gui/5001/"):
			return "Could not find service", errors.New("exit status 113")
		case strings.HasPrefix(line, "bootstrap gui/5001 "):
			return "Bootstrap failed: 5: Input/output error", errors.New("exit status 5")
		}
		return "", nil
	}
	if _, err := r.o.startUnit(context.Background()); err != nil {
		t.Fatalf("startUnit: %v (calls %q)", err, calls)
	}
	want := []string{"print gui/5001", "print user/5001", "print user/5001/" + openShellGatewayLabel, "kickstart user/5001/" + openShellGatewayLabel}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("launchctl calls:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}
}
