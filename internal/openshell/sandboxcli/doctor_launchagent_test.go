// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

func launchAgentDoctorFixture(t *testing.T, output string, launchErr error) (*testApp, *openshelltest.Runner) {
	t.Helper()
	ta := newTestApp(t, "")
	ta.GOOS = "darwin"
	ta.Geteuid = func() int { return 503 }
	ta.daemon.status.Managed = managedStatusFixture()
	ta.images.recs = readyImages(ta)

	// Keep the unrelated e2fsprogs row healthy so the ready verdict tests
	// isolate the loaded LaunchAgent's state.
	prefix, err := os.MkdirTemp("/tmp", "dc-launchagent-doctor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(prefix) })
	if err := os.Chmod(prefix, 0o755); err != nil {
		t.Fatal(err)
	}
	sbin := filepath.Join(prefix, "sbin")
	if err := os.MkdirAll(sbin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mke2fs", "debugfs"} {
		if err := os.WriteFile(filepath.Join(sbin, name), []byte("tool"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ta.ManagedE2fsprogsDir = func(context.Context) (string, bool) { return prefix, true }
	ta.ManagedAccountHome = func() (string, error) { return ta.home, nil }
	runner := &openshelltest.Runner{}
	runner.On("launchctl print gui/503/com.cisco.defenseclaw.openshell-gateway", output, launchErr)
	runner.On("launchctl print user/503/com.cisco.defenseclaw.openshell-gateway", "Could not find service \"com.cisco.defenseclaw.openshell-gateway\" in domain for uid: 503", errors.New("exit status 113"))
	ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		d.Runner = runner
		d.TrustedE2fsprogsDir = func(string, string) error { return nil }
		d.TrustedE2fsprogsFile = func(string, string) error { return nil }
		return hostReport(nil)(ctx, d)
	}
	return ta, runner
}

func TestManagedMacDoctorLaunchAgentVerdict(t *testing.T) {
	withManagedHost(t)
	const target = "gui/503/com.cisco.defenseclaw.openshell-gateway"
	for _, tc := range []struct {
		name, output, wantStatus, wantDetail string
		err                                  error
		wantRow                              bool
	}{
		{"code signing kill", target + " = {\n\tstate = not running\n\truns = 5\n\tlast exit reason = OS_REASON_CODESIGNING\n\tlast exit code = (never exited)\n}\n", "fail", "code signing", nil, true},
		{"running", target + " = {\n\tstate = running\n\truns = 1\n}\n", "pass", "running", nil, true},
		{"running after prior kill", target + " = {\n\tstate = running\n\truns = 6\n\tlast exit reason = OS_REASON_CODESIGNING\n}\n", "pass", "running", nil, true},
		{"cleanly idle", target + " = {\n\tstate = not running\n\truns = 1\n\tlast exit code = 0\n}\n", "pass", "loaded and idle", nil, true},
		{"idle prerequisite exit", target + " = {\n\tstate = not running\n\truns = 1\n\tlast exit code = 78: EX_CONFIG\n}\n", "warn", "prerequisite of this account", nil, true},
		{"idle other exit", target + " = {\n\tstate = not running\n\truns = 1\n\tlast exit code = 1\n}\n", "warn", "last exit code 1", nil, true},
		{"not loaded", "Could not find service \"com.cisco.defenseclaw.openshell-gateway\" in domain for uid: 503", "", "", errors.New("exit status 113"), false},
		{"no gui domain", "Could not find domain for port identifier: gui/503", "", "", errors.New("exit status 3"), false},
		{"other inspection error", "permission denied", "warn", "could not inspect", errors.New("launchctl failed"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta, runner := launchAgentDoctorFixture(t, tc.output, tc.err)
			rep := ta.runDoctor(bg)
			row := rep.Get("managed-openshell-launchagent")
			if !tc.wantRow {
				if row != nil {
					t.Fatalf("unexpected row: %+v", row)
				}
			} else {
				if row == nil || string(row.Status) != tc.wantStatus || !strings.Contains(row.Detail, tc.wantDetail) {
					t.Fatalf("LaunchAgent row = %+v; want %s containing %q", row, tc.wantStatus, tc.wantDetail)
				}
			}
			ta.printDoctor(rep)
			if tc.wantStatus == "fail" {
				if rep.OK() || row.Fix == nil || row.Fix.Command != "sudo defenseclaw-gateway enterprise macos repair" || !row.Fix.Sudo {
					t.Fatalf("failed job did not make doctor unready with administrator repair: %+v", row)
				}
				has(t, ta.output(), "not ready for sandboxes: 1 check failed", "sudo defenseclaw-gateway enterprise macos repair")
				lacks(t, ta.output(), "✓ ready for sandboxes")
			} else {
				if !rep.OK() {
					t.Fatalf("doctor not ready for a nonfailed job: %+v", rep.Checks)
				}
				if row != nil && row.Fix != nil {
					t.Fatalf("nonfailed job was sent to administrator repair: %+v", row.Fix)
				}
				has(t, ta.output(), "✓ ready for sandboxes")
				lacks(t, ta.output(), "not ready for sandboxes", "sudo defenseclaw-gateway enterprise macos repair")
			}
			calls := runner.Calls()
			if len(calls) != 2 || openshelltest.Argv(calls[0]) != "launchctl print "+target || openshelltest.Argv(calls[1]) != "launchctl print user/503/com.cisco.defenseclaw.openshell-gateway" || calls[0].Timeout != 10*time.Second || calls[1].Timeout != 10*time.Second {
				t.Fatalf("launchctl calls = %+v", calls)
			}
		})
	}
	t.Run("not darwin", func(t *testing.T) {
		ta, runner := launchAgentDoctorFixture(t, "", nil)
		ta.GOOS = "linux"
		if row := ta.runDoctor(bg).Get("managed-openshell-launchagent"); row != nil {
			t.Fatalf("Linux doctor has macOS row: %+v", row)
		}
		if calls := runner.Calls(); len(calls) != 0 {
			t.Fatalf("Linux doctor ran launchctl: %+v", calls)
		}
	})
	t.Run("unmanaged", func(t *testing.T) {
		prior := onManagedHost
		onManagedHost = func() bool { return false }
		t.Cleanup(func() { onManagedHost = prior })
		ta, runner := launchAgentDoctorFixture(t, "", nil)
		ta.daemon.status.Managed = nil
		if row := ta.runDoctor(bg).Get("managed-openshell-launchagent"); row != nil {
			t.Fatalf("unmanaged doctor has enterprise row: %+v", row)
		}
		if calls := runner.Calls(); len(calls) != 0 {
			t.Fatalf("unmanaged doctor ran launchctl: %+v", calls)
		}
	})
}

func TestManagedMacDoctorUserDomainLaunchAgent(t *testing.T) {
	withManagedHost(t)
	const gui = "gui/503/com.cisco.defenseclaw.openshell-gateway"
	const user = "user/503/com.cisco.defenseclaw.openshell-gateway"
	t.Run("ssh-only code signing", func(t *testing.T) {
		ta, runner := launchAgentDoctorFixture(t, "Bad request.\nCould not find domain for user gui: 503", errors.New("exit status 112"))
		runner.On("launchctl print "+user, user+" = {\n\tstate = not running\n\truns = 5\n\tlast exit reason = OS_REASON_CODESIGNING\n}\n", nil)
		rep := ta.runDoctor(bg)
		row := rep.Get(openshell.CheckIDManagedLaunchAgent)
		if row == nil || row.Status != openshell.StatusFail || !strings.Contains(row.Detail, user) || row.Fix == nil || !strings.Contains(row.Fix.Command, "enterprise macos repair") || rep.OK() {
			t.Fatalf("doctor missed failed user-domain job: %+v", row)
		}
		ta.printDoctor(rep)
		has(t, ta.output(), "not ready for sandboxes", "sudo defenseclaw-gateway enterprise macos repair")
		if calls := runner.Calls(); len(calls) != 2 || openshelltest.Argv(calls[0]) != "launchctl print "+gui || openshelltest.Argv(calls[1]) != "launchctl print "+user {
			t.Fatalf("domain inspection calls = %+v", calls)
		}
	})
	t.Run("both domains missing", func(t *testing.T) {
		ta, runner := launchAgentDoctorFixture(t, "Could not find domain for user gui: 503", errors.New("exit status 112"))
		if row := ta.runDoctor(bg).Get(openshell.CheckIDManagedLaunchAgent); row != nil {
			t.Fatalf("unexpected row: %+v", row)
		}
		if len(runner.Calls()) != 2 {
			t.Fatalf("did not inspect both domains: %+v", runner.Calls())
		}
	})
	t.Run("user domain inspection error", func(t *testing.T) {
		ta, runner := launchAgentDoctorFixture(t, "Could not find domain for user gui: 503", errors.New("exit status 112"))
		runner.On("launchctl print "+user, "permission denied", errors.New("launchctl failed"))
		rep := ta.runDoctor(bg)
		row := rep.Get(openshell.CheckIDManagedLaunchAgent)
		if row == nil || row.Status != openshell.StatusWarn || !strings.Contains(row.Detail, user) || !rep.OK() || row.Fix != nil {
			t.Fatalf("unexpected inspection verdict: %+v", row)
		}
	})
}

func TestManagedMacDoctorLaunchAgentFailureExitsNonzero(t *testing.T) {
	withManagedHost(t)
	ta, _ := launchAgentDoctorFixture(t, "gui/503/com.cisco.defenseclaw.openshell-gateway = {\n\tstate = not running\n\truns = 5\n\tlast exit reason = OS_REASON_CODESIGNING\n}\n", nil)
	wantExit(t, ta.RunDoctor(bg, DoctorOptions{}), 1)
	has(t, ta.output(), "not ready for sandboxes: 1 check failed", "sudo defenseclaw-gateway enterprise macos repair")
}

func TestManagedMacDoctorIdleExit78RemainsReady(t *testing.T) {
	withManagedHost(t)
	ta, _ := launchAgentDoctorFixture(t, "gui/503/com.cisco.defenseclaw.openshell-gateway = {\n\tstate = not running\n\truns = 1\n\tlast exit code = 78: EX_CONFIG\n}\n", nil)
	if err := ta.RunDoctor(bg, DoctorOptions{}); err != nil {
		t.Fatalf("doctor failed for a deliberate idle exit: %v", err)
	}
	has(t, ta.output(), "ready for sandboxes", "prerequisite of this account")
	lacks(t, ta.output(), "sudo defenseclaw-gateway enterprise macos repair")
}
