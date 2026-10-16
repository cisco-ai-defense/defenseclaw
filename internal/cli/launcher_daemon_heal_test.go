// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

const launcherCodeSigningState = "state = not running\nruns = 2\nlast exit reason = OS_REASON_CODESIGNING\n"

func TestLauncherLaunchAgentPreKickstartHeal(t *testing.T) {
	const healthy = "state = not running\nruns = 0\nlast exit code = (never exited)\n"
	for _, tc := range []struct {
		name, sandbox, gateway, failedBootstrap string
		restart                                 bool
		wantReload                              string
	}{
		{name: "sandbox code signing", sandbox: launcherCodeSigningState, gateway: healthy, wantReload: launcherAgentLabel},
		{name: "gateway code signing", sandbox: healthy, gateway: launcherCodeSigningState, wantReload: launcherGatewayLabel},
		{name: "gateway spawn error", sandbox: healthy, gateway: "state = not running\nlast spawn error = operation not permitted\n", wantReload: launcherGatewayLabel},
		{name: "healthy idle", sandbox: "state = not running\nlast exit code = 78\n", gateway: healthy},
		{name: "running job with stale reason", sandbox: "state = running\nlast exit reason = OS_REASON_CODESIGNING\n", gateway: "state = running\nlast spawn error = old failure\n"},
		{name: "failed bootstrap", sandbox: healthy, gateway: launcherCodeSigningState, wantReload: launcherGatewayLabel, failedBootstrap: launcherGatewayPlist},
		{name: "restart reload", sandbox: healthy, gateway: launcherCodeSigningState, wantReload: launcherGatewayLabel, restart: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			old := launcherRun
			launcherRun = func(_ context.Context, name string, args ...string) (string, error) {
				line := strings.Join(args, " ")
				calls = append(calls, line)
				if name != launcherLaunchctl {
					t.Fatalf("unexpected command %q", name)
				}
				switch line {
				case "print gui/501":
					return "", nil
				case "print gui/501/" + launcherAgentLabel:
					return tc.sandbox, nil
				case "print gui/501/" + launcherGatewayLabel:
					return tc.gateway, nil
				}
				if strings.HasPrefix(line, "bootstrap ") && tc.failedBootstrap != "" && strings.HasSuffix(line, tc.failedBootstrap) {
					return "bootstrap failed", errors.New("exit status 1")
				}
				return "", nil
			}
			t.Cleanup(func() { launcherRun = old })
			var err error
			if tc.restart {
				err = launcherRestartDaemon(context.Background(), "darwin", 501)
			} else {
				err = launcherStartDaemon(context.Background(), "darwin", 501)
			}
			if tc.failedBootstrap != "" {
				if err == nil || !strings.Contains(err.Error(), launcherRepairCommand) {
					t.Fatalf("failed reload did not name repair: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			want := []string{"print gui/501", "print gui/501/" + launcherAgentLabel}
			if tc.wantReload == launcherAgentLabel {
				want = append(want, "bootout gui/501/"+launcherAgentLabel, "bootstrap gui/501 "+launcherAgentPlist)
			}
			want = append(want, "print gui/501/"+launcherGatewayLabel)
			if tc.wantReload == launcherGatewayLabel {
				want = append(want, "bootout gui/501/"+launcherGatewayLabel, "bootstrap gui/501 "+launcherGatewayPlist)
			}
			if tc.failedBootstrap == "" {
				kick := "kickstart gui/501/" + launcherAgentLabel
				if tc.restart {
					kick = "kickstart -k gui/501/" + launcherAgentLabel
				}
				want = append(want, kick)
			}
			if strings.Join(calls, "\n") != strings.Join(want, "\n") {
				t.Fatalf("launchctl calls:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
			}
			for _, line := range calls {
				if strings.Contains(line, "/com.cisco.defenseclaw.") && !strings.Contains(line, "/"+launcherAgentLabel) && !strings.Contains(line, "/"+launcherGatewayLabel) {
					t.Fatalf("another label was touched: %q", line)
				}
			}
		})
	}
}

type launcherHealStatus struct {
	kickstarts *int
	alwaysDown bool
}

func (s launcherHealStatus) Status(context.Context) (*sandboxapi.Status, error) {
	if !s.alwaysDown && *s.kickstarts >= 2 {
		return &sandboxapi.Status{Enabled: true, Available: true}, nil
	}
	return nil, errors.New("daemon unavailable")
}

func TestLauncherFirstUseHealAfterFailedAwait(t *testing.T) {
	for _, tc := range []struct {
		name, afterKickstart string
		alwaysDown           bool
		wantBootout          int
	}{
		{name: "code signing appears after first kickstart", afterKickstart: launcherCodeSigningState, wantBootout: 1},
		{name: "healthy job never reloads", afterKickstart: "state = not running\nlast exit code = (never exited)\n", alwaysDown: true},
		{name: "persistent failure reloads only once", afterKickstart: launcherCodeSigningState, alwaysDown: true, wantBootout: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fastLauncherWaits(t)
			var calls []string
			kickstarts, bootouts := 0, 0
			old := launcherRun
			launcherRun = func(_ context.Context, name string, args ...string) (string, error) {
				line := strings.Join(args, " ")
				calls = append(calls, line)
				if name != launcherLaunchctl {
					t.Fatalf("unexpected command %q", name)
				}
				switch line {
				case "print gui/501/" + launcherGatewayLabel:
					return "state = running\n", nil
				case "print gui/501/" + launcherAgentLabel:
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
			t.Cleanup(func() { launcherRun = old })
			var stderr bytes.Buffer
			_, err := launcherEnsureDaemon(context.Background(), launcherHealStatus{kickstarts: &kickstarts, alwaysDown: tc.alwaysDown}, "darwin", 501, &stderr)
			if tc.alwaysDown {
				if err == nil || !strings.Contains(err.Error(), "was started but does not answer") {
					t.Fatalf("timeout wording changed: %v", err)
				}
			} else if err != nil {
				t.Fatalf("first-use recovery: %v", err)
			}
			if bootouts != tc.wantBootout || kickstarts != 1+tc.wantBootout {
				t.Fatalf("mutations bootout=%d kickstart=%d, calls %v", bootouts, kickstarts, calls)
			}
			if bootouts == 1 && !strings.Contains(strings.Join(calls, "\n"), "bootstrap gui/501 "+launcherAgentPlist) {
				t.Fatalf("the failed job was not bootstrapped: %v", calls)
			}
		})
	}
}
