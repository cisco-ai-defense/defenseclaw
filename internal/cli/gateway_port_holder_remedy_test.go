// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// GAP-0706: the root-gateway reason is a full sentence, so the start,
// restart, policy and scan messages that follow it with a period or a
// semicolon must not double the punctuation, and the remedy they carry is
// the one table for this OS.
func TestGAP0706RootGatewayMessagesHaveSinglePunctuation(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	oldHolder, oldClass := gatewayPortHolder, gatewayListenerClass
	t.Cleanup(func() { gatewayPortHolder, gatewayListenerClass = oldHolder, oldClass })
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: 1, UID: 0}, nil
	}
	gatewayListenerClass = func(string, int, string, daemon.PortHolder, error, bool) daemon.PerUserListenerClass {
		return daemon.PerUserListenerOwnGatewayRunAsRoot
	}
	c := config.DefaultConfig()
	c.Gateway.APIBind = "127.0.0.1"
	c.Gateway.APIPort = 18970

	problem := foreignGatewayListener(c)
	fix := foreignGatewayListenerFix(c)
	if problem != daemon.RootGatewayListenerReason || fix != daemon.RootGatewayListenerRemedy(config.DefaultDataPath()) {
		t.Fatalf("root listener = (%q, %q)", problem, fix)
	}
	for name, message := range map[string]string{
		"readiness": explainForeignListenerAtReadiness(c, errGatewayIdentityMismatch).Error(),
		"start":     "cannot start the gateway: " + problemClause(problem) + ". " + fix,
		"policy":    "policy reload: " + problemClause(problem) + "; the gateway token was not sent. " + fix,
	} {
		if strings.Contains(message, "..") || strings.Contains(message, ".;") {
			t.Errorf("%s message doubles punctuation: %q", name, message)
		}
		if !strings.Contains(message, "running as root") || !namesRootGatewayRemedy(runtime.GOOS, message) {
			t.Errorf("%s message lost the root reason or remedy: %q", name, message)
		}
	}
	if problemClause("held by another process") != "held by another process" {
		t.Fatal("a problem without a final period changed")
	}
}

// namesRootGatewayRemedy reports whether text carries the remedy of the
// given OS (GAP-0706, GAP-0746): macOS and Linux name the privileged
// stop with the account's home (sudo env DEFENSECLAW_HOME=), Windows names
// the elevated PowerShell prompt and never sudo.
func namesRootGatewayRemedy(goos, text string) bool {
	if goos == "windows" {
		return strings.Contains(text, "elevated PowerShell prompt") && !strings.Contains(text, "sudo ")
	}
	return strings.Contains(text, "sudo env DEFENSECLAW_HOME=")
}

// GAP-0746: the root-gateway remedy check follows the OS. Each OS accepts its
// own remedy only: the Unix sudo form is not a Windows remedy, and the
// elevated PowerShell prompt is not a macOS or Linux one.
func TestGAP0746RootGatewayRemedyCheckFollowsTheOS(t *testing.T) {
	const unix = "Stop it, return its files to your account and start it as yourself with: sudo env DEFENSECLAW_HOME='/h' '/bin/defenseclaw-gateway' stop && defenseclaw-gateway start"
	const windows = "Stop it from an elevated PowerShell prompt (& 'C:\\Users\\a\\bin\\defenseclaw-gateway.exe' stop), then start it as yourself from a normal PowerShell prompt (& 'C:\\Users\\a\\bin\\defenseclaw-gateway.exe' start)"
	for _, tc := range []struct {
		goos, text string
		want       bool
	}{
		{"linux", unix, true}, {"darwin", unix, true}, {"windows", windows, true},
		{"windows", unix, false}, {"linux", windows, false}, {"darwin", windows, false},
	} {
		if got := namesRootGatewayRemedy(tc.goos, tc.text); got != tc.want {
			t.Errorf("%s remedy check on %q = %v, want %v", tc.goos, tc.text, got, tc.want)
		}
	}
}

// GAP-0711, GAP-0713: gateway status, start and the other messages that carry
// the root-gateway remedy return the moved store as well as the install home.
func TestGAP0711RootGatewayStatusRemedyCoversMovedStore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows remedy has no ownership step")
	}
	home := t.TempDir()
	store := filepath.Join(t.TempDir(), "moved store")
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_CONFIG", "")
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("data_dir: "+strconv.Quote(store)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldHolder, oldClass := gatewayPortHolder, gatewayListenerClass
	t.Cleanup(func() { gatewayPortHolder, gatewayListenerClass = oldHolder, oldClass })
	gatewayPortHolder = func(string, int) (daemon.PortHolder, error) { return daemon.PortHolder{PID: 1, UID: 0}, nil }
	gatewayListenerClass = func(string, int, string, daemon.PortHolder, error, bool) daemon.PerUserListenerClass {
		return daemon.PerUserListenerOwnGatewayRunAsRoot
	}
	c := config.DefaultConfig()
	c.Gateway.APIBind = "127.0.0.1"
	c.Gateway.APIPort = 18970
	fix := foreignGatewayListenerFix(c)
	for _, dir := range []string{home, store} {
		if !strings.Contains(fix, "'"+dir+"'") {
			t.Errorf("status remedy leaves %s root-owned: %q", dir, fix)
		}
	}
	if !strings.Contains(fix, `sudo chown -R "$(id -un)" `) || !strings.HasSuffix(fix, "defenseclaw-gateway start") {
		t.Errorf("status remedy does not end with a start the account can run: %q", fix)
	}
}
