// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

type refreshFailModesResult struct {
	Config    string   `json:"config"`
	Refreshed []string `json:"refreshed"`
}

// runRefreshFailModesForTest runs the installers' pre-swap refresh against
// home, as the staged gateway does.
func runRefreshFailModesForTest(t *testing.T, home string) refreshFailModesResult {
	t.Helper()
	previousCfg, previousDir, previousJSON := cfg, connectorFlagDataDir, connectorFlagJSON
	t.Cleanup(func() { cfg, connectorFlagDataDir, connectorFlagJSON = previousCfg, previousDir, previousJSON })
	connectorFlagDataDir, connectorFlagJSON = home, true
	var out bytes.Buffer
	connectorRefreshFailModesCmd.SetOut(&out)
	t.Cleanup(func() { connectorRefreshFailModesCmd.SetOut(nil) })
	if err := runConnectorRefreshFailModes(connectorRefreshFailModesCmd, nil); err != nil {
		t.Fatal(err)
	}
	var result refreshFailModesResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("refresh output %q: %v", out.String(), err)
	}
	return result
}

// oldHookFailMode is the mode a 0.8.10-1.0.3 native hook reads for connector
// from hooks/.hookcfg: the fail_modes entry, whatever its source.
func oldHookFailMode(t *testing.T, home, connector string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, "hooks", ".hookcfg"))
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		FailModes map[string]string `json:"fail_modes"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state.FailModes[connector]
}

func isolateHookEnvForTest(t *testing.T, home string) {
	t.Helper()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_CONFIG", "")
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "")
	t.Setenv("DEFENSECLAW_FAIL_MODE", "")
}

// A Windows 0.8.x upgrade: the 0.8.x config (config_version 7) cannot load
// before 'defenseclaw migrate', and the 0.8.10 sidecar holds the open 0.8.x
// resolved for an unset mode under observe. The refresh reads the config's
// explicit fail modes and closes it, so the old hook and the new one both
// fail closed while the gateway is down for the swap.
func TestRefreshFailModesClosesA08xSidecarOpenNobodySet(t *testing.T) {
	home := t.TempDir()
	isolateHookEnvForTest(t, home)
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("config_version: 7\nguardrail:\n  mode: observe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open","claudecode":"open"}}`)
	if got := oldHookFailMode(t, home, "codex"); got != "open" {
		t.Fatalf("precondition: the old hook reads %q", got)
	}

	result := runRefreshFailModesForTest(t, home)
	if result.Config != "document" || !reflect.DeepEqual(result.Refreshed, []string{"claudecode", "codex"}) {
		t.Fatalf("refresh %+v", result)
	}
	for _, name := range []string{"codex", "claudecode"} {
		if got := oldHookFailMode(t, home, name); got != "closed" {
			t.Fatalf("the old %s hook reads %q, want closed", name, got)
		}
		if got := buildHookOptions(name, "PreToolUse", "", "").FailMode; got != "closed" {
			t.Fatalf("the new %s hook fails %q, want closed", name, got)
		}
	}
}

// An older per-user open in a 0.8.x config outside the data directory
// (DEFENSECLAW_CONFIG) is closed during the upgrade, including in the sidecar.
func TestRefreshFailModesClosesAnExternalConfigsOpen(t *testing.T) {
	home := t.TempDir()
	isolateHookEnvForTest(t, home)
	external := filepath.Join(t.TempDir(), "defenseclaw.yaml")
	if err := os.WriteFile(external, []byte("config_version: 7\nguardrail:\n  mode: observe\n  hook_fail_mode: open\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"}}`)
	if got := buildHookOptions("codex", "PreToolUse", "", "").FailMode; got != "closed" {
		t.Fatalf("precondition: the new hook fails %q before the refresh", got)
	}

	t.Setenv("DEFENSECLAW_CONFIG", external)
	if result := runRefreshFailModesForTest(t, home); result.Config != "document" || !reflect.DeepEqual(result.Refreshed, []string{"codex"}) {
		t.Fatalf("refresh %+v", result)
	}
	t.Setenv("DEFENSECLAW_CONFIG", "")
	if got := buildHookOptions("codex", "PreToolUse", "", "").FailMode; got != "closed" {
		t.Fatalf("the new hook fails %q, want closed", got)
	}
	if got := oldHookFailMode(t, home, "codex"); got != "closed" {
		t.Fatalf("the old hook fails %q, want closed", got)
	}
}

// A loaded config: an earlier render recorded Copilot's unset mode as open
// (lowered because its vendor hook surface cannot fail closed) without a
// source. The refresh writes the closed outage mode for every per-user hook,
// including one whose older config chose open.
func TestRefreshFailModesDoesNotTreatACapabilityOpenAsTheConfigs(t *testing.T) {
	for _, test := range []struct {
		name, config, want string
	}{
		{name: "unset", config: "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n", want: "closed"},
		{name: "older operator open", config: "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n  connectors:\n    copilot:\n      hook_fail_mode: open\n", want: "closed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			isolateHookEnvForTest(t, home)
			if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(test.config), 0o600); err != nil {
				t.Fatal(err)
			}
			// What the earlier render recorded for Copilot: open, no source.
			writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"copilot":"open"}}`)
			if got := buildHookOptions("copilot", "preToolUse", "", "").FailMode; got != test.want {
				t.Fatalf("before the refresh the native hook fails %q, want %q", got, test.want)
			}
			if result := runRefreshFailModesForTest(t, home); result.Config != "loaded" || !reflect.DeepEqual(result.Refreshed, []string{"copilot"}) {
				t.Fatalf("refresh %+v", result)
			}
			if got := oldHookFailMode(t, home, "copilot"); got != test.want {
				t.Fatalf("refreshed copilot mode %q, want %q", got, test.want)
			}
			if got := buildHookOptions("copilot", "preToolUse", "", "").FailMode; got != test.want {
				t.Fatalf("the native hook fails %q, want %q", got, test.want)
			}
		})
	}
}

// A previous Cursor render could record open in observe mode. The refresh
// closes it for every per-user upgrade, loaded or pre-migration document.
func TestRefreshFailModesClosesACursorOpenNobodyChose(t *testing.T) {
	const v9 = "config_version: 9\nobservability: {}\nguardrail:\n"
	const v7 = "config_version: 7\nguardrail:\n"
	for _, test := range []struct {
		name, config, read, want string
	}{
		{"1.0.x observe, unset", v9 + "  mode: observe\n", "loaded", "closed"},
		{"1.0.x observe, cursor open", v9 + "  mode: observe\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", "loaded", "closed"},
		{"1.0.x action, cursor open", v9 + "  mode: action\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", "loaded", "closed"},
		{"0.8.x observe, unset", v7 + "  mode: observe\n", "document", "closed"},
		{"0.8.x observe, cursor open", v7 + "  mode: observe\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", "document", "closed"},
		{"0.8.x action, cursor open", v7 + "  mode: action\n  connectors:\n    cursor:\n      hook_fail_mode: open\n", "document", "closed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			isolateHookEnvForTest(t, home)
			if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(test.config), 0o600); err != nil {
				t.Fatal(err)
			}
			// The 0.8.10 to 1.0.3 render for an observe Cursor.
			writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"cursor":"open"}}`)
			if result := runRefreshFailModesForTest(t, home); result.Config != test.read || !reflect.DeepEqual(result.Refreshed, []string{"cursor"}) {
				t.Fatalf("refresh %+v", result)
			}
			if got := oldHookFailMode(t, home, "cursor"); got != test.want {
				t.Fatalf("the old cursor hook reads %q, want %q", got, test.want)
			}
			if got := buildHookOptions("cursor", "beforeShellExecution", "", "").FailMode; got != test.want {
				t.Fatalf("the new cursor hook fails %q, want %q", got, test.want)
			}
		})
	}
}

// A managed install's hooks take their mode from protected state: the
// refresh leaves its sidecar alone, loaded or not.
func TestRefreshFailModesLeavesAManagedInstallAlone(t *testing.T) {
	home := t.TempDir()
	isolateHookEnvForTest(t, home)
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("config_version: 7\ndeployment_mode: managed_enterprise\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const body = `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"}}`
	writeHookSidecarForTest(t, home, body)
	if result := runRefreshFailModesForTest(t, home); len(result.Refreshed) != 0 {
		t.Fatalf("refresh %+v", result)
	}
	if got, _ := os.ReadFile(filepath.Join(home, "hooks", ".hookcfg")); string(got) != body {
		t.Fatalf("managed sidecar rewritten: %s", got)
	}
}

// An older automatic protection overlay may hold open in a 0.8.x document.
// The refresh closes every per-user sidecar during the upgrade.
func TestRefreshFailModesClosesA08xAutomaticProtectionOpen(t *testing.T) {
	const ap = "application_protection:\n  enabled: true\n"
	for _, test := range []struct {
		name, doc string
		want      map[string]string
	}{
		{"overlay open", "config_version: 7\nguardrail:\n  mode: observe\n" + ap + "  guardrail:\n    hook_fail_mode: open\n",
			map[string]string{"codex": "closed", "claudecode": "closed"}},
		{"connector overlay open", "config_version: 7\nguardrail:\n  mode: observe\n" + ap + "  connectors:\n    claudecode:\n      guardrail:\n        hook_fail_mode: open\n",
			map[string]string{"codex": "closed", "claudecode": "closed"}},
		{"set up by hand", "config_version: 7\nguardrail:\n  mode: observe\n  connectors:\n    codex:\n      hook_fail_mode: open\n" + ap + "  guardrail:\n    hook_fail_mode: closed\n",
			map[string]string{"codex": "closed", "claudecode": "closed"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			isolateHookEnvForTest(t, home)
			if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(test.doc), 0o600); err != nil {
				t.Fatal(err)
			}
			writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open","claudecode":"open"}}`)
			if result := runRefreshFailModesForTest(t, home); result.Config != "document" {
				t.Fatalf("refresh %+v", result)
			}
			for name, want := range test.want {
				if got := oldHookFailMode(t, home, name); got != want {
					t.Fatalf("the old %s hook reads %q, want %q", name, got, want)
				}
				if got := buildHookOptions(name, "PreToolUse", "", "").FailMode; got != want {
					t.Fatalf("the new %s hook fails %q, want %q", name, got, want)
				}
			}
		})
	}
}

// The installers run the refresh with --hold-until-exit for a running
// gateway: it says when the first refresh is written and the lock held,
// and it ends only once that gateway has exited.
func TestRefreshFailModesHoldsUntilTheGatewayExits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sleep(1) as the gateway")
	}
	home := t.TempDir()
	isolateHookEnvForTest(t, home)
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("config_version: 7\nguardrail:\n  mode: observe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"}}`)
	gateway := exec.Command("sleep", "60")
	if err := gateway.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Process.Kill(); _ = gateway.Wait() })

	previousCfg, previousDir, previousJSON := cfg, connectorFlagDataDir, connectorFlagJSON
	previousPID, previousTimeout := refreshFailModesHoldPID, refreshFailModesHoldTimeout
	t.Cleanup(func() {
		cfg, connectorFlagDataDir, connectorFlagJSON = previousCfg, previousDir, previousJSON
		refreshFailModesHoldPID, refreshFailModesHoldTimeout = previousPID, previousTimeout
		connectorRefreshFailModesCmd.SetOut(nil)
	})
	connectorFlagDataDir, connectorFlagJSON = home, false
	refreshFailModesHoldPID, refreshFailModesHoldTimeout = gateway.Process.Pid, time.Minute
	reader, writer := io.Pipe()
	connectorRefreshFailModesCmd.SetOut(writer)
	done := make(chan error, 1)
	go func() {
		err := runConnectorRefreshFailModes(connectorRefreshFailModesCmd, nil)
		_ = writer.Close()
		done <- err
	}()
	holding := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), hookFailModeHoldMarker) {
				close(holding)
			}
		}
	}()
	select {
	case <-holding:
	case err := <-done:
		t.Fatalf("the hold ended before the gateway exited: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the hold never said it was holding")
	}
	if got := oldHookFailMode(t, home, "codex"); got != "closed" {
		t.Fatalf("while holding the old hook reads %q, want closed", got)
	}
	select {
	case err := <-done:
		t.Fatalf("the hold ended while the gateway runs: %v", err)
	default:
	}
	_ = gateway.Process.Kill()
	_ = gateway.Wait()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the hold did not end after the gateway exited")
	}
}

// W4b loop round 2: install.ps1 stops with its install unfinished (a restore
// a running hook refused leaves the failed install's programs beside data
// they do not match, with the gateway down). It closes every hook with
// --closed, an open the config chooses included, so no hook follows an
// outage open until the gateway renders them again. A managed install is
// left alone, and --closed never takes a hold.
func TestRefreshFailModesClosedClosesEveryHookWhateverTheConfigChooses(t *testing.T) {
	previous := refreshFailModesClosed
	t.Cleanup(func() { refreshFailModesClosed = previous })
	for _, test := range []struct{ name, doc string }{
		{"loaded config open", "config_version: 9\nguardrail:\n  mode: action\n  hook_fail_mode: open\n"},
		{"0.8.x document open", "config_version: 7\nguardrail:\n  mode: observe\n  hook_fail_mode: open\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			isolateHookEnvForTest(t, home)
			if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(test.doc), 0o600); err != nil {
				t.Fatal(err)
			}
			writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open","claudecode":"open"}}`)
			refreshFailModesClosed = false
			runRefreshFailModesForTest(t, home)
			if got := oldHookFailMode(t, home, "codex"); got != "closed" {
				t.Fatalf("per-user config open stayed active, got %q", got)
			}
			refreshFailModesClosed = true
			if result := runRefreshFailModesForTest(t, home); !reflect.DeepEqual(result.Refreshed, []string{"claudecode", "codex"}) {
				t.Fatalf("refresh %+v", result)
			}
			for _, name := range []string{"codex", "claudecode"} {
				if got := oldHookFailMode(t, home, name); got != "closed" {
					t.Fatalf("the old %s hook reads %q, want closed", name, got)
				}
				if got := buildHookOptions(name, "PreToolUse", "", "").FailMode; got != "closed" {
					t.Fatalf("the new %s hook fails %q, want closed", name, got)
				}
			}
		})
	}
	t.Run("managed install", func(t *testing.T) {
		home := t.TempDir()
		isolateHookEnvForTest(t, home)
		if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("config_version: 7\ndeployment_mode: managed_enterprise\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		const body = `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"}}`
		writeHookSidecarForTest(t, home, body)
		refreshFailModesClosed = true
		if result := runRefreshFailModesForTest(t, home); len(result.Refreshed) != 0 {
			t.Fatalf("refresh %+v", result)
		}
		if got, _ := os.ReadFile(filepath.Join(home, "hooks", ".hookcfg")); string(got) != body {
			t.Fatalf("managed sidecar rewritten: %s", got)
		}
	})
	t.Run("no hold", func(t *testing.T) {
		previousPID, previousDir, previousJSON := refreshFailModesHoldPID, connectorFlagDataDir, connectorFlagJSON
		t.Cleanup(func() {
			refreshFailModesHoldPID, connectorFlagDataDir, connectorFlagJSON = previousPID, previousDir, previousJSON
		})
		home := t.TempDir()
		isolateHookEnvForTest(t, home)
		connectorFlagDataDir, connectorFlagJSON, refreshFailModesHoldPID, refreshFailModesClosed = home, false, os.Getpid(), true
		if err := runConnectorRefreshFailModes(connectorRefreshFailModesCmd, nil); err == nil || !strings.Contains(err.Error(), "--closed does not take --hold-until-exit") {
			t.Fatalf("--closed with a hold: %v", err)
		}
	})
}
