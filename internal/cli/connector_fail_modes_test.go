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

func TestRefreshFailModesUsesConfiguredDataDirectoryWithoutInstallerOverride(t *testing.T) {
	home := t.TempDir()
	dataDir := t.TempDir()
	isolateHookEnvForTest(t, home)
	configPath := filepath.Join(home, "config.yaml")
	configBody := "config_version: 9\ndata_dir: " + dataDir + "\nobservability: {}\nguardrail:\n  mode: action\n  rule_pack: strict\n"
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"}}`)
	writeHookSidecarForTest(t, dataDir, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"}}`)
	previousCfg, previousDir, previousJSON := cfg, connectorFlagDataDir, connectorFlagJSON
	t.Cleanup(func() { cfg, connectorFlagDataDir, connectorFlagJSON = previousCfg, previousDir, previousJSON })
	connectorFlagDataDir, connectorFlagJSON = "", true
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
	if result.Config != "loaded" || !reflect.DeepEqual(result.Refreshed, []string{"codex"}) {
		t.Fatalf("refresh %+v", result)
	}
	if got := oldHookFailMode(t, dataDir, "codex"); got != "closed" {
		t.Fatalf("configured data dir hook mode = %q, want closed", got)
	}
	if got := oldHookFailMode(t, home, "codex"); got != "open" {
		t.Fatalf("default home hook mode = %q, want untouched open", got)
	}
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

// A per-user 0.8.x config may still contain open outside the data directory.
// The upgrade refresh closes the old sidecar and the new hook stays closed.
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
}

// A loaded config: an earlier render recorded Copilot's unset mode as open
// (lowered because its vendor hook surface cannot fail closed) without a
// source. The native hook does not trust that open; the refresh writes the
// outage mode of the policy tier with its config source (oss-outage-open):
// open for the default tier, closed for strict, and a saved value, open or
// closed, wins over either (BALANCED-DEFAULTS owner decision 2026-10-23).
// Every other native hook failure stays closed.
func TestRefreshFailModesWritesThePolicyTiersOutageMode(t *testing.T) {
	for _, test := range []struct {
		name, config, want string
	}{
		{name: "default tier", config: "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n", want: "open"},
		{name: "default tier, saved closed", config: "config_version: 9\nobservability: {}\nguardrail:\n  mode: action\n  connectors:\n    copilot:\n      hook_fail_mode: closed\n", want: "closed"},
		{name: "strict tier", config: "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n  rule_pack: strict\n", want: "closed"},
		{name: "strict tier, saved open", config: "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n  rule_pack: strict\n  connectors:\n    copilot:\n      hook_fail_mode: open\n", want: "open"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			isolateHookEnvForTest(t, home)
			if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(test.config), 0o600); err != nil {
				t.Fatal(err)
			}
			// What the earlier render recorded for Copilot: open, no source.
			writeHookSidecarForTest(t, home, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"copilot":"open"}}`)
			if result := runRefreshFailModesForTest(t, home); result.Config != "loaded" || !reflect.DeepEqual(result.Refreshed, []string{"copilot"}) {
				t.Fatalf("refresh %+v", result)
			}
			if got := oldHookFailMode(t, home, "copilot"); got != test.want {
				t.Fatalf("refreshed copilot mode %q, want %q", got, test.want)
			}
			if got := hookOutageFailModeNow("copilot", filepath.Join(home, "hooks")); got != test.want {
				t.Fatalf("the native hook's call-time outage mode is %q, want %q", got, test.want)
			}
		})
	}
}

// Cursor: a 1.0.x refresh recorded its observe mode open whatever the
// config said. The refresh now writes the policy tier's outage mode in
// observe and action mode alike, and a saved value wins over the tier; a
// 0.8.x document the release cannot load yet is closed until the migrated
// config renders the hooks.
func TestRefreshFailModesGivesCursorThePolicyTiersOutageMode(t *testing.T) {
	const v9 = "config_version: 9\nobservability: {}\nguardrail:\n"
	const v7 = "config_version: 7\nguardrail:\n"
	for _, test := range []struct {
		name, config, read, want string
	}{
		{"1.0.x observe, default tier", v9 + "  mode: observe\n", "loaded", "open"},
		{"1.0.x action, default tier, cursor closed", v9 + "  mode: action\n  connectors:\n    cursor:\n      hook_fail_mode: closed\n", "loaded", "closed"},
		{"1.0.x action, strict tier", v9 + "  mode: action\n  rule_pack: strict\n", "loaded", "closed"},
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
			if test.read == "loaded" {
				if got := hookOutageFailModeNow("cursor", filepath.Join(home, "hooks")); got != test.want {
					t.Fatalf("the new cursor hook's call-time outage mode is %q, want %q", got, test.want)
				}
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

// A 0.8.x automatic-protection overlay or manual connector can carry an open.
// The refresh closes every per-user hook through the upgrade outage.
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

// An accepted empty-record retry holds --closed over the running older
// gateway even when the config explicitly selects outage-open. The hold
// refreshes again after that gateway exits, so its last render cannot reopen
// hooks before the checked replacement is installed.
func TestRefreshFailModesHoldsUntilTheGatewayExits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sleep(1) as the gateway")
	}
	home := t.TempDir()
	isolateHookEnvForTest(t, home)
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("config_version: 7\nguardrail:\n  mode: observe\n  hook_fail_mode: open\n"), 0o600); err != nil {
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
	previousClosed := refreshFailModesClosed
	t.Cleanup(func() {
		cfg, connectorFlagDataDir, connectorFlagJSON = previousCfg, previousDir, previousJSON
		refreshFailModesHoldPID, refreshFailModesHoldTimeout = previousPID, previousTimeout
		refreshFailModesClosed = previousClosed
		connectorRefreshFailModesCmd.SetOut(nil)
	})
	connectorFlagDataDir, connectorFlagJSON = home, false
	refreshFailModesHoldPID, refreshFailModesHoldTimeout = gateway.Process.Pid, time.Minute
	refreshFailModesClosed = true
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
	if got := oldHookFailMode(t, home, "codex"); got != "closed" {
		t.Fatalf("after the gateway exited the old hook reads %q, want closed", got)
	}
}

// W4b loop round 2: install.ps1 stops with its install unfinished (a restore
// a running hook refused leaves the failed install's programs beside data
// they do not match, with the gateway down). It closes every hook with
// --closed, an open the config chooses included, so no hook follows an
// outage open until the gateway renders them again. A managed install is
// left alone.
func TestRefreshFailModesClosedClosesEveryHookWhateverTheConfigChooses(t *testing.T) {
	previous := refreshFailModesClosed
	t.Cleanup(func() { refreshFailModesClosed = previous })
	for _, test := range []struct{ name, doc, tier string }{
		{"loaded config, default tier", "config_version: 9\nguardrail:\n  mode: action\n  hook_fail_mode: open\n", "open"},
		{"0.8.x document open", "config_version: 7\nguardrail:\n  mode: observe\n  hook_fail_mode: open\n", "closed"},
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
			// Without --closed the refresh writes the policy tier's outage
			// mode (oss-outage-open); an unloadable 0.8.x document is closed.
			if got := oldHookFailMode(t, home, "codex"); got != test.tier {
				t.Fatalf("per-user refresh wrote %q, want the tier's %q", got, test.tier)
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
}

// GAP-1001: the installers run the refresh while they hold the data
// directory. The hooks of 0.8.10 to 1.0.3 never read .install.lock, so an
// open the config sets let a call run while the gateway was down for the
// swap. With the lock held every hook is closed, the config's open included,
// in the sidecar the old native hooks read and in the open an old script
// bakes; the hold refreshes the same way. Without the lock the operator's
// open stays open (control). The lock in DEFENSECLAW_HOME counts too, for
// a refresh whose --data-dir names the gateway's data_dir.
func TestRefreshFailModesClosesEveryHookWhileAnInstallHoldsTheDataDirectory(t *testing.T) {
	const v9 = "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n  hook_fail_mode: open\n"
	const v7 = "config_version: 7\nguardrail:\n  mode: observe\n  hook_fail_mode: open\n"
	released, err := os.ReadFile(filepath.Join("..", "gateway", "connector", "testdata", "released-hooks", "1.0.3", "copilot-hook.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(released, []byte(`FAIL_MODE="open"`)) {
		t.Fatal("precondition: the released 1.0.3 Copilot hook bakes no open")
	}
	for _, test := range []struct {
		name, config, read string
		lock               string // "", "data" or "home"
		hold               bool
		want               string
	}{
		{name: "1.0.x config open, install", config: v9, read: "install", lock: "data", want: "closed"},
		{name: "0.8.x config open, install", config: v7, read: "install", lock: "data", want: "closed"},
		{name: "config open, install in DEFENSECLAW_HOME", config: v9, read: "install", lock: "home", want: "closed"},
		{name: "config open, install, hold", config: v9, read: "install", lock: "data", hold: true, want: "closed"},
		// Outside an install the runtime record holds the per-user outage mode,
		// which follows the policy tier (owner decision 2026-10-23: default
		// tier open); the open a released script baked is closed (TGT-0115).
		{name: "config open, no install", config: v9, read: "loaded", want: "open"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			dataDir := home
			if test.lock == "home" {
				dataDir = t.TempDir()
			}
			isolateHookEnvForTest(t, home)
			if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte(test.config), 0o600); err != nil {
				t.Fatal(err)
			}
			writeHookSidecarForTest(t, dataDir, `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open","copilot":"open"},"fail_mode_sources":{"codex":"config","copilot":"config"}}`)
			script := filepath.Join(dataDir, "hooks", "copilot-hook.sh")
			if err := os.WriteFile(script, released, 0o700); err != nil {
				t.Fatal(err)
			}
			switch test.lock {
			case "data":
				if err := os.Mkdir(filepath.Join(dataDir, ".install.lock"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "home":
				if err := os.Mkdir(filepath.Join(home, ".install.lock"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if test.hold {
				runRefreshFailModesHoldForTest(t, dataDir)
			} else if result := runRefreshFailModesForTest(t, dataDir); result.Config != test.read {
				t.Fatalf("refresh %+v, want config %q", result, test.read)
			}
			for _, name := range []string{"codex", "copilot"} {
				if got := oldHookFailMode(t, dataDir, name); got != test.want {
					t.Fatalf("the old %s hook reads %q, want %q", name, got, test.want)
				}
			}
			body, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			// A per-user script bakes closed in every tier (TGT-0115).
			if bytes.Contains(body, []byte(`FAIL_MODE="open"`)) {
				t.Fatal("the released Copilot hook still bakes open")
			}
		})
	}
}

// runRefreshFailModesHoldForTest runs the refresh with --hold-until-exit for
// a gateway that has already exited, as an installer does for a gateway
// that stops at once.
func runRefreshFailModesHoldForTest(t *testing.T, dataDir string) {
	t.Helper()
	gateway := exec.Command(os.Args[0], "-test.run=^$")
	if err := gateway.Run(); err != nil {
		t.Fatal(err)
	}
	previousCfg, previousDir, previousJSON := cfg, connectorFlagDataDir, connectorFlagJSON
	previousPID, previousTimeout := refreshFailModesHoldPID, refreshFailModesHoldTimeout
	t.Cleanup(func() {
		cfg, connectorFlagDataDir, connectorFlagJSON = previousCfg, previousDir, previousJSON
		refreshFailModesHoldPID, refreshFailModesHoldTimeout = previousPID, previousTimeout
		connectorRefreshFailModesCmd.SetOut(nil)
	})
	connectorFlagDataDir, connectorFlagJSON = dataDir, false
	refreshFailModesHoldPID, refreshFailModesHoldTimeout = gateway.Process.Pid, time.Minute
	var out bytes.Buffer
	connectorRefreshFailModesCmd.SetOut(&out)
	if err := runConnectorRefreshFailModes(connectorRefreshFailModesCmd, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Hook fail modes closed for the install until the gateway starts: ") {
		t.Fatalf("hold output %q names no install close", out.String())
	}
}
