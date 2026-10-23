// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func readHookConfigSidecarForTest(t *testing.T, hookDir string) hookConfigSidecar {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(hookDir, hookConfigSidecarName))
	if err != nil {
		t.Fatal(err)
	}
	var state hookConfigSidecar
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func readFlatHookRecordForTest(t *testing.T, hookDir, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(hookDir, hookConfigSidecarName+"."+name))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// Each connector entry this release writes records that its mode was
// resolved from the config, in the JSON sidecar and in its flat shell record;
// a peer entry an earlier release wrote keeps no source, so the native hook
// and the shared shell readers do not trust its open. A managed sidecar
// carries no sources (its readers reject unknown fields), and a teardown
// removes the connector's source with its mode.
func TestHookConfigSidecarRecordsTheSourceOfEachMode(t *testing.T) {
	hookDir := t.TempDir()
	legacy := `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"claudecode":"open","codex":"open"}}` + "\n"
	if err := os.WriteFile(filepath.Join(hookDir, hookConfigSidecarName), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeHookConfigSidecar(hookDir, "127.0.0.1:18970", "codex", "closed", false); err != nil {
		t.Fatal(err)
	}
	state := readHookConfigSidecarForTest(t, hookDir)
	if !reflect.DeepEqual(state.FailModes, map[string]string{"claudecode": "open", "codex": "closed"}) ||
		!reflect.DeepEqual(state.FailModeSources, map[string]string{"codex": HookFailModeSourceConfig}) {
		t.Fatalf("sidecar after a codex render: %+v", state)
	}
	if got := readFlatHookRecordForTest(t, hookDir, "codex"); got != "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=closed\nFAIL_MODE_SOURCE=config\n" {
		t.Fatalf("codex flat record %q", got)
	}
	if err := writeHookConfigSidecar(hookDir, "127.0.0.1:18970", "claudecode", "open", false); err != nil {
		t.Fatal(err)
	}
	if state := readHookConfigSidecarForTest(t, hookDir); state.FailModeSources["claudecode"] != HookFailModeSourceConfig ||
		state.FailModeSources["codex"] != HookFailModeSourceConfig {
		t.Fatalf("peer source not carried: %+v", state)
	}
	// A mode the config did not choose drops the entry's source.
	if err := writeHookConfigSidecarUsing(hookDir, "127.0.0.1:18970", "claudecode", "open", "", false, atomicWriteFile); err != nil {
		t.Fatal(err)
	}
	if state := readHookConfigSidecarForTest(t, hookDir); state.FailModeSources["claudecode"] != "" ||
		state.FailModeSources["codex"] != HookFailModeSourceConfig {
		t.Fatalf("unsourced write kept a source: %+v", state)
	}
	if got := readFlatHookRecordForTest(t, hookDir, "claudecode"); strings.Contains(got, "SOURCE") {
		t.Fatalf("unsourced flat record %q", got)
	}
	if err := clearHookConfigSidecarEntry(hookDir, "codex"); err != nil {
		t.Fatal(err)
	}
	if state := readHookConfigSidecarForTest(t, hookDir); state.FailModes["codex"] != "" || state.FailModeSources["codex"] != "" {
		t.Fatalf("teardown left the codex entry: %+v", state)
	}

	if runtime.GOOS == "windows" {
		// The Windows managed writer publishes with the guardian's DACLs.
		return
	}
	managedDir := t.TempDir()
	if err := writeHookConfigSidecarUsing(managedDir, "127.0.0.1:18970", "codex", "closed", HookFailModeSourceConfig, true, atomicWriteFile); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(managedDir, hookConfigSidecarName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "fail_mode_source") {
		t.Fatalf("managed sidecar carries sources: %s", body)
	}
	if got := readFlatHookRecordForTest(t, managedDir, "codex"); got != "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=closed\n" {
		t.Fatalf("managed flat record %q", got)
	}
	var strict hookConfigSidecar
	if err := decodeManagedHookConfigSidecar(body, &strict); err != nil {
		t.Fatalf("managed sidecar does not decode strictly: %v", err)
	}
}

// cannotFailClosedForTest is a per-user connector whose vendor hook surface
// cannot fail closed and whose hook does not block its own failures.
type cannotFailClosedForTest struct{ Connector }

func (cannotFailClosedForTest) HookCapabilities(SetupOpts) HookCapability {
	return HookCapability{SupportsFailClosed: false}
}

// A per-user render records the config as the source of a mode only when it
// is the outage mode the config chose (OutageHookFailMode). Copilot and
// Antigravity render an unset mode closed (their hooks print the native
// denial), and a Cursor in observe renders closed unless the config sets open
// (its observe registration stays fail-open): both carry the source. An open
// CapableHookFailMode lowered for a vendor that cannot fail closed is that
// vendor's limit and has no source, so the native hook fails it closed and
// the installers' refresh writes closed.
func TestPerUserRenderRecordsOnlyAnOutageModeTheConfigChose(t *testing.T) {
	for _, test := range []struct {
		name                          string
		conn                          Connector
		opts                          SetupOpts
		wantMode, wantSource, wantOut string
	}{
		{"copilot unset", NewCopilotConnector(), SetupOpts{}, "closed", HookFailModeSourceConfig, "closed"},
		{"copilot explicit open", NewCopilotConnector(), SetupOpts{HookFailMode: "open", ConfiguredHookFailMode: "open"}, "open", HookFailModeSourceConfig, "open"},
		{"antigravity unset", NewAntigravityConnector(), SetupOpts{}, "closed", HookFailModeSourceConfig, "closed"},
		{"cursor observe unset", NewCursorConnector(), SetupOpts{GuardrailMode: "observe", HookFailMode: "open"}, "closed", HookFailModeSourceConfig, "closed"},
		{"cursor observe explicit open", NewCursorConnector(), SetupOpts{GuardrailMode: "observe", HookFailMode: "open", ConfiguredHookFailMode: "open"}, "open", HookFailModeSourceConfig, "open"},
		{"cursor action explicit open", NewCursorConnector(), SetupOpts{GuardrailMode: "action", HookFailMode: "open", ConfiguredHookFailMode: "open"}, "closed", HookFailModeSourceConfig, "closed"},
		{"capability-lowered unset", cannotFailClosedForTest{NewCodexConnector()}, SetupOpts{}, "open", "", "closed"},
		{"capability-lowered explicit open", cannotFailClosedForTest{NewCodexConnector()}, SetupOpts{HookFailMode: "open", ConfiguredHookFailMode: "open"}, "open", HookFailModeSourceConfig, "open"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataDir := t.TempDir()
			hookDir := filepath.Join(dataDir, "hooks")
			opts := test.opts
			opts.DataDir, opts.APIAddr = dataDir, "127.0.0.1:18970"
			if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, test.conn); err != nil {
				t.Fatal(err)
			}
			name := test.conn.Name()
			state := readHookConfigSidecarForTest(t, hookDir)
			if state.FailModes[name] != test.wantMode || state.FailModeSources[name] != test.wantSource {
				t.Fatalf("%s sidecar %+v, want %s with source %q", name, state, test.wantMode, test.wantSource)
			}
			if got := strings.Contains(readFlatHookRecordForTest(t, hookDir, name), "FAIL_MODE_SOURCE=config"); got != (test.wantSource != "") {
				t.Fatalf("%s flat record source = %v, want %v", name, got, test.wantSource != "")
			}
			if got := OutageHookFailMode(opts, test.conn); got != test.wantOut {
				t.Fatalf("outage fail mode %q, want %q", got, test.wantOut)
			}
			if got := HookFailClosed(opts, test.conn); got != (test.wantMode == "closed") {
				t.Fatalf("HookFailClosed = %v, want %v", got, test.wantMode == "closed")
			}
		})
	}
}

// A per-user Cursor's contract (its hook lock) follows the guardrail mode
// while its outage mode is closed without an explicit open: the runtime
// validation accepts a closed runtime under an open contract and still
// refuses an open runtime under a closed one.
func TestCursorRuntimeMayBeClosedUnderAnOpenContract(t *testing.T) {
	cursor := NewCursorConnector()
	for _, test := range []struct {
		name     string
		opts     SetupOpts
		contract string
		ok       bool
	}{
		{"observe, unset", SetupOpts{GuardrailMode: "observe", HookFailMode: "open"}, "open", true},
		{"observe, explicit open", SetupOpts{GuardrailMode: "observe", HookFailMode: "open", ConfiguredHookFailMode: "open"}, "open", true},
		{"open runtime, closed contract", SetupOpts{GuardrailMode: "observe", HookFailMode: "open", ConfiguredHookFailMode: "open"}, "closed", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataDir := t.TempDir()
			opts := test.opts
			opts.DataDir, opts.APIAddr = dataDir, "127.0.0.1:18970"
			if err := WriteHookScriptsForConnectorObjectWithOpts(filepath.Join(dataDir, "hooks"), opts, cursor); err != nil {
				t.Fatal(err)
			}
			if test.contract == "open" && resolveHookFailMode(opts, cursor) != "open" {
				t.Fatal("precondition: the observe contract is not open")
			}
			if err := ValidateHookRuntimeState(dataDir, "cursor", test.contract); (err == nil) != test.ok {
				t.Fatalf("validate against %s: %v, want ok=%v", test.contract, err, test.ok)
			}
		})
	}
}

// The installers' pre-swap refresh: every entry of an earlier release's
// sidecar takes the mode the config chooses, with its source, and both the
// JSON and the flat shell records agree. An entry the resolver cannot name
// is left alone; a managed or missing sidecar is not touched.
func TestRefreshHookFailModesRendersAnEarlierReleasesSidecar(t *testing.T) {
	hookDir := t.TempDir()
	legacy := `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"claudecode":"open","codex":"open","retired":"open"}}` + "\n"
	if err := os.WriteFile(filepath.Join(hookDir, hookConfigSidecarName), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	modes := map[string]string{"claudecode": "closed", "codex": "open"}
	refreshed, err := RefreshHookFailModes(hookDir, func(name string) string { return modes[name] })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(refreshed.Sidecar, []string{"claudecode", "codex"}) || refreshed.Scripts != nil {
		t.Fatalf("refreshed %+v", refreshed)
	}
	state := readHookConfigSidecarForTest(t, hookDir)
	if !reflect.DeepEqual(state.FailModes, map[string]string{"claudecode": "closed", "codex": "open", "retired": "open"}) ||
		!reflect.DeepEqual(state.FailModeSources, map[string]string{"claudecode": HookFailModeSourceConfig, "codex": HookFailModeSourceConfig}) ||
		state.GatewayAddr != "127.0.0.1:18970" {
		t.Fatalf("sidecar after refresh: %+v", state)
	}
	for name, want := range modes {
		flat := readFlatHookRecordForTest(t, hookDir, name)
		if legacyHookConfigValue([]byte(flat), "DEFENSECLAW_FAIL_MODE") != want ||
			legacyHookConfigValue([]byte(flat), "FAIL_MODE_SOURCE") != HookFailModeSourceConfig {
			t.Fatalf("%s flat record %q, want %s from the config", name, flat, want)
		}
	}

	if refreshed, err := RefreshHookFailModes(t.TempDir(), func(string) string { return "closed" }); err != nil ||
		refreshed.Sidecar != nil || refreshed.Scripts != nil {
		t.Fatalf("missing sidecar: %+v %v", refreshed, err)
	}
	managedDir := t.TempDir()
	managedBody := `{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"},"managed_enterprise":true}` + "\n"
	if err := os.WriteFile(filepath.Join(managedDir, hookConfigSidecarName), []byte(managedBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if refreshed, err := RefreshHookFailModes(managedDir, func(string) string { return "closed" }); err != nil ||
		refreshed.Sidecar != nil || refreshed.Scripts != nil {
		t.Fatalf("managed sidecar: %+v %v", refreshed, err)
	}
	if body, _ := os.ReadFile(filepath.Join(managedDir, hookConfigSidecarName)); string(body) != managedBody {
		t.Fatalf("managed sidecar rewritten: %s", body)
	}

	corruptDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(corruptDir, hookConfigSidecarName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshHookFailModes(corruptDir, func(string) string { return "closed" }); err == nil ||
		!strings.Contains(err.Error(), hookConfigSidecarName) {
		t.Fatalf("an unreadable sidecar was not refused: %v", err)
	}
}

// What an earlier release left beside the sidecar is refreshed too: the
// KEY=value sidecar of an install older than 0.8.10, a flat shell record with
// no JSON entry, and the open a connector hook script bakes (0.8.10 to 1.0.2
// let the environment open it; 1.0.3 bakes it, and its missing-home check).
// While the gateway is down for the swap, the old hook scripts allow a call
// before the refresh and block it after; an open the config sets stays.
func TestRefreshHookFailModesClosesAnEarlierReleasesHooks(t *testing.T) {
	hookDir := t.TempDir()
	write := func(name, body string, perm os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(hookDir, name), []byte(body), perm); err != nil {
			t.Fatal(err)
		}
	}
	write(hookConfigSidecarName, "DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:18970\nDEFENSECLAW_FAIL_MODE=open\n", 0o600)
	write(hookConfigSidecarName+".kiro", "DEFENSECLAW_CONNECTOR=kiro\nDEFENSECLAW_FAIL_MODE=open\n", 0o600)
	// The outage path of each release's per-user connector script, as rendered
	// for an open mode.
	const outage = "if [ \"$FAIL_MODE\" = \"closed\" ]; then echo blocked >&2; exit 2; fi\nexit 0\n"
	scripts := map[string]string{
		"codex-hook.sh":       "#!/usr/bin/env bash\nFAIL_MODE=\"${DEFENSECLAW_FAIL_MODE:-open}\"\n" + outage,
		"claude-code-hook.sh": "#!/usr/bin/env bash\nif [ \"open\" = \"closed\" ] || [ \"${DEFENSECLAW_STRICT_AVAILABILITY:-}\" = \"1\" ]; then exit 2; fi\nFAIL_MODE=\"open\"\n" + outage,
		"cursor-hook.sh":      "#!/usr/bin/env bash\n_DC_HOME_FAIL_MODE=\"open\"\nFAIL_MODE=\"${DEFENSECLAW_FAIL_MODE:-closed}\"\n" + outage,
		"copilot-hook.sh":     "#!/usr/bin/env bash\nFAIL_MODE=\"open\"\n" + outage,
	}
	for name, body := range scripts {
		write(name, body, 0o700)
	}
	run := func(name string) int {
		t.Helper()
		cmd := exec.Command("bash", filepath.Join(hookDir, name))
		cmd.Env = append(os.Environ(), "DEFENSECLAW_FAIL_MODE=open")
		if err := cmd.Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				return exit.ExitCode()
			}
			t.Fatal(err)
		}
		return 0
	}
	canRun := runtime.GOOS != "windows"
	if canRun {
		if _, err := exec.LookPath("bash"); err != nil {
			canRun = false
		}
	}
	if canRun {
		for _, name := range []string{"codex-hook.sh", "claude-code-hook.sh", "copilot-hook.sh"} {
			if got := run(name); got != 0 {
				t.Fatalf("%s before the refresh exits %d, want 0 (fail open)", name, got)
			}
		}
	}

	modes := map[string]string{"": "closed", "codex": "closed", "claudecode": "closed", "cursor": "closed", "kiro": "closed", "copilot": "open"}
	refreshed, err := RefreshHookFailModes(hookDir, func(name string) string { return modes[name] })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(refreshed.Sidecar, []string{"kiro", "legacy"}) ||
		!reflect.DeepEqual(refreshed.Scripts, []string{"claude-code-hook.sh", "codex-hook.sh", "cursor-hook.sh"}) {
		t.Fatalf("refreshed %+v", refreshed)
	}
	state := readHookConfigSidecarForTest(t, hookDir)
	if state.Version != 2 || state.GatewayAddr != "127.0.0.1:18970" || state.LegacyMode != "closed" ||
		state.LegacySource != HookFailModeSourceConfig || state.FailModes["kiro"] != "closed" {
		t.Fatalf("sidecar after refresh: %+v", state)
	}
	if got := readFlatHookRecordForTest(t, hookDir, "kiro"); legacyHookConfigValue([]byte(got), "DEFENSECLAW_FAIL_MODE") != "closed" {
		t.Fatalf("kiro flat record %q", got)
	}
	if got := readFlatHookRecordForTest(t, hookDir, "legacy"); legacyHookConfigValue([]byte(got), "DEFENSECLAW_FAIL_MODE") != "closed" {
		t.Fatalf("legacy flat record %q", got)
	}
	for _, name := range []string{"codex-hook.sh", "claude-code-hook.sh", "cursor-hook.sh"} {
		body, err := os.ReadFile(filepath.Join(hookDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), `"open"`) || strings.Contains(string(body), "DEFENSECLAW_FAIL_MODE:-") {
			t.Fatalf("%s still opens:\n%s", name, body)
		}
		if info, err := os.Stat(filepath.Join(hookDir, name)); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o700) {
			t.Fatalf("%s mode %v (%v)", name, info.Mode(), err)
		}
	}
	if body, _ := os.ReadFile(filepath.Join(hookDir, "copilot-hook.sh")); string(body) != scripts["copilot-hook.sh"] {
		t.Fatalf("the operator's open copilot hook was changed:\n%s", body)
	}
	if canRun {
		for _, name := range []string{"codex-hook.sh", "claude-code-hook.sh", "cursor-hook.sh"} {
			if got := run(name); got != 2 {
				t.Fatalf("%s after the refresh exits %d, want 2 (fail closed)", name, got)
			}
		}
		if got := run("copilot-hook.sh"); got != 0 {
			t.Fatalf("the operator's open copilot hook exits %d, want 0", got)
		}
	}
	// A second pass (after the gateway stopped) changes no script again.
	again, err := RefreshHookFailModes(hookDir, func(name string) string { return modes[name] })
	if err != nil || again.Scripts != nil {
		t.Fatalf("second refresh %+v %v", again, err)
	}
}

// The shared inspect scripts of this release follow an open from the hook
// runtime records only when its config source is recorded: an earlier
// release's record (or a peer entry it left) and an open CapableHookFailMode
// lowered fail closed while the gateway is down.
func TestSharedShellReaderFollowsOnlyAnOpenTheConfigChose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, jq := exec.LookPath("jq")
	_, python := exec.LookPath("python3")
	jsonReadable := jq == nil || python == nil
	for _, test := range []struct {
		name, flat, sidecar, want string
		needsJSON                 bool
	}{
		{name: "earlier release's flat open", flat: "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=open\n", want: "closed"},
		{name: "flat open from the config", flat: "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=open\nFAIL_MODE_SOURCE=config\n", want: "open"},
		{name: "flat closed", flat: "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=closed\nFAIL_MODE_SOURCE=config\n", want: "closed"},
		{name: "earlier release's JSON open", sidecar: `{"version":2,"fail_modes":{"codex":"open"}}`, want: "closed"},
		{name: "JSON open from the config", sidecar: `{"version":2,"fail_modes":{"codex":"open"},"fail_mode_sources":{"codex":"config"}}`, want: "open", needsJSON: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.needsJSON && !jsonReadable {
				t.Skip("neither jq nor python3 is installed")
			}
			hookDir := t.TempDir()
			if err := os.WriteFile(filepath.Join(hookDir, "_hardening.sh"), helper, 0o600); err != nil {
				t.Fatal(err)
			}
			if test.flat != "" {
				if err := os.WriteFile(filepath.Join(hookDir, hookConfigSidecarName+".codex"), []byte(test.flat), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if test.sidecar != "" {
				if err := os.WriteFile(filepath.Join(hookDir, hookConfigSidecarName), []byte(test.sidecar), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "-c", `. "$1/_hardening.sh"; defenseclaw_shared_runtime_fail_mode "$1" codex`, "test", hookDir)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("reader: %v", err)
			}
			if got := string(out); got != test.want {
				t.Fatalf("fail mode %q, want %q", got, test.want)
			}
		})
	}
}

// A managed hook's guardian-written runtime records carry no config source
// (the managed readers decode them canonically), and their open is the
// administrator's explicit choice: the shared inspect scripts follow it while
// the gateway is down, with or without jq and python3. The managed exception
// needs both the managed hook and a sidecar the managed writer wrote: a
// per-user hook that inherits DEFENSECLAW_MANAGED_HOOK=1 still closes an
// unsourced open, and a managed hook does not follow a per-user record.
func TestSharedShellReaderFollowsAManagedSidecarsOpen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	const addr = "127.0.0.1:18970"
	writeManaged := func(t *testing.T, hookDir string, modes ...string) {
		t.Helper()
		for i := 0; i+1 < len(modes); i += 2 {
			if err := writeHookConfigSidecar(hookDir, addr, modes[i], modes[i+1], true); err != nil {
				t.Fatal(err)
			}
		}
	}
	writePerUser := func(t *testing.T, hookDir, connector, mode, source string) {
		t.Helper()
		if err := writeHookConfigSidecarUsing(hookDir, addr, connector, mode, source, false, atomicWriteFile); err != nil {
			t.Fatal(err)
		}
	}
	writeRaw := func(name, body string) func(*testing.T, string) {
		return func(t *testing.T, hookDir string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(hookDir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	flatOpen := writeRaw(hookConfigSidecarName+".codex", "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=open\n")
	for _, test := range []struct {
		name      string
		managed   bool
		connector string
		setup     func(*testing.T, string)
		want      string
		// jsonOnly: only hooks/.hookcfg holds the entry, which the reader
		// parses with jq or python3; without both it fails closed.
		jsonOnly bool
	}{
		{name: "managed open", managed: true, connector: "codex", setup: func(t *testing.T, d string) { writeManaged(t, d, "codex", "open") }, want: "open"},
		// One shared script serves every connector and nothing authenticates
		// the selected one, so a closed peer record closes it (train rule:
		// a selector can only tighten), managed or not.
		{name: "managed open beside a closed peer", managed: true, connector: "codex", setup: func(t *testing.T, d string) {
			writeManaged(t, d, "codex", "open", "claudecode", "closed")
		}, want: "closed"},
		{name: "managed open beside a managed open peer", managed: true, connector: "codex", setup: func(t *testing.T, d string) {
			writeManaged(t, d, "codex", "open", "claudecode", "open")
		}, want: "open"},
		{name: "managed closed peer of an open", managed: true, connector: "claudecode", setup: func(t *testing.T, d string) {
			writeManaged(t, d, "codex", "open", "claudecode", "closed")
		}, want: "closed"},
		{name: "managed closed", managed: true, connector: "codex", setup: func(t *testing.T, d string) { writeManaged(t, d, "codex", "closed") }, want: "closed"},
		{name: "managed unscoped open", managed: true, connector: "", setup: func(t *testing.T, d string) { writeManaged(t, d, "", "open") }, want: "open"},
		{name: "managed open in the JSON sidecar only", managed: true, connector: "codex", setup: func(t *testing.T, d string) {
			writeManaged(t, d, "codex", "open")
			if err := os.Remove(filepath.Join(d, hookConfigSidecarName+".codex")); err != nil {
				t.Fatal(err)
			}
		}, want: "open", jsonOnly: true},
		{name: "per-user unsourced open in the JSON sidecar only", managed: false, connector: "codex", setup: func(t *testing.T, d string) {
			writePerUser(t, d, "codex", "open", "")
			if err := os.Remove(filepath.Join(d, hookConfigSidecarName+".codex")); err != nil {
				t.Fatal(err)
			}
		}, want: "closed", jsonOnly: true},
		{name: "managed hook, flat open without the managed sidecar", managed: true, connector: "codex", setup: flatOpen, want: "closed"},
		{name: "managed hook, per-user unsourced open", managed: true, connector: "codex", setup: func(t *testing.T, d string) { writePerUser(t, d, "codex", "open", "") }, want: "closed"},
		{name: "managed hook, earlier release's per-user sidecar", managed: true, connector: "codex", setup: func(t *testing.T, d string) {
			flatOpen(t, d)
			writeRaw(hookConfigSidecarName, "{\"version\":2,\"gateway_addr\":\""+addr+"\",\"fail_modes\":{\"codex\":\"open\"}}\n")(t, d)
		}, want: "closed"},
		{name: "managed hook, managed_enterprise false", managed: true, connector: "codex", setup: func(t *testing.T, d string) {
			flatOpen(t, d)
			writeRaw(hookConfigSidecarName, "{\"version\":2,\"fail_modes\":{\"codex\":\"open\"},\"managed_enterprise\":false}\n")(t, d)
		}, want: "closed"},
		{name: "managed hook, managed_enterprise only inside a string", managed: true, connector: "codex", setup: func(t *testing.T, d string) {
			flatOpen(t, d)
			writeRaw(hookConfigSidecarName, "{\"version\":2,\"gateway_addr\":\"x\\\"managed_enterprise\\\": true\",\"fail_modes\":{\"codex\":\"open\"}}\n")(t, d)
		}, want: "closed"},
		{name: "per-user hook reads a managed sidecar", managed: false, connector: "codex", setup: func(t *testing.T, d string) { writeManaged(t, d, "codex", "open") }, want: "closed"},
		{name: "per-user sourced open", managed: false, connector: "codex", setup: func(t *testing.T, d string) {
			writePerUser(t, d, "codex", "open", HookFailModeSourceConfig)
		}, want: "open"},
	} {
		for _, tools := range readerToolSets(t) {
			t.Run(test.name+"/"+tools.name, func(t *testing.T) {
				want := test.want
				if test.jsonOnly && !tools.json {
					want = "closed"
				}
				hookDir := t.TempDir()
				if err := os.WriteFile(filepath.Join(hookDir, "_hardening.sh"), helper, 0o600); err != nil {
					t.Fatal(err)
				}
				test.setup(t, hookDir)
				cmd := exec.Command(bash, "-c", `. "$1/_hardening.sh"; defenseclaw_shared_runtime_fail_mode "$1" "$2"`, "test", hookDir, test.connector)
				cmd.Env = []string{"PATH=" + tools.path, "HOME=" + t.TempDir()}
				if test.managed {
					cmd.Env = append(cmd.Env, "DEFENSECLAW_MANAGED_HOOK=1")
				}
				out, err := cmd.Output()
				if err != nil {
					t.Fatalf("reader: %v", err)
				}
				if got := string(out); got != want {
					t.Fatalf("fail mode %q, want %q", got, want)
				}
			})
		}
	}
}

// A managed shared inspect script resolves its connector the way the
// rendered scripts do: several guardian records leave it unselected. Its
// records combine to the strictest mode, so an administrator's open on every
// connector stands for the outage and any closed record (a connector or the
// unscoped legacy entry) closes it. A per-user hook with several records
// still needs the legacy open. Before, every managed call with several
// records closed, so the administrator's explicit open was lost (GAP-0362).
func TestManagedSharedHookCombinesSeveralConnectorRecordsToTheStrictest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	const addr = "127.0.0.1:18970"
	for _, test := range []struct {
		name    string
		managed bool
		modes   []string
		// legacyFlat replaces the flat legacy record; jsonOnly drops the
		// flat connector records, so only a parser reads them.
		legacyFlat string
		jsonOnly   bool
		want       string
	}{
		{name: "managed open on every connector", managed: true, modes: []string{"codex", "open", "claudecode", "open"}, want: "open"},
		{name: "managed open on three connectors", managed: true, modes: []string{"codex", "open", "claudecode", "open", "cursor", "open"}, want: "open"},
		{name: "managed open beside a closed peer", managed: true, modes: []string{"codex", "open", "claudecode", "closed"}, want: "closed"},
		{name: "managed closed on every connector", managed: true, modes: []string{"codex", "closed", "claudecode", "closed"}, want: "closed"},
		{name: "managed open with a closed legacy entry", managed: true, modes: []string{"codex", "open", "claudecode", "open", "", "closed"}, want: "closed"},
		{name: "managed open with an open legacy entry", managed: true, modes: []string{"codex", "open", "claudecode", "open", "", "open"}, want: "open"},
		{name: "managed open with a legacy record naming a connector", managed: true, modes: []string{"codex", "open", "claudecode", "open"}, legacyFlat: "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=open\n", want: "closed"},
		{name: "managed open with an unreadable legacy record", managed: true, modes: []string{"codex", "open", "claudecode", "open"}, legacyFlat: "garbage\n", want: "closed"},
		{name: "managed open in the JSON sidecar only", managed: true, modes: []string{"codex", "open", "claudecode", "open"}, jsonOnly: true, want: "open"},
		{name: "managed closed peer in the JSON sidecar only", managed: true, modes: []string{"codex", "open", "claudecode", "closed"}, jsonOnly: true, want: "closed"},
		{name: "per-user hook with the same records", managed: false, modes: []string{"codex", "open", "claudecode", "open"}, want: "closed"},
	} {
		for _, tools := range readerToolSets(t) {
			t.Run(test.name+"/"+tools.name, func(t *testing.T) {
				want := test.want
				if test.jsonOnly && !tools.json {
					want = "closed"
				}
				hookDir := t.TempDir()
				if err := os.WriteFile(filepath.Join(hookDir, "_hardening.sh"), helper, 0o600); err != nil {
					t.Fatal(err)
				}
				for i := 0; i+1 < len(test.modes); i += 2 {
					if test.managed {
						err = writeHookConfigSidecar(hookDir, addr, test.modes[i], test.modes[i+1], true)
					} else {
						err = writeHookConfigSidecarUsing(hookDir, addr, test.modes[i], test.modes[i+1], HookFailModeSourceConfig, false, atomicWriteFile)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				if test.legacyFlat != "" {
					if err := os.WriteFile(filepath.Join(hookDir, hookConfigSidecarName+".legacy"), []byte(test.legacyFlat), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if test.jsonOnly {
					for i := 0; i+1 < len(test.modes); i += 2 {
						if err := os.Remove(filepath.Join(hookDir, hookConfigSidecarName+"."+test.modes[i])); err != nil {
							t.Fatal(err)
						}
					}
				}
				run := func(env ...string) (connector, mode string) {
					t.Helper()
					cmd := exec.Command(bash, "-c", `. "$1/_hardening.sh"; c="$(defenseclaw_shared_runtime_connector "$1")"; printf '%s|' "$c"; defenseclaw_shared_runtime_fail_mode "$1" "$c"`, "test", hookDir)
					cmd.Env = append([]string{"PATH=" + tools.path, "HOME=" + t.TempDir()}, env...)
					out, err := cmd.Output()
					if err != nil {
						t.Fatalf("reader: %v", err)
					}
					connector, mode, _ = strings.Cut(string(out), "|")
					return connector, mode
				}
				var got string
				if test.managed {
					// The environment's connector is not trusted by a managed hook.
					var connector string
					connector, got = run("DEFENSECLAW_MANAGED_HOOK=1", "DEFENSECLAW_CONNECTOR=codex")
					if connector != "" {
						t.Fatalf("managed hook selected connector %q from several records or the environment", connector)
					}
				} else {
					// A per-user selection only tightens, so check it unselected.
					_, got = run()
				}
				if got != want {
					t.Fatalf("fail mode %q, want %q", got, want)
				}
			})
		}
	}
}

// The combined managed open covers a gateway outage only, in every shared
// inspect script. A managed host whose records are all open allows a call
// when the gateway is unreachable or answers 5xx, but a refusal (400, 429)
// or a 200 without a usable action blocks: the agent can force a 400 with
// an input whose escaped body passes the gateway's limit and a 429 by
// flooding its own hook budget. Before, the combined open allowed all four.
func TestManagedSharedHookOpenCoversOutagesOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	for _, reply := range []struct {
		name   string
		status int
		body   string
		want   int
	}{
		{"allow", http.StatusOK, `{"action":"allow"}`, 0},
		{"HTTP 400", http.StatusBadRequest, `{"error":"request body too large"}`, 2},
		{"HTTP 429", http.StatusTooManyRequests, `{"error":"rate limited"}`, 2},
		{"HTTP 404", http.StatusNotFound, ``, 2},
		{"missing action", http.StatusOK, `{}`, 2},
		{"invalid action", http.StatusOK, `{"action":"unrecognized"}`, 2},
		{"unparseable reply", http.StatusOK, `garbage`, 2},
		{"HTTP 503", http.StatusServiceUnavailable, ``, 0},
		{"gateway unreachable", 0, ``, 0},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(reply.status)
			_, _ = io.WriteString(w, reply.body)
		}))
		addr := strings.TrimPrefix(server.URL, "http://")
		if reply.status == 0 {
			server.Close()
		}
		dir := t.TempDir()
		if err := writeHookScriptsCommonWithOptions(dir, addr, "test-token", "open", nil, true, "codex", false); err != nil {
			t.Fatal(err)
		}
		if err := writeHookConfigSidecar(dir, addr, "claudecode", "open", true); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"inspect-request.sh", "inspect-tool.sh", "inspect-response.sh", "inspect-tool-response.sh"} {
			t.Run(reply.name+"/"+name, func(t *testing.T) {
				cmd := exec.Command("bash", filepath.Join(dir, name))
				cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "DEFENSECLAW_HOME="+t.TempDir(), "DEFENSECLAW_MANAGED_HOOK=1", "DEFENSECLAW_CONNECTOR=codex")
				cmd.Stdin = strings.NewReader(`{"tool":"Bash","input":"echo marker","content":"marker"}`)
				output, err := cmd.CombinedOutput()
				got := 0
				if err != nil {
					exit, ok := err.(*exec.ExitError)
					if !ok {
						t.Fatalf("run hook: %v, output=%q", err, output)
					}
					got = exit.ExitCode()
				}
				if got != reply.want {
					t.Fatalf("hook exit=%d, want=%d, output=%q", got, reply.want, output)
				}
			})
		}
		server.Close()
	}

	// Nor does a body the hook cannot encode open it: on a host without jq,
	// the agent's PYTHONIOENCODING=utf-8 makes python3 reject a tool input
	// or output that is not UTF-8.
	if _, err := exec.LookPath("python3"); err != nil {
		return
	}
	noJQ := t.TempDir()
	for _, bin := range filepath.SplitList(os.Getenv("PATH")) {
		entries, err := os.ReadDir(bin)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			target := filepath.Join(noJQ, entry.Name())
			if entry.IsDir() || entry.Name() == "jq" {
				continue
			}
			if _, err := os.Lstat(target); os.IsNotExist(err) {
				_ = os.Symlink(filepath.Join(bin, entry.Name()), target)
			}
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"action":"allow"}`)
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "http://")
	dir := t.TempDir()
	if err := writeHookScriptsCommonWithOptions(dir, addr, "test-token", "open", nil, true, "codex", false); err != nil {
		t.Fatal(err)
	}
	if err := writeHookConfigSidecar(dir, addr, "claudecode", "open", true); err != nil {
		t.Fatal(err)
	}
	bakeHookPathForTest(t, filepath.Join(dir, "inspect-tool.sh"), noJQ)
	for _, name := range []string{"inspect-tool.sh", "inspect-tool-response.sh"} {
		t.Run("unencodable body/"+name, func(t *testing.T) {
			cmd := exec.Command("bash", filepath.Join(dir, name))
			cmd.Env = append(os.Environ(), "PATH="+noJQ, "HOME="+t.TempDir(), "DEFENSECLAW_HOME="+t.TempDir(), "PYTHONIOENCODING=utf-8")
			cmd.Stdin = strings.NewReader("\xff")
			output, err := cmd.CombinedOutput()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
				t.Fatalf("unencodable body did not fail closed: err=%v output=%q", err, output)
			}
			if !strings.Contains(string(output), "failed to build inspect body") {
				t.Fatalf("hook did not fail on the body: %q", output)
			}
		})
	}
}

// readerToolSets are the PATHs the shared shell reader runs under: the host
// PATH, one with only python3 (no jq), when the host has python3, and one
// with neither. json says whether the reader can parse hooks/.hookcfg.
func readerToolSets(t *testing.T) []struct {
	name, path string
	json       bool
} {
	t.Helper()
	_, jq := exec.LookPath("jq")
	python, pythonErr := exec.LookPath("python3")
	sets := []struct {
		name, path string
		json       bool
	}{
		{name: "host PATH", path: os.Getenv("PATH"), json: jq == nil || pythonErr == nil},
		{name: "no jq or python3", path: filepath.Join(t.TempDir(), "empty-bin")},
	}
	if pythonErr == nil {
		bin := t.TempDir()
		if err := os.Symlink(python, filepath.Join(bin, "python3")); err != nil {
			t.Fatal(err)
		}
		sets = append(sets, struct {
			name, path string
			json       bool
		}{name: "python3 only", path: bin, json: true})
	}
	return sets
}
