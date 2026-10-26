// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A Windows user whose connectors are all machine policy (Cursor, Codex,
// Claude) has no per-user manifest row, but can still add a user-level
// foreign hook; the guardian must clean it for every eligible profile, not
// only for users with rows.
func TestWindowsForeignCleanupCoversEligibleUsersWithoutRows(t *testing.T) {
	previousOptions, previousProfiles := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles
	previousCleanup, previousBlocks := enterpriseForeignHookCleanup, enterpriseForeignHookCollectBlocks
	t.Cleanup(func() {
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles = previousOptions, previousProfiles
		enterpriseForeignHookCleanup, enterpriseForeignHookCollectBlocks = previousCleanup, previousBlocks
		enterpriseHookWindowsForeignCleanupState.last, enterpriseHookWindowsForeignCleanupState.fingerprint = time.Time{}, ""
	})
	enterpriseHookWindowsForeignCleanupState.last, enterpriseHookWindowsForeignCleanupState.fingerprint = time.Time{}, ""
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{}, []string{"cursor"}, true, nil
	}
	const alice, bob = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		return []enterprisehooks.TargetCredentials{
			{UserHome: `C:\Users\alice`, UID: -1, GID: -1, SID: alice},
			{UserHome: `C:\Users\bob`, UID: -1, GID: -1, SID: bob},
		}, nil
	}
	var calls []string
	enterpriseForeignHookCleanup = func(target enterprisehooks.TargetCredentials, name, dataDir string) (enterprisepolicy.CleanupResult, error) {
		calls = append(calls, target.SID+"|"+name+"|"+dataDir)
		return enterprisepolicy.CleanupResult{}, nil
	}
	var collected []string
	enterpriseForeignHookCollectBlocks = func(target enterprisehooks.TargetCredentials) ([]enterprisepolicy.BlockSummary, int, error) {
		collected = append(collected, target.SID)
		return nil, 0, nil
	}
	// GAP-0587: DefenseClaw's own older per-user Claude hooks are migrated
	// for every user, so Copilot does not block on them as foreign hooks.
	// Only a file the read-only probe finds one in is rewritten, and what
	// still names DefenseClaw afterwards is reported.
	previousRemover, previousProbe := windowsManagedClaudeSettingsRemover, windowsManagedClaudeRegistrationProbe
	t.Cleanup(func() {
		windowsManagedClaudeSettingsRemover, windowsManagedClaudeRegistrationProbe = previousRemover, previousProbe
	})
	var probed, migrated []string
	windowsManagedClaudeRegistrationProbe = func(home, sid string) (bool, []string, error) {
		probed = append(probed, sid+"|"+home)
		return sid == alice, nil, nil
	}
	windowsManagedClaudeSettingsRemover = func(home, sid, _ string) (int, []string, error) {
		migrated = append(migrated, sid+"|"+home)
		return 2, []string{"Stop: a hook command naming defenseclaw-hook (arguments not shown)"}, nil
	}
	rows := []enterpriseHookReconcileRow{{OK: true, SID: bob, UserHome: `C:\Users\bob`, Connector: "cursor"}}
	var log bytes.Buffer
	enterpriseHookStandalonePlatformFinish(context.Background(), &log, rows, time.Now())
	if strings.Join(calls, ",") != alice+`|cursor|C:\Users\alice\.defenseclaw` {
		t.Fatalf("cleanup must run for the eligible user without rows and skip the row's own connector: %v\n%s", calls, log.String())
	}
	if strings.Join(collected, ",") != bob+","+alice {
		t.Fatalf("block records must be collected for every user: %v", collected)
	}
	if strings.Join(probed, ",") != bob+`|C:\Users\bob,`+alice+`|C:\Users\alice` {
		t.Fatalf("older DefenseClaw Claude hooks must be looked for for every user: %v", probed)
	}
	if strings.Join(migrated, ",") != alice+`|C:\Users\alice` {
		t.Fatalf("only settings holding older DefenseClaw Claude hooks may be rewritten: %v", migrated)
	}
	for _, want := range []string{
		`removed 2 older DefenseClaw hook command(s) from C:\Users\alice\.claude\settings.json`,
		`C:\Users\alice\.claude\settings.json still holds Stop: a hook command naming defenseclaw-hook (arguments not shown)`,
	} {
		if !strings.Contains(log.String(), want) {
			t.Fatalf("migration log lacks %q:\n%s", want, log.String())
		}
	}
}

// GAP-0587: a user enrolled for Claude Code has a Claude Code manifest row,
// but that row is the machine policy registration and never reads the user's
// settings. The migration skipped every such user, so the older per-user
// DefenseClaw hooks stayed in ~/.claude/settings.json after a full-five
// install or upgrade and Copilot blocked every tool call in a home project.
// It must run for every user, whatever rows the user has.
func TestWindowsClaudeMigrationRunsForUsersWithClaudeCodeRows(t *testing.T) {
	previousOptions, previousProfiles := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles
	previousCleanup, previousBlocks := enterpriseForeignHookCleanup, enterpriseForeignHookCollectBlocks
	previousRemover, previousProbe := windowsManagedClaudeSettingsRemover, windowsManagedClaudeRegistrationProbe
	t.Cleanup(func() {
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles = previousOptions, previousProfiles
		enterpriseForeignHookCleanup, enterpriseForeignHookCollectBlocks = previousCleanup, previousBlocks
		windowsManagedClaudeSettingsRemover, windowsManagedClaudeRegistrationProbe = previousRemover, previousProbe
		enterpriseHookWindowsForeignCleanupState.last, enterpriseHookWindowsForeignCleanupState.fingerprint = time.Time{}, ""
	})
	enterpriseHookWindowsForeignCleanupState.last, enterpriseHookWindowsForeignCleanupState.fingerprint = time.Time{}, ""
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{}, []string{"copilot", "cursor"}, true, nil
	}
	const std1, std2 = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		return []enterprisehooks.TargetCredentials{{UserHome: `C:\Users\dcw-std2`, UID: -1, GID: -1, SID: std2}}, nil
	}
	enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
		return enterprisepolicy.CleanupResult{}, nil
	}
	enterpriseForeignHookCollectBlocks = func(enterprisehooks.TargetCredentials) ([]enterprisepolicy.BlockSummary, int, error) {
		return nil, 0, nil
	}
	var probed, migrated []string
	windowsManagedClaudeRegistrationProbe = func(home, sid string) (bool, []string, error) {
		probed = append(probed, sid)
		return true, nil, nil
	}
	windowsManagedClaudeSettingsRemover = func(home, sid, _ string) (int, []string, error) {
		migrated = append(migrated, sid)
		return 29, nil, nil
	}
	// std1 has the full-five rows, Claude Code and Copilot among them; std2
	// is an eligible profile without rows.
	var rows []enterpriseHookReconcileRow
	for _, name := range []string{"claudecode", "codex", "copilot", "hermes", "opencode"} {
		rows = append(rows, enterpriseHookReconcileRow{OK: true, SID: std1, UserHome: `C:\Users\dcw-std1`, Connector: name})
	}
	var log bytes.Buffer
	enterpriseHookStandalonePlatformFinish(context.Background(), &log, rows, time.Now())
	if strings.Join(probed, ",") != std1+","+std2 || strings.Join(migrated, ",") != std1+","+std2 {
		t.Fatalf("older DefenseClaw Claude hooks must be migrated for every user, a Claude Code row or not: probed %v, migrated %v\n%s",
			probed, migrated, log.String())
	}
	if want := `removed 29 older DefenseClaw hook command(s) from C:\Users\dcw-std1\.claude\settings.json`; !strings.Contains(log.String(), want) {
		t.Fatalf("migration log lacks %q:\n%s", want, log.String())
	}
}

// A settings file holding only DefenseClaw hooks the remover keeps (here
// an edited launcher guard and a defenseclaw-gateway command) is never
// rewritten, but each is still reported: the real probe finds them, so
// Copilot's block on them comes with guidance.
func TestWindowsClaudeMigrationReportsLeftoversWhenNothingIsRemovable(t *testing.T) {
	t.Setenv("SystemRoot", `C:\Windows`)
	const home, sid = `C:\Users\alice`, "S-1-5-21-1-2-3-1001"
	edited := windowsClaudeGuardFixture(filepath.Join(home, ".local", "bin", "defenseclaw-hook.exe"), "claudecode", "0")
	gateway := map[string]any{"type": "command", "command": `C:\tools\defenseclaw-gateway.exe`, "args": []any{"hook"}}
	raw, err := json.Marshal(map[string]any{"hooks": map[string]any{
		"PreToolUse": []any{map[string]any{"hooks": []any{edited}}},
		"Stop":       []any{map[string]any{"hooks": []any{gateway}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	previousReader, previousRemover := windowsManagedClaudeUserSettingsReader, windowsManagedClaudeSettingsRemover
	t.Cleanup(func() {
		windowsManagedClaudeUserSettingsReader, windowsManagedClaudeSettingsRemover = previousReader, previousRemover
	})
	windowsManagedClaudeUserSettingsReader = func(gotHome, gotSID string) ([]byte, error) {
		if gotHome != home || gotSID != sid {
			t.Fatalf("read %s %s", gotHome, gotSID)
		}
		return raw, nil
	}
	windowsManagedClaudeSettingsRemover = func(string, string, string) (int, []string, error) {
		t.Fatal("settings without a removable hook were rewritten")
		return 0, nil, nil
	}
	var log bytes.Buffer
	migrateWindowsClaudeUserHooks(&log, &log, enterprisehooks.TargetCredentials{UserHome: home, UID: -1, GID: -1, SID: sid})
	settings := filepath.Join(home, ".claude", "settings.json")
	for _, want := range []string{
		settings + " still holds PreToolUse: a hook command naming defenseclaw-hook (arguments not shown)",
		settings + " still holds Stop: a hook command naming defenseclaw-gateway (arguments not shown)",
	} {
		if !strings.Contains(log.String(), want) {
			t.Fatalf("migration log lacks %q:\n%s", want, log.String())
		}
	}
	if strings.Contains(log.String(), "removed") {
		t.Fatalf("nothing was removed:\n%s", log.String())
	}
	// A file without a DefenseClaw hook stays silent.
	raw = []byte(`{"hooks":{"Stop":[{"hooks":[{"command":"notify.exe"}]}]}}`)
	log.Reset()
	migrateWindowsClaudeUserHooks(&log, &log, enterprisehooks.TargetCredentials{UserHome: home, UID: -1, GID: -1, SID: sid})
	if log.Len() != 0 {
		t.Fatalf("clean settings were reported:\n%s", log.String())
	}
}

// The guardian routes OpenCode rows by OpenCode's machine policy: the
// managed config under the trusted ProgramData, in force only while the
// trusted managed plugin is installed and named there.
func TestWindowsOpenCodeMachinePolicyCheckNamesTheManagedConfig(t *testing.T) {
	layout, _, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		t.Skipf("no standalone layout: %v", err)
	}
	path, inForce := windowsOpenCodeMachinePolicy()
	if dir := filepath.Join(programData, "opencode"); !strings.EqualFold(filepath.Dir(path), dir) {
		t.Fatalf("OpenCode policy path = %q, want one in %s", path, dir)
	}
	if _, err := os.Lstat(enterprisepolicy.OpenCodeManagedPluginPath(layout)); errors.Is(err, os.ErrNotExist) && inForce {
		t.Fatal("OpenCode machine policy reported in force without the managed plugin")
	}
}

// Every guardian reconcile re-checks the Claude Code version floor, even
// when the Go-owned policy fails, and only in the standalone profile.
func TestWindowsGuardianRechecksTheClaudeVersionFloor(t *testing.T) {
	previousOptions, previousFloor, previousWSL := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsClaudeVersionFloor, enterpriseHookWindowsWSL
	previousCursor, previousProfiles := enterpriseHookWindowsCursorAdapterRefresh, enterpriseHookWindowsEligibleProfiles
	t.Cleanup(func() {
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsClaudeVersionFloor, enterpriseHookWindowsWSL = previousOptions, previousFloor, previousWSL
		enterpriseHookWindowsCursorAdapterRefresh, enterpriseHookWindowsEligibleProfiles = previousCursor, previousProfiles
	})
	// The pass migrates the profiles this test names, never the host's own.
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) { return nil, nil }
	// GAP-2467: every standalone pass also refreshes a stale Cursor adapter.
	var cursorHooks []string
	enterpriseHookWindowsCursorAdapterRefresh = func(hook string) (bool, error) {
		cursorHooks = append(cursorHooks, hook)
		return true, nil
	}
	wslCalls := 0
	enterpriseHookWindowsWSL = func(enterprisepolicy.Options) (enterprisepolicy.State, error) {
		wslCalls++
		return enterprisepolicy.State{}, errors.New("registry denied")
	}
	standalone := false
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{HookBinary: `C:\hook.exe`}, []string{"claudecode"}, standalone, nil
	}
	var calls [][]string
	enterpriseHookWindowsClaudeVersionFloor = func(_ enterprisepolicy.Options, connectors []string) (enterprisepolicy.State, error) {
		calls = append(calls, connectors)
		return enterprisepolicy.State{}, errors.New("lock timeout")
	}
	var log bytes.Buffer
	enterpriseHookStandalonePlatformPrepare(&log)
	if len(calls) != 0 || wslCalls != 0 || len(cursorHooks) != 0 || log.Len() != 0 {
		t.Fatalf("a Secure Client guardian must not touch the floor, the WSL policy or the Cursor adapter: %v %d %v %q", calls, wslCalls, cursorHooks, log.String())
	}
	standalone = true
	enterpriseHookStandalonePlatformPrepare(&log)
	if len(calls) != 1 || strings.Join(calls[0], ",") != "claudecode" {
		t.Fatalf("the floor must be re-checked every reconcile: %v", calls)
	}
	if !strings.Contains(log.String(), "Claude Code version floor: lock timeout") {
		t.Fatalf("a floor failure must be reported: %q", log.String())
	}
	if wslCalls != 1 || !strings.Contains(log.String(), "WSL agent sessions: registry denied") {
		t.Fatalf("the WSL policy must be reconciled every pass and its failure reported: %d %q", wslCalls, log.String())
	}
	if strings.Join(cursorHooks, ",") != `C:\hook.exe` || !strings.Contains(log.String(), "rewrote the Cursor enterprise adapter") {
		t.Fatalf("the Cursor adapter must be refreshed for the guardian's hook binary every pass: %v %q", cursorHooks, log.String())
	}
}

// The uninstall's teardown loads no config, so a standalone removal of
// DefenseClaw's VS Code Local hook file must not depend on it.
func TestWindowsCopilotVSCodeUserRemovalWithoutLoadedConfig(t *testing.T) {
	previous := cfg
	t.Cleanup(func() { cfg = previous })
	cfg = nil
	layout, _, _, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		t.Fatal(err)
	}
	hooks, err := enterprisepolicy.RenderCopilotVSCodeLocalHooks("windows", enterprisepolicy.HookBinaryPath(layout))
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	hookFile := enterprisepolicy.CopilotVSCodeLocalHookFilePath(home)
	if err := os.MkdirAll(filepath.Dir(hookFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookFile, hooks, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(managed.EnterpriseProfileEnv, "")
	if err := windowsCopilotVSCodeUser(home, false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(hookFile); err != nil {
		t.Fatalf("a Secure Client removal touched the hook file: %v", err)
	}

	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	if err := windowsCopilotVSCodeUser(home, false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(hookFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("standalone removal kept DefenseClaw's hook file: %v", err)
	}
}

// The Copilot VS Code Local hook file is the guardian's on managed Windows
// (WIN-R1-25, #1055): the row's verify fails while a user's copy is missing
// or edited (so the guardian reinstalls it), and uninstall removes whatever
// is at its name.
func TestWindowsCopilotVSCodeUserOwnsTheLocalHookFile(t *testing.T) {
	previous := enterpriseHookWindowsGuardianOptions
	t.Cleanup(func() { enterpriseHookWindowsGuardianOptions = previous })
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{HookBinary: `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`}, []string{"copilot"}, true, nil
	}
	home := t.TempDir()
	hookFile := enterprisepolicy.CopilotVSCodeLocalHookFilePath(home)
	if err := windowsCopilotVSCodeUser(home, true, false); err == nil {
		t.Fatal("verify must fail before the hook file is written")
	}
	if err := windowsCopilotVSCodeUser(home, false, false); err != nil {
		t.Fatal(err)
	}
	if err := windowsCopilotVSCodeUser(home, true, false); err != nil {
		t.Fatalf("verify after install: %v", err)
	}
	if err := os.WriteFile(hookFile, []byte(`{"hooks":{"PreToolUse":[{"type":"command","command":"user-tool"}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := windowsCopilotVSCodeUser(home, true, false); err == nil || !strings.Contains(err.Error(), hookFile) {
		t.Fatalf("verify must name the edited hook file: %v", err)
	}
	if err := windowsCopilotVSCodeUser(home, false, false); err == nil {
		t.Fatal("apply must refuse the independent handler")
	}
	if err := os.Remove(hookFile); err != nil {
		t.Fatal(err)
	}
	if err := windowsCopilotVSCodeUser(home, false, false); err != nil {
		t.Fatal(err)
	}
	if err := windowsCopilotVSCodeUser(home, true, false); err != nil {
		t.Fatalf("verify after repair: %v", err)
	}
	if err := os.Remove(hookFile); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(hookFile, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := windowsCopilotVSCodeUser(home, false, true); err != nil {
		t.Fatalf("uninstall must remove whatever is at the hook file: %v", err)
	}
	if _, err := os.Lstat(hookFile); !os.IsNotExist(err) {
		t.Fatalf("hook file left behind: %v", err)
	}
}

func TestWindowsCopilotApplyRefusesIndependentLocalHandler(t *testing.T) {
	previous := enterpriseHookWindowsGuardianOptions
	t.Cleanup(func() { enterpriseHookWindowsGuardianOptions = previous })
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{HookBinary: `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`}, []string{"copilot"}, true, nil
	}
	home := t.TempDir()
	path := enterprisepolicy.CopilotVSCodeLocalHookFilePath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := []byte(`{"hooks":{"PreToolUse":[{"type":"command","command":"operator-hook"}]}}`)
	if err := os.WriteFile(path, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := windowsCopilotVSCodeUser(home, false, false); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("apply claimed a guarded Local hook despite the independent handler: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(foreign) {
		t.Fatalf("apply changed the operator's hook: %q, %v", got, err)
	}
}

// The machine-policy pass holds no removal lock of its own while it cleans
// a user's hooks: a slow scan that removes nothing never keeps the
// account's gateway exchanges waiting.
func TestWindowsForeignCleanupHoldsNoLockWhileItCleans(t *testing.T) {
	useForeignHookGuardian(t, nil)
	previousOptions, previousProfiles := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles
	previousCleanup, previousBlocks := enterpriseForeignHookCleanup, enterpriseForeignHookCollectBlocks
	t.Cleanup(func() {
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles = previousOptions, previousProfiles
		enterpriseForeignHookCleanup, enterpriseForeignHookCollectBlocks = previousCleanup, previousBlocks
		enterpriseHookWindowsForeignCleanupState.last, enterpriseHookWindowsForeignCleanupState.fingerprint = time.Time{}, ""
	})
	enterpriseHookWindowsForeignCleanupState.last, enterpriseHookWindowsForeignCleanupState.fingerprint = time.Time{}, ""
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{}, []string{"cursor"}, true, nil
	}
	const alice = "S-1-5-21-1-2-3-1001"
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		return []enterprisehooks.TargetCredentials{{UserHome: `C:\Users\alice`, UID: -1, GID: -1, SID: alice}}, nil
	}
	enterpriseForeignHookCollectBlocks = func(enterprisehooks.TargetCredentials) ([]enterprisepolicy.BlockSummary, int, error) {
		return nil, 0, nil
	}
	calls := 0
	enterpriseForeignHookCleanup = func(enterprisehooks.TargetCredentials, string, string) (enterprisepolicy.CleanupResult, error) {
		calls++
		if !accountRemovalLockFree(t, alice, 200*time.Millisecond) {
			t.Error("the machine-policy pass holds the account's removal lock while it scans")
		}
		return enterprisepolicy.CleanupResult{}, nil
	}
	var log bytes.Buffer
	enterpriseHookStandalonePlatformFinish(context.Background(), &log, nil, time.Now())
	if calls != 1 {
		t.Fatalf("cleanup calls = %d\n%s", calls, log.String())
	}
}

// GAP-1540 (LEAD DECISION 03:34): the guardian migrates DefenseClaw's own
// older per-user Claude Code hooks out of every eligible account before it
// publishes the machine policy the hook-side guard enforces, so an account
// this pass enrolls never meets them as foreign hooks. The pass before
// enforcement reports only what it removed; the finish step reports the rest.
func TestWindowsClaudeMigrationRunsBeforeTheMachinePolicyIsPublished(t *testing.T) {
	previousOptions, previousFloor, previousWSL := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsClaudeVersionFloor, enterpriseHookWindowsWSL
	previousCursor, previousProfiles := enterpriseHookWindowsCursorAdapterRefresh, enterpriseHookWindowsEligibleProfiles
	previousRemover, previousProbe := windowsManagedClaudeSettingsRemover, windowsManagedClaudeRegistrationProbe
	t.Cleanup(func() {
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsClaudeVersionFloor, enterpriseHookWindowsWSL = previousOptions, previousFloor, previousWSL
		enterpriseHookWindowsCursorAdapterRefresh, enterpriseHookWindowsEligibleProfiles = previousCursor, previousProfiles
		windowsManagedClaudeSettingsRemover, windowsManagedClaudeRegistrationProbe = previousRemover, previousProbe
	})
	var order []string
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{HookBinary: `C:\hook.exe`}, []string{"copilot"}, true, nil
	}
	enterpriseHookWindowsClaudeVersionFloor = func(enterprisepolicy.Options, []string) (enterprisepolicy.State, error) {
		order = append(order, "policy")
		return enterprisepolicy.State{}, nil
	}
	enterpriseHookWindowsWSL = func(enterprisepolicy.Options) (enterprisepolicy.State, error) { return enterprisepolicy.State{}, nil }
	enterpriseHookWindowsCursorAdapterRefresh = func(string) (bool, error) { return false, nil }
	const std1, std2 = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		return []enterprisehooks.TargetCredentials{
			{UserHome: `C:\Users\dcw-std1`, UID: -1, GID: -1, SID: std1},
			{UserHome: `C:\Users\dcw-std2`, UID: -1, GID: -1, SID: std2},
		}, nil
	}
	windowsManagedClaudeRegistrationProbe = func(home, sid string) (bool, []string, error) {
		if sid == std2 {
			return false, nil, errors.New("the Claude settings must be a JSON object")
		}
		return true, nil, nil
	}
	windowsManagedClaudeSettingsRemover = func(home, sid, _ string) (int, []string, error) {
		order = append(order, "migrate "+sid)
		return 29, nil, nil
	}
	var log bytes.Buffer
	enterpriseHookStandalonePlatformPrepare(&log)
	if strings.Join(order, ",") != "migrate "+std1+",policy" {
		t.Fatalf("the older DefenseClaw Claude hooks must be migrated before the machine policy is published: %v\n%s", order, log.String())
	}
	if want := `removed 29 older DefenseClaw hook command(s) from C:\Users\dcw-std1\.claude\settings.json`; !strings.Contains(log.String(), want) {
		t.Fatalf("the pass before enforcement must report what it removed (%q):\n%s", want, log.String())
	}
	if strings.Contains(log.String(), "dcw-std2") {
		t.Fatalf("the pass before enforcement repeats a failure the finish step and verify report:\n%s", log.String())
	}
}

// GAP-1540 (LEAD DECISION 03:34): a migration that cannot finish (a settings
// file DefenseClaw cannot read, such as one saved with a byte order mark) or
// has not run yet makes the Copilot row's enterprise verify fail with the file
// and the reason, instead of the guard silently blocking every call. Setup's
// readiness reports it as a warning, so one account's file never rolls back
// Install or Upgrade; the guardian's own pass does not fail the row on it.
func TestWindowsCopilotVerifyNamesClaudeSettingsTheMigrationCannotFinish(t *testing.T) {
	previousOptions, previousProfiles, previousProbe := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles, windowsManagedClaudeRegistrationProbe
	t.Cleanup(func() {
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles, windowsManagedClaudeRegistrationProbe = previousOptions, previousProfiles, previousProbe
		enterpriseHookGuardianWatching.Store(false)
	})
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{HookBinary: `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`}, []string{"copilot"}, true, nil
	}
	home := t.TempDir()
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		return []enterprisehooks.TargetCredentials{{UserHome: strings.ToUpper(home), UID: -1, GID: -1, SID: "S-1-5-21-1-2-3-1001"}}, nil
	}
	settings := filepath.Join(strings.ToUpper(home), ".claude", "settings.json")
	for _, tc := range []struct {
		name    string
		present bool
		err     error
		want    string
	}{
		{"unreadable", false, errors.New("the Claude settings must be a JSON object: invalid character"), "cannot check " + settings + " for its older per-user hooks"},
		{"not migrated yet", true, nil, settings + " still holds DefenseClaw's older per-user Claude Code hooks"},
	} {
		windowsManagedClaudeRegistrationProbe = func(string, string) (bool, []string, error) { return tc.present, nil, tc.err }
		enterpriseHookGuardianWatching.Store(false)
		if err := windowsCopilotVSCodeUser(home, true, false); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: verify must name the file and the reason: %v", tc.name, err)
		}
		enterpriseHookGuardianWatching.Store(true)
		if err := windowsCopilotVSCodeUser(home, true, false); err != nil && strings.Contains(err.Error(), settings) {
			t.Fatalf("%s: the guardian's own pass must not fail the row on the Claude settings: %v", tc.name, err)
		}
		enterpriseHookGuardianWatching.Store(false)
		notes := &enterpriseHookNoteSet{}
		enterpriseHookReadinessNotes.Store(notes)
		err := windowsCopilotVSCodeUser(home, true, false)
		enterpriseHookReadinessNotes.Store(nil)
		if err != nil && strings.Contains(err.Error(), settings) {
			t.Fatalf("%s: Setup readiness must not fail the row (and the whole Install/Upgrade) on one account's Claude settings: %v", tc.name, err)
		}
		if got := notes.list(); len(got) != 1 || !strings.Contains(got[0], tc.want) {
			t.Fatalf("%s: Setup readiness must report the file and the reason as a warning: %q", tc.name, got)
		}
	}
	windowsManagedClaudeRegistrationProbe = func(string, string) (bool, []string, error) { return false, nil, nil }
	enterpriseHookGuardianWatching.Store(false)
	if err := windowsCopilotVSCodeUser(home, true, false); err != nil && strings.Contains(err.Error(), settings) {
		t.Fatalf("migrated settings must pass: %v", err)
	}
}
