// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
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
	// An administrator console cannot read a profile whose settings carry a
	// private ACL; only LocalSystem (Setup, the guardian) fails the row on it.
	previousSystem := windowsClaudeSettingsCheckerIsLocalSystem
	t.Cleanup(func() { windowsClaudeSettingsCheckerIsLocalSystem = previousSystem })
	windowsManagedClaudeRegistrationProbe = func(string, string) (bool, []string, error) {
		return false, nil, fmt.Errorf("open settings.json: %w", os.ErrPermission)
	}
	windowsClaudeSettingsCheckerIsLocalSystem = func() bool { return false }
	if err := windowsCopilotVSCodeUser(home, true, false); err != nil && strings.Contains(err.Error(), settings) {
		t.Fatalf("an administrator console must not fail the row on a file it may not read: %v", err)
	}
	windowsClaudeSettingsCheckerIsLocalSystem = func() bool { return true }
	if err := windowsCopilotVSCodeUser(home, true, false); err == nil || !strings.Contains(err.Error(), "cannot check "+settings) {
		t.Fatalf("LocalSystem must fail the row on a file it cannot read: %v", err)
	}
	// GAP-0031: with the DefenseClaw hook file and plugin in place the
	// settings file is the row's only fault, and verify says so (the
	// protected records are then compared with the row as protected); any
	// other fault of the row is not excused by it.
	windowsManagedClaudeRegistrationProbe = func(string, string) (bool, []string, error) { return false, nil, nil }
	if err := windowsCopilotVSCodeUser(home, false, false); err != nil {
		t.Fatalf("place the Copilot hook file: %v", err)
	}
	windowsManagedClaudeRegistrationProbe = func(string, string) (bool, []string, error) {
		return false, nil, errors.New("the Claude settings must be a JSON object: invalid character")
	}
	var userFile enterpriseHookUserFileFault
	err := windowsCopilotVSCodeUser(home, true, false)
	if !errors.As(err, &userFile) || !strings.Contains(err.Error(), "cannot check "+settings) {
		t.Fatalf("the settings file is the only fault and must be reported as one: %v", err)
	}
	hookFile := enterprisepolicy.CopilotVSCodeLocalHookFilePath(home)
	if err := os.Remove(hookFile); err != nil {
		t.Fatal(err)
	}
	err = windowsCopilotVSCodeUser(home, true, false)
	if err == nil || errors.As(err, &userFile) || !strings.Contains(err.Error(), "cannot check "+settings) {
		t.Fatalf("a missing hook file is a second fault: verify must name both and not report a user-file-only fault: %v", err)
	}
}

// GAP-1970: a verify or readiness run lists the eligible profiles once for
// all its Copilot rows, not once per row; a check outside a run still lists
// them itself.
func TestWindowsClaudeSettingsCheckListsProfilesOncePerVerifyRun(t *testing.T) {
	previousProfiles, previousProbe := enterpriseHookWindowsEligibleProfiles, windowsManagedClaudeRegistrationProbe
	t.Cleanup(func() {
		enterpriseHookWindowsEligibleProfiles, windowsManagedClaudeRegistrationProbe = previousProfiles, previousProbe
		enterpriseHookVerifyProfiles.Store(nil)
	})
	homes := []string{t.TempDir(), t.TempDir(), t.TempDir()}
	lists := 0
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		lists++
		out := make([]enterprisehooks.TargetCredentials, 0, len(homes))
		for i, home := range homes {
			out = append(out, enterprisehooks.TargetCredentials{UserHome: home, UID: -1, GID: -1, SID: fmt.Sprintf("S-1-5-21-1-2-3-%d", 1001+i)})
		}
		return out, nil
	}
	probed := map[string]int{}
	windowsManagedClaudeRegistrationProbe = func(home, _ string) (bool, []string, error) {
		probed[home]++
		return home == homes[1], nil, nil
	}
	end := enterpriseHookVerifyRunScope()
	for i, home := range homes {
		err := windowsClaudeUserSettingsMigrated(home)
		if (i == 1) != (err != nil) {
			t.Fatalf("home %d: the check must still judge each account on its own file: %v", i, err)
		}
	}
	if lists != 1 {
		t.Fatalf("one verify run with %d Copilot rows listed the eligible profiles %d times, want 1", len(homes), lists)
	}
	for _, home := range homes {
		if probed[home] != 1 {
			t.Fatalf("each account's Claude settings are read once per row: %v", probed)
		}
	}
	end()
	lists = 0
	_ = windowsClaudeUserSettingsMigrated(homes[0])
	_ = windowsClaudeUserSettingsMigrated(homes[0])
	if lists != 2 {
		t.Fatalf("outside a verify run each check must list the profiles itself (no stale list): %d", lists)
	}
}

// GAP-1967 (and the GAP-1969 wording): status, verify and ensure, which
// Setup /status, /verify, /ensure and Intune detection report, warn
// claude_settings_unmigrated with the file and the reason for each enrolled
// account whose Claude settings the migration cannot finish, instead of
// reporting healthy while that account's Copilot and Cursor calls block.
func TestWindowsStatusWarnsAnUnmigratableClaudeSettingsFile(t *testing.T) {
	previousHome, previousProbe, previousSystem := windowsEnterpriseClaudeSettingsHome, windowsManagedClaudeRegistrationProbe, windowsClaudeSettingsCheckerIsLocalSystem
	t.Cleanup(func() {
		windowsEnterpriseClaudeSettingsHome, windowsManagedClaudeRegistrationProbe, windowsClaudeSettingsCheckerIsLocalSystem = previousHome, previousProbe, previousSystem
	})
	root := t.TempDir()
	homes := map[string]string{}
	for _, name := range []string{"bom", "readonly", "clean", "denied"} {
		homes[name] = filepath.Join(root, name)
	}
	sids := map[string]string{
		"S-1-5-21-1-2-3-1001": "bom",
		"S-1-5-21-1-2-3-1002": "readonly",
		"S-1-5-21-1-2-3-1003": "clean",
		"S-1-5-21-1-2-3-1004": "denied",
	}
	windowsEnterpriseClaudeSettingsHome = func(sid string) (string, error) {
		name, ok := sids[sid]
		if !ok {
			return "", os.ErrNotExist
		}
		return homes[name], nil
	}
	windowsManagedClaudeRegistrationProbe = func(home, _ string) (bool, []string, error) {
		switch home {
		case homes["bom"]:
			return false, nil, errors.New("the Claude settings must be a JSON object: invalid character 'ï' looking for beginning of value")
		case homes["readonly"]:
			return true, nil, nil
		case homes["denied"]:
			return false, nil, fmt.Errorf("open settings.json: %w", os.ErrPermission)
		}
		return false, nil, nil
	}
	accounts := []enterprisestatus.EnrollmentAccount{
		{Account: `DCLAB\bom`, SID: "S-1-5-21-1-2-3-1001"},
		{Account: `DCLAB\bom`, SID: "s-1-5-21-1-2-3-1001"},
		{Account: `DCLAB\readonly`, SID: "S-1-5-21-1-2-3-1002"},
		{Account: `DCLAB\clean`, SID: "S-1-5-21-1-2-3-1003"},
		{Account: `DCLAB\denied`, SID: "S-1-5-21-1-2-3-1004"},
		{Account: `DCLAB\gone`, SID: "S-1-5-21-1-2-3-1999"},
		{Account: "nosid"},
	}
	// An administrator console cannot read a profile with a private ACL;
	// LocalSystem (Setup, the guardian) can, so only it reports access denied.
	windowsClaudeSettingsCheckerIsLocalSystem = func() bool { return false }
	admin := &enterprisestatus.Result{}
	appendWindowsClaudeUserSettingsWarnings(admin, accounts)
	if len(admin.Warnings) != 2 {
		t.Fatalf("an administrator console must not report a file it may not read: %+v", admin.Warnings)
	}
	windowsClaudeSettingsCheckerIsLocalSystem = func() bool { return true }
	result := &enterprisestatus.Result{}
	appendWindowsClaudeUserSettingsWarnings(result, accounts)
	if len(result.Warnings) != 3 {
		t.Fatalf("want one warning each for the unreadable, the unremovable and the access-denied file, got %+v", result.Warnings)
	}
	for _, warning := range result.Warnings {
		if warning.Code != "claude_settings_unmigrated" {
			t.Fatalf("warning code: %+v", warning)
		}
	}
	bom := filepath.Join(homes["bom"], ".claude", "settings.json")
	if !strings.Contains(result.Warnings[0].Message, "cannot check "+bom) || !strings.Contains(result.Warnings[0].Message, "without a byte order mark") {
		t.Fatalf("the unreadable file's warning must name the file and the fix: %s", result.Warnings[0].Message)
	}
	readonly := filepath.Join(homes["readonly"], ".claude", "settings.json")
	if !strings.Contains(result.Warnings[1].Message, readonly) || !strings.Contains(result.Warnings[1].Message, "remove the hooks by hand") {
		t.Fatalf("a file the guardian cannot write must name the by-hand fix (GAP-1969): %s", result.Warnings[1].Message)
	}
	denied := filepath.Join(homes["denied"], ".claude", "settings.json")
	if !strings.Contains(result.Warnings[2].Message, "cannot check "+denied) {
		t.Fatalf("LocalSystem reports a file it cannot read as verify reports it: %s", result.Warnings[2].Message)
	}
}
