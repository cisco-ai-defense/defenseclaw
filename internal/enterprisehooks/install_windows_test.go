//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

type windowsManagedInstallFixture struct {
	home       string
	policyPath string
	hookExe    string
	targetSID  *windows.SID
}

func newWindowsManagedInstallFixture(t *testing.T, basePolicy map[string]interface{}) windowsManagedInstallFixture {
	t.Helper()
	targetSID := currentWindowsTestSID(t)
	scope := t.TempDir()
	home := filepath.Join(scope, "home")
	policyRoot := filepath.Join(scope, "policy", "ClaudeCode")
	dropin := filepath.Join(policyRoot, "managed-settings.d")
	for _, path := range []string{home, policyRoot, dropin} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := setWindowsUserPathProtection(home, targetSID, true); err != nil {
		t.Fatalf("harden test home: %v", err)
	}

	originalAdmin := windowsEnterpriseAdministratorCheck
	originalHook := windowsEnterpriseHookExecutable
	originalHookTrust := windowsEnterpriseHookTrustCheck
	originalPath := windowsClaudeManagedPolicyPathResolver
	originalHigher := windowsClaudeHigherPolicyCheck
	originalOwner := windowsManagedPolicyOwnerSID
	originalRuntimeOwner := windowsManagedRuntimeOwnerSID
	originalRuntimeChildOpen := windowsManagedRuntimeChildOpen
	originalDirTrust := windowsManagedPolicyDirTrustCheck
	originalFileTrust := windowsManagedPolicyFileTrustCheck
	originalWriter := windowsManagedPolicyWriter
	originalProfile := windowsEnterpriseProfilePathResolver
	originalTransaction := windowsClaudeManagedPolicyTransaction
	originalConnectorPolicyRoot := connector.ClaudeCodeManagedSettingsRootOverride
	windowsEnterpriseAdministratorCheck = func() error { return nil }
	windowsClaudeHigherPolicyCheck = func() error { return nil }
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return targetSID, nil }
	windowsManagedRuntimeOwnerSID = func() (*windows.SID, error) { return targetSID, nil }
	windowsManagedPolicyDirTrustCheck = func(path string) error {
		return validateWindowsUserPathElement(path, targetSID, true, true, true)
	}
	windowsManagedPolicyFileTrustCheck = func(path string) error {
		return validateWindowsUserPathElement(path, targetSID, false, false, true)
	}
	windowsManagedPolicyWriter = writeWindowsManagedFile
	windowsClaudeManagedPolicyTransaction = func(fn func() error) error { return fn() }
	policyPath := filepath.Join(dropin, windowsClaudeManagedPolicyFile)
	windowsClaudeManagedPolicyPathResolver = func() (string, error) { return policyPath, nil }
	windowsEnterpriseProfilePathResolver = func() (string, error) { return home, nil }
	connector.ClaudeCodeManagedSettingsRootOverride = policyRoot

	for _, path := range []string{policyRoot, dropin} {
		if err := setWindowsManagedPolicyProtection(path, true, false); err != nil {
			t.Fatalf("harden test policy dir %s: %v", path, err)
		}
	}
	if basePolicy != nil {
		body, err := json.MarshalIndent(basePolicy, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		basePath := filepath.Join(policyRoot, "managed-settings.json")
		if err := os.WriteFile(basePath, append(body, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := setWindowsManagedPolicyProtection(basePath, false, true); err != nil {
			t.Fatal(err)
		}
	}

	hookExe := filepath.Join(scope, "trusted", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(hookExe), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookExe, []byte("test native hook"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(filepath.Dir(hookExe), targetSID, true); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(hookExe, targetSID, false); err != nil {
		t.Fatal(err)
	}
	windowsEnterpriseHookExecutable = func() (string, error) { return hookExe, nil }
	windowsEnterpriseHookTrustCheck = func(path string) error {
		return validateWindowsUserPathElement(path, targetSID, false, false, true)
	}
	t.Cleanup(func() {
		windowsEnterpriseAdministratorCheck = originalAdmin
		windowsEnterpriseHookExecutable = originalHook
		windowsEnterpriseHookTrustCheck = originalHookTrust
		windowsClaudeManagedPolicyPathResolver = originalPath
		windowsClaudeHigherPolicyCheck = originalHigher
		windowsManagedPolicyOwnerSID = originalOwner
		windowsManagedRuntimeOwnerSID = originalRuntimeOwner
		windowsManagedRuntimeChildOpen = originalRuntimeChildOpen
		windowsManagedPolicyDirTrustCheck = originalDirTrust
		windowsManagedPolicyFileTrustCheck = originalFileTrust
		windowsManagedPolicyWriter = originalWriter
		windowsEnterpriseProfilePathResolver = originalProfile
		windowsClaudeManagedPolicyTransaction = originalTransaction
		connector.ClaudeCodeManagedSettingsRootOverride = originalConnectorPolicyRoot
	})
	return windowsManagedInstallFixture{home: home, policyPath: policyPath, hookExe: hookExe, targetSID: targetSID}
}

func windowsManagedInstallOptions(fixture windowsManagedInstallFixture) InstallOptions {
	return InstallOptions{
		ConnectorName: "claudecode",
		UserHome:      fixture.home,
		OwnerUID:      -1,
		OwnerGID:      -1,
		OwnerSID:      fixture.targetSID.String(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      strings.Repeat("a", 64),
		OTLPPathToken: strings.Repeat("b", 64),
		GuardrailMode: "action",
		HookFailMode:  "closed",
		AgentVersion:  "2.1.187 (Claude Code)",
		Registry:      connector.NewDefaultRegistry(),
	}
}

func TestInstallWindowsClaudeManagedPolicySurvivesManagedOnlyHooks(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{
		"allowManagedHooksOnly": true,
		"companyAnnouncements":  []interface{}{"managed by test"},
	})
	customClaudeConfig := filepath.Join(fixture.home, "custom-claude-config")
	customDefenseClawHome := filepath.Join(fixture.home, "custom-defenseclaw-home")
	t.Setenv("CLAUDE_CONFIG_DIR", customClaudeConfig)
	t.Setenv("DEFENSECLAW_HOME", customDefenseClawHome)
	opts := windowsManagedInstallOptions(fixture)
	result, err := Install(context.Background(), opts)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(result.HookConfigPaths) != 1 || !strings.EqualFold(result.HookConfigPaths[0], fixture.policyPath) {
		t.Fatalf("managed policy paths = %v, want %s", result.HookConfigPaths, fixture.policyPath)
	}
	if _, err := os.Lstat(filepath.Join(fixture.home, ".claude", "settings.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("enterprise install wrote user Claude settings: %v", err)
	}
	for _, redirected := range []string{customClaudeConfig, customDefenseClawHome} {
		if _, err := os.Lstat(redirected); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("managed install followed process environment redirect %s: %v", redirected, err)
		}
	}
	data, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]interface{}
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	if _, exists := policy["env"]; exists {
		t.Fatal("machine managed policy contains per-user OTLP environment")
	}
	hooks, ok := policy["hooks"].(map[string]interface{})
	if !ok || len(hooks) < 20 {
		t.Fatalf("managed hook matrix missing: %#v", policy["hooks"])
	}
	preTool, ok := hooks["PreToolUse"].([]interface{})
	if !ok || len(preTool) != 1 {
		t.Fatalf("PreToolUse managed hooks = %#v", hooks["PreToolUse"])
	}
	entry := preTool[0].(map[string]interface{})
	handler := entry["hooks"].([]interface{})[0].(map[string]interface{})
	if handler["command"] != fixture.hookExe {
		t.Fatalf("managed command = %q, want %q", handler["command"], fixture.hookExe)
	}
	args := handler["args"].([]interface{})
	if len(args) != 4 || args[0] != "hook" || args[1] != "--connector" || args[2] != "claudecode" || args[3] != "--enterprise-managed" {
		t.Fatalf("managed exec args = %#v", args)
	}
	tokenPath := filepath.Join(fixture.home, ".defenseclaw", "hooks", ".hook-claudecode.token")
	if token, err := os.ReadFile(tokenPath); err != nil || strings.TrimSpace(string(token)) != opts.APIToken {
		t.Fatalf("per-user scoped token = %q, err=%v", token, err)
	}
	runtimeOwner, err := windowsManagedRuntimeOwnerSID()
	if err != nil {
		t.Fatal(err)
	}
	if owner, err := windowsPathOwner(tokenPath); err != nil || !owner.Equals(runtimeOwner) {
		t.Fatalf("runtime token owner = %v, err=%v, want administrator %s", owner, err, runtimeOwner)
	}
	if err := validateWindowsManagedRuntimePathElement(tokenPath, fixture.targetSID, false, false); err != nil {
		t.Fatalf("runtime token DACL: %v", err)
	}
	if err := validateWindowsUserPathElement(fixture.policyPath, fixture.targetSID, false, false, true); err != nil {
		t.Fatalf("managed policy DACL: %v", err)
	}
	statePath := filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile)
	usersSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	if !windowsTestDACLGrants(statePath, usersSID, windows.FILE_GENERIC_READ) {
		t.Fatal("managed ownership sidecar is not readable by standard-user hook processes")
	}
	if dataDir, registered, err := ResolveWindowsClaudeManagedHookRuntime(fixture.hookExe); err != nil || !registered || !strings.EqualFold(dataDir, filepath.Join(fixture.home, ".defenseclaw")) {
		t.Fatalf("managed runtime resolution: data=%q registered=%v err=%v", dataDir, registered, err)
	}
	if _, registered, err := ResolveWindowsClaudeManagedHookRuntime(filepath.Join(filepath.Dir(fixture.hookExe), "stale-hook.exe")); err == nil || registered {
		t.Fatalf("stale executable resolution: registered=%v err=%v, want fail-closed mismatch", registered, err)
	}
	before, err := os.Stat(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("idempotent Install: %v", err)
	}
	after, err := os.Stat(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("no-op reconcile churned managed policy mtime: before=%s after=%s", before.ModTime(), after.ModTime())
	}
}

func TestWindowsManagedRuntimeTargetHasReadOnlyEffectiveRights(t *testing.T) {
	owner := currentWindowsTestSID(t)
	target, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	originalOwner := windowsManagedRuntimeOwnerSID
	windowsManagedRuntimeOwnerSID = func() (*windows.SID, error) { return owner, nil }
	t.Cleanup(func() { windowsManagedRuntimeOwnerSID = originalOwner })

	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := []string{
		filepath.Join(hookDir, ".hookcfg"),
		filepath.Join(hookDir, ".hookcfg.claudecode"),
		filepath.Join(hookDir, ".hook-claudecode.token"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("managed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := hardenWindowsManagedRuntime(dataDir, paths, target); err != nil {
		t.Fatal(err)
	}

	for _, item := range append([]struct {
		path string
		dir  bool
	}{{dataDir, true}, {hookDir, true}}, []struct {
		path string
		dir  bool
	}{{paths[0], false}, {paths[1], false}, {paths[2], false}}...) {
		rights := windowsTestEffectiveRights(t, item.path, target)
		if rights&windows.FILE_GENERIC_READ != windows.FILE_GENERIC_READ {
			t.Fatalf("target effective rights on %s = 0x%x, want FILE_GENERIC_READ", item.path, uint32(rights))
		}
		if item.dir && rights&windows.FILE_GENERIC_EXECUTE != windows.FILE_GENERIC_EXECUTE {
			t.Fatalf("target effective rights on directory %s = 0x%x, want FILE_GENERIC_EXECUTE", item.path, uint32(rights))
		}
		if windowsEnterpriseWriteLikeAccess(rights, item.dir) {
			t.Fatalf("target effective rights on %s remain write-capable: 0x%x", item.path, uint32(rights))
		}
		if err := validateWindowsManagedRuntimePathElement(item.path, target, item.dir, item.dir); err != nil {
			t.Fatalf("managed runtime validation for %s: %v", item.path, err)
		}
	}

	// A target-user write grant is the original bypass primitive. The runtime
	// validator must refuse it before hook code reads the mutable sidecar.
	setWindowsTestManagedRuntimeTargetWriteDACL(t, paths[0], owner, target)
	if err := validateWindowsManagedRuntimePathElement(paths[0], target, false, false); err == nil || !strings.Contains(err.Error(), "target user SID") {
		t.Fatalf("writable target sidecar validation error = %v, want fail-closed refusal", err)
	}
}

func TestResolveWindowsClaudeManagedHookRuntimeFailsClosedOnWritableSidecar(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatal(err)
	}
	sidecar := filepath.Join(fixture.home, ".defenseclaw", "hooks", ".hookcfg")
	setWindowsTestUntrustedWriteDACL(t, sidecar, fixture.targetSID)
	if _, registered, err := ResolveWindowsClaudeManagedHookRuntime(fixture.hookExe); err == nil || registered || !strings.Contains(err.Error(), "write-like access") {
		t.Fatalf("writable managed sidecar resolution: registered=%v err=%v, want fail closed", registered, err)
	}
}

func TestWindowsClaudeManagedPolicyRejectsCustomDataDir(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	opts.DataDir = filepath.Join(fixture.home, "custom-defenseclaw")

	if _, err := Install(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "custom data directories are not supported") {
		t.Fatalf("Install error = %v, want custom data-dir refusal", err)
	}
	if _, err := WatchDirs(opts); err == nil || !strings.Contains(err.Error(), "custom data directories are not supported") {
		t.Fatalf("WatchDirs error = %v, want custom data-dir refusal", err)
	}
	if err := RemoveManagedPolicy(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "custom data directories are not supported") {
		t.Fatalf("RemoveManagedPolicy error = %v, want custom data-dir refusal", err)
	}
	if _, err := os.Lstat(fixture.policyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed policy created after custom data-dir refusal: %v", err)
	}
}

func TestRemoveWindowsClaudeManagedPolicyRejectsDataDirWithSIDOnly(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	opts.UserHome = ""
	opts.DataDir = filepath.Join(fixture.home, ".defenseclaw")

	err := RemoveManagedPolicy(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "cannot be used for SID-only") {
		t.Fatalf("RemoveManagedPolicy error = %v, want SID-only data-dir refusal", err)
	}
}

func TestInstallWindowsClaudeRejectsWrongTargetSIDBeforeMutation(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	opts.OwnerSID = "S-1-5-21-111-222-333-444"
	_, err := Install(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "does not match target SID") {
		t.Fatalf("Install error = %v, want wrong SID refusal", err)
	}
	if _, err := os.Lstat(fixture.policyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("policy created after wrong-SID refusal: %v", err)
	}
}

func TestInstallWindowsClaudeRejectsUnsafeHomeDACL(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	setWindowsTestUntrustedWriteDACL(t, fixture.home, fixture.targetSID)
	_, err := Install(context.Background(), windowsManagedInstallOptions(fixture))
	if err == nil || !strings.Contains(err.Error(), "untrusted Windows principal") {
		t.Fatalf("Install error = %v, want unsafe DACL refusal", err)
	}
}

func TestInstallWindowsClaudeRejectsReparseDataDir(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	outside := filepath.Join(filepath.Dir(fixture.home), "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(fixture.home, ".defenseclaw")
	if err := os.Symlink(outside, link); err != nil {
		output, junctionErr := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, outside).CombinedOutput()
		if junctionErr != nil {
			t.Fatalf("create reparse fixture after symlink error %v: %v: %s", err, junctionErr, output)
		}
	}
	_, err := Install(context.Background(), windowsManagedInstallOptions(fixture))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("Install error = %v, want reparse refusal", err)
	}
}

func TestInstallWindowsClaudeRejectsDataDirSubstitutedAfterHomeBinding(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	dataDir := filepath.Join(fixture.home, ".defenseclaw")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(dataDir, fixture.targetSID, true); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(fixture.home), "outside-runtime")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(filepath.Dir(fixture.home), "junction-probe")
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", probe, outside).CombinedOutput(); err != nil {
		t.Skipf("directory junctions are unavailable: %v (%s)", err, output)
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}

	originalOpen := windowsManagedRuntimeChildOpen
	var swapErr error
	windowsManagedRuntimeChildOpen = func(parent *os.File, name string, target *windows.SID) (windowsManagedRuntimeDirectory, error) {
		if name == ".defenseclaw" {
			originalDir := dataDir + ".original"
			if err := os.Rename(dataDir, originalDir); err != nil {
				swapErr = err
				return windowsManagedRuntimeDirectory{}, err
			}
			if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", dataDir, outside).CombinedOutput(); err != nil {
				swapErr = errors.New(err.Error() + ": " + string(output))
				return windowsManagedRuntimeDirectory{}, swapErr
			}
		}
		return originalOpen(parent, name, target)
	}

	_, err := Install(context.Background(), windowsManagedInstallOptions(fixture))
	if swapErr != nil {
		t.Fatalf("substitute data directory: %v", swapErr)
	}
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("Install error = %v, want bound reparse-substitution refusal", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "hooks")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("privileged runtime write escaped through substituted junction: %v", err)
	}
	if _, err := os.Lstat(fixture.policyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed policy published after runtime binding failure: %v", err)
	}
}

func TestInstallWindowsClaudeRefusesForeignManagedPolicy(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	foreign := []byte("{\"hooks\":{\"PreToolUse\":[]}}\n")
	if err := os.WriteFile(fixture.policyPath, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsManagedPolicyProtection(fixture.policyPath, false, true); err != nil {
		t.Fatal(err)
	}
	_, err := Install(context.Background(), windowsManagedInstallOptions(fixture))
	if err == nil || !strings.Contains(err.Error(), "ownership metadata is incomplete") {
		t.Fatalf("Install error = %v, want foreign-policy refusal", err)
	}
	if got, err := os.ReadFile(fixture.policyPath); err != nil || string(got) != string(foreign) {
		t.Fatalf("foreign policy changed: %q err=%v", got, err)
	}
}

func TestInstallWindowsClaudeRefusesAdministratorPolicyEdit(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	edited := append(append([]byte(nil), original...), ' ', '\n')
	if err := os.WriteFile(fixture.policyPath, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Install(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "changed outside DefenseClaw") {
		t.Fatalf("Install error = %v, want administrator-edit refusal", err)
	}
	if got, err := os.ReadFile(fixture.policyPath); err != nil || string(got) != string(edited) {
		t.Fatalf("administrator edit changed: %q err=%v", got, err)
	}
}

func TestWriteWindowsManagedFileReappliesRequestedACLWhenBytesMatch(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	path := filepath.Join(filepath.Dir(fixture.policyPath), "acl-repair.json")
	body := []byte("{\"schema\":1}\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsManagedPolicyProtection(path, false, false); err != nil {
		t.Fatal(err)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	if windowsTestDACLGrants(path, users, windows.FILE_GENERIC_READ) {
		t.Fatal("fixture unexpectedly grants Users read access")
	}

	if err := writeWindowsManagedFile(path, body, true); err != nil {
		t.Fatalf("writeWindowsManagedFile: %v", err)
	}
	if !windowsTestDACLGrants(path, users, windows.FILE_GENERIC_READ) {
		t.Fatal("unchanged managed file did not receive requested Users read ACL")
	}
}

func TestInstallWindowsClaudeManagedPolicyRejectsOversizedPayloadBeforeWrite(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	originalWriter := windowsManagedPolicyWriter
	writes := 0
	windowsManagedPolicyWriter = func(string, []byte, bool) error {
		writes++
		return nil
	}
	t.Cleanup(func() { windowsManagedPolicyWriter = originalWriter })

	_, rollback, err := installWindowsClaudeManagedPolicy(
		bytes.Repeat([]byte{'x'}, windowsClaudeManagedStateLimit+1),
		connector.SetupOpts{HookExecutable: fixture.hookExe},
		fixture.targetSID,
	)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("installWindowsClaudeManagedPolicy error = %v, want size refusal", err)
	}
	if rollback != nil {
		t.Fatal("oversized managed policy unexpectedly returned rollback")
	}
	if writes != 0 {
		t.Fatalf("managed policy writes = %d, want zero", writes)
	}
}

func TestInstallWindowsClaudeRollsBackRuntimeAndPolicy(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	hookDir := filepath.Join(fixture.home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Dir(hookDir), hookDir} {
		if err := setWindowsUserPathProtection(dir, fixture.targetSID, true); err != nil {
			t.Fatal(err)
		}
	}
	tokenPath := filepath.Join(hookDir, ".hook-claudecode.token")
	const sentinel = "preexisting-runtime\n"
	if err := os.WriteFile(tokenPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(tokenPath, fixture.targetSID, false); err != nil {
		t.Fatal(err)
	}
	originalSecurity := map[string]string{}
	for _, path := range []string{filepath.Dir(hookDir), hookDir, tokenPath} {
		originalSecurity[path] = windowsTestSecurityDescriptor(t, path)
	}
	originalWriter := windowsManagedPolicyWriter
	failed := false
	windowsManagedPolicyWriter = func(path string, data []byte, readable bool) error {
		if filepath.Base(path) == windowsClaudeManagedStateFile && !failed {
			failed = true
			return errors.New("injected state publication failure")
		}
		return writeWindowsManagedFile(path, data, readable)
	}
	t.Cleanup(func() { windowsManagedPolicyWriter = originalWriter })
	_, err := Install(context.Background(), windowsManagedInstallOptions(fixture))
	if err == nil || !strings.Contains(err.Error(), "injected state publication failure") {
		t.Fatalf("Install error = %v, want injected rollback failure", err)
	}
	if got, err := os.ReadFile(tokenPath); err != nil || string(got) != sentinel {
		t.Fatalf("runtime rollback = %q err=%v, want sentinel", got, err)
	}
	for path, want := range originalSecurity {
		if got := windowsTestSecurityDescriptor(t, path); got != want {
			t.Fatalf("runtime security rollback for %s = %q, want %q", path, got, want)
		}
	}
	for _, path := range []string{fixture.policyPath, filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("managed policy artifact survived rollback at %s: %v", path, err)
		}
	}
}

func TestInstallWindowsClaudePublishesFreshRuntimeFileIdentity(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	hookDir := filepath.Join(fixture.home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Dir(hookDir), hookDir} {
		if err := setWindowsUserPathProtection(dir, fixture.targetSID, true); err != nil {
			t.Fatal(err)
		}
	}
	tokenPath := filepath.Join(hookDir, ".hook-claudecode.token")
	if err := os.WriteFile(tokenPath, []byte("preexisting-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(tokenPath, fixture.targetSID, false); err != nil {
		t.Fatal(err)
	}
	before := windowsTestFileIdentity(t, tokenPath)

	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatal(err)
	}
	after := windowsTestFileIdentity(t, tokenPath)
	if before == after {
		t.Fatalf("managed runtime token reused existing file identity: %#v", after)
	}
}

func TestInstallWindowsClaudeRejectsRuntimeFileWithRetainedWritableHandle(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	hookDir := filepath.Join(fixture.home, ".defenseclaw", "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Dir(hookDir), hookDir} {
		if err := setWindowsUserPathProtection(dir, fixture.targetSID, true); err != nil {
			t.Fatal(err)
		}
	}
	tokenPath := filepath.Join(hookDir, ".hook-claudecode.token")
	const sentinel = "retained-writable-handle\n"
	if err := os.WriteFile(tokenPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(tokenPath, fixture.targetSID, false); err != nil {
		t.Fatal(err)
	}
	pathPtr, err := winpath.UTF16Ptr(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)

	_, err = Install(context.Background(), windowsManagedInstallOptions(fixture))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "share") {
		t.Fatalf("Install error = %v, want retained-handle sharing refusal", err)
	}
	if got, readErr := os.ReadFile(tokenPath); readErr != nil || string(got) != sentinel {
		t.Fatalf("runtime file changed after retained-handle refusal: %q err=%v", got, readErr)
	}
	if _, statErr := os.Lstat(fixture.policyPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("managed policy published after retained-handle refusal: %v", statErr)
	}
}

func windowsTestFileIdentity(t *testing.T, path string) [3]uint32 {
	t.Helper()
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		t.Fatal(err)
	}
	return [3]uint32{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}
}

func TestInstallWindowsClaudeRollsBackNewManagedPolicyDirectories(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, nil)
	policyDir := filepath.Dir(fixture.policyPath)
	policyRoot := filepath.Dir(policyDir)
	if err := os.Remove(policyDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(policyRoot); err != nil {
		t.Fatal(err)
	}
	originalWriter := windowsManagedPolicyWriter
	windowsManagedPolicyWriter = func(path string, data []byte, readable bool) error {
		if filepath.Base(path) == windowsClaudeManagedStateFile {
			return errors.New("injected state publication failure")
		}
		return writeWindowsManagedFile(path, data, readable)
	}
	t.Cleanup(func() { windowsManagedPolicyWriter = originalWriter })
	_, err := Install(context.Background(), windowsManagedInstallOptions(fixture))
	if err == nil || !strings.Contains(err.Error(), "injected state publication failure") {
		t.Fatalf("Install error = %v, want injected rollback failure", err)
	}
	for _, path := range []string{policyDir, policyRoot} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("new managed policy directory survived rollback at %s: %v", path, err)
		}
	}
}

func TestInstallWindowsClaudeRejectsHigherPriorityAndDisabledPolicy(t *testing.T) {
	t.Run("higher priority MDM", func(t *testing.T) {
		fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
		windowsClaudeHigherPolicyCheck = func() error { return errors.New("HKLM policy wins") }
		_, err := Install(context.Background(), windowsManagedInstallOptions(fixture))
		if err == nil || !strings.Contains(err.Error(), "HKLM policy wins") {
			t.Fatalf("Install error = %v", err)
		}
	})
	t.Run("disable all hooks", func(t *testing.T) {
		fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true, "disableAllHooks": true})
		_, err := Install(context.Background(), windowsManagedInstallOptions(fixture))
		basePolicyPath := filepath.Join(filepath.Dir(filepath.Dir(fixture.policyPath)), "managed-settings.json")
		if err == nil || !strings.Contains(err.Error(), "disableAllHooks=true") ||
			!strings.Contains(err.Error(), basePolicyPath) {
			t.Fatalf("Install error = %v", err)
		}
	})
	t.Run("policy helper", func(t *testing.T) {
		fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"policyHelper": map[string]interface{}{"path": `C:\Program Files\Policy\helper.exe`}})
		_, err := Install(context.Background(), windowsManagedInstallOptions(fixture))
		basePolicyPath := filepath.Join(filepath.Dir(filepath.Dir(fixture.policyPath)), "managed-settings.json")
		if err == nil || !strings.Contains(err.Error(), "policyHelper") ||
			!strings.Contains(err.Error(), "supersedes file-based managed hooks") ||
			!strings.Contains(err.Error(), basePolicyPath) {
			t.Fatalf("Install error = %v", err)
		}
	})
	t.Run("higher drop-in clears policy helper", func(t *testing.T) {
		fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{
			"policyHelper": map[string]interface{}{"path": `C:\Program Files\Policy\helper.exe`},
		})
		clearPath := filepath.Join(filepath.Dir(fixture.policyPath), "20-clear-policy-helper.json")
		if err := os.WriteFile(clearPath, []byte("{\"policyHelper\":null}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := setWindowsManagedPolicyProtection(clearPath, false, true); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
			t.Fatalf("Install with cleared policyHelper: %v", err)
		}
	})
}

func TestRemoveWindowsClaudeManagedPolicyRemovesLastOwnedTarget(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	runtimeToken := filepath.Join(fixture.home, ".defenseclaw", "hooks", ".hook-claudecode.token")
	if err := RemoveManagedPolicy(context.Background(), opts); err != nil {
		t.Fatalf("RemoveManagedPolicy: %v", err)
	}
	for _, path := range []string{fixture.policyPath, filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("managed policy artifact survived cleanup at %s: %v", path, err)
		}
	}
	if got, err := os.ReadFile(runtimeToken); err != nil || strings.TrimSpace(string(got)) != opts.APIToken {
		t.Fatalf("cleanup removed recovery runtime: token=%q err=%v", got, err)
	}
	if err := RemoveManagedPolicy(context.Background(), opts); err != nil {
		t.Fatalf("idempotent RemoveManagedPolicy: %v", err)
	}
}

func TestRemoveWindowsClaudeManagedPolicyRefusesTamperedPolicy(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append(append([]byte(nil), original...), ' ', '\n')
	if err := os.WriteFile(fixture.policyPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveManagedPolicy(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "changed outside DefenseClaw") {
		t.Fatalf("RemoveManagedPolicy error = %v, want tamper refusal", err)
	}
	if got, err := os.ReadFile(fixture.policyPath); err != nil || string(got) != string(tampered) {
		t.Fatalf("tampered policy changed during refused cleanup: %q err=%v", got, err)
	}
}

func TestRemoveWindowsClaudeManagedPolicyAllowsSIDOnlyForAbsentProfile(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	opts.UserHome = ""
	if err := RemoveManagedPolicy(context.Background(), opts); err != nil {
		t.Fatalf("SID-only RemoveManagedPolicy: %v", err)
	}
	if _, err := os.Lstat(fixture.policyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed policy survived SID-only cleanup: %v", err)
	}
}

func TestRemoveWindowsClaudeManagedPolicyKeepsPolicyForOtherTargets(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile)
	stateData, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state windowsClaudeManagedPolicyState
	if err := json.Unmarshal(stateData, &state); err != nil {
		t.Fatal(err)
	}
	const otherSID = "S-1-5-21-111-222-333-1001"
	state.TargetSIDs = append(state.TargetSIDs, otherSID)
	state.TargetSIDs = sortedUnique(state.TargetSIDs)
	stateData, err = json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeWindowsManagedFile(statePath, append(stateData, '\n'), false); err != nil {
		t.Fatal(err)
	}
	if err := RemoveManagedPolicy(context.Background(), opts); err != nil {
		t.Fatalf("RemoveManagedPolicy: %v", err)
	}
	if _, err := os.Stat(fixture.policyPath); err != nil {
		t.Fatalf("shared managed policy removed: %v", err)
	}
	stateData, err = os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(stateData, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.TargetSIDs) != 1 || state.TargetSIDs[0] != otherSID {
		t.Fatalf("remaining target SIDs = %v, want [%s]", state.TargetSIDs, otherSID)
	}
	if _, registered, err := ResolveWindowsClaudeManagedHookRuntime(fixture.hookExe); err != nil || registered {
		t.Fatalf("removed target still active: registered=%v err=%v", registered, err)
	}
}

func currentWindowsTestSID(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current Windows token user: %v", err)
	}
	return user.User.Sid
}

func setWindowsTestUntrustedWriteDACL(t *testing.T, path string, owner *windows.SID) {
	t.Helper()
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	entries := []windows.EXPLICIT_ACCESS{}
	for _, item := range []struct {
		sid  *windows.SID
		mask windows.ACCESS_MASK
	}{{owner, windows.GENERIC_ALL}, {system, windows.GENERIC_ALL}, {everyone, windows.GENERIC_WRITE}} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: item.mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(item.sid)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func setWindowsTestManagedRuntimeTargetWriteDACL(t *testing.T, path string, owner, target *windows.SID) {
	t.Helper()
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	entries := []windows.EXPLICIT_ACCESS{}
	for _, item := range []struct {
		sid  *windows.SID
		mask windows.ACCESS_MASK
	}{
		{owner, windows.GENERIC_ALL},
		{system, windows.GENERIC_ALL},
		{target, windows.GENERIC_READ | windows.GENERIC_WRITE},
	} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: item.mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER, TrusteeValue: windows.TrusteeValueFromSID(item.sid)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func windowsTestEffectiveRights(t *testing.T, path string, principal *windows.SID) windows.ACCESS_MASK {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("read DACL for %s: %v", path, err)
	}
	trustee := windows.TRUSTEE{
		TrusteeForm:  windows.TRUSTEE_IS_SID,
		TrusteeType:  windows.TRUSTEE_IS_USER,
		TrusteeValue: windows.TrusteeValueFromSID(principal),
	}
	var rights windows.ACCESS_MASK
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("GetEffectiveRightsFromAclW")
	status, _, _ := proc.Call(
		uintptr(unsafe.Pointer(dacl)),
		uintptr(unsafe.Pointer(&trustee)),
		uintptr(unsafe.Pointer(&rights)),
	)
	if status != 0 {
		t.Fatalf("GetEffectiveRightsFromAclW(%s, %s): %v", path, principal, syscall.Errno(status))
	}
	return rights
}

func windowsTestSecurityDescriptor(t *testing.T, path string) string {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor.String()
}

func windowsTestDACLGrants(path string, principal *windows.SID, mask windows.ACCESS_MASK) bool {
	extended, err := winpath.Extended(path)
	if err != nil {
		return false
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(principal) && ace.Mask&mask == mask {
			return true
		}
	}
	return false
}
