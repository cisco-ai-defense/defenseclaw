//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	gatewayExe string
	targetSID  *windows.SID
}

type windowsGenericCodexFixture struct {
	home      string
	config    string
	targetSID *windows.SID
	opts      InstallOptions
}

type windowsGenericCodexTestConnector struct {
	configPath string
	setupCalls *int
	name       string
}

const windowsGenericTestConnectorName = "codex"

func validateWindowsTestManagedPolicyProtection(
	path string,
	owner *windows.SID,
	directory bool,
) error {
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	actualOwner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if actualOwner == nil || !actualOwner.Equals(owner) {
		return fmt.Errorf(
			"managed policy fixture owner = %s, want %s",
			windowsSIDString(actualOwner),
			windowsSIDString(owner),
		)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("managed policy fixture DACL is not protected: %s", path)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("managed policy fixture DACL is null or unreadable: %s", path)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return err
	}
	type principalCoverage struct {
		current bool
		child   bool
		count   int
	}
	coverage := map[string]*principalCoverage{
		owner.String():  {},
		system.String(): {},
		users.String():  {},
	}
	seen := map[string]bool{}
	fullMasks := map[windows.ACCESS_MASK]bool{
		windows.GENERIC_ALL: true,
		mapWindowsUserPathGenericMask(windows.GENERIC_ALL): true,
	}
	userGenericMask := windows.ACCESS_MASK(windows.GENERIC_READ)
	if directory {
		userGenericMask |= windows.GENERIC_EXECUTE
	}
	userMasks := map[windows.ACCESS_MASK]bool{
		userGenericMask: true,
		mapWindowsUserPathGenericMask(userGenericMask): true,
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("managed policy fixture contains a non-allow ACE: %s", path)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		sidString := sid.String()
		principal, allowed := coverage[sidString]
		if !allowed {
			return fmt.Errorf(
				"managed policy fixture contains an unexpected principal %s",
				sidString,
			)
		}
		if directory {
			allowedFlags := map[uint8]bool{
				0: true,
				uint8(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT):                            true,
				uint8(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT) | windows.INHERIT_ONLY_ACE: true,
			}
			if !allowedFlags[ace.Header.AceFlags] {
				return fmt.Errorf(
					"managed policy fixture contains unexpected inheritance 0x%x for %s",
					uint32(ace.Header.AceFlags),
					sidString,
				)
			}
		} else if ace.Header.AceFlags != 0 {
			return fmt.Errorf(
				"managed policy fixture file contains inherited ACE flags 0x%x for %s",
				uint32(ace.Header.AceFlags),
				sidString,
			)
		}
		if sid.Equals(users) {
			if !userMasks[ace.Mask] {
				return fmt.Errorf(
					"managed policy fixture grants unexpected user mask 0x%x",
					uint32(ace.Mask),
				)
			}
		} else if !fullMasks[ace.Mask] {
			return fmt.Errorf(
				"managed policy fixture grants non-canonical trusted mask 0x%x to %s",
				uint32(ace.Mask),
				sidString,
			)
		}
		signature := fmt.Sprintf("%s:%x:%x", sidString, uint32(ace.Mask), ace.Header.AceFlags)
		if seen[signature] {
			return fmt.Errorf("managed policy fixture contains duplicate ACE %s", signature)
		}
		seen[signature] = true
		principal.count++
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
			principal.current = true
		}
		if ace.Header.AceFlags&uint8(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT) ==
			uint8(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT) {
			principal.child = true
		}
		if principal.count > 2 {
			return fmt.Errorf("managed policy fixture has too many ACEs for %s", sidString)
		}
	}
	for _, sid := range []*windows.SID{owner, system} {
		principal := coverage[sid.String()]
		if !principal.current || (directory && !principal.child) {
			return fmt.Errorf(
				"managed policy fixture lacks canonical full-control coverage for %s",
				sid.String(),
			)
		}
	}
	if directory {
		userCoverage := coverage[users.String()]
		if !userCoverage.current || !userCoverage.child {
			return fmt.Errorf("managed policy fixture lacks canonical inherited user read/execute")
		}
	}
	return nil
}

func (c *windowsGenericCodexTestConnector) Name() string {
	if strings.TrimSpace(c.name) != "" {
		return strings.ToLower(strings.TrimSpace(c.name))
	}
	return windowsGenericTestConnectorName
}
func (c *windowsGenericCodexTestConnector) Description() string {
	return "Windows generic guardian lifecycle test connector"
}
func (c *windowsGenericCodexTestConnector) ToolInspectionMode() connector.ToolInspectionMode {
	return connector.ToolModePreExecution
}
func (c *windowsGenericCodexTestConnector) SubprocessPolicy() connector.SubprocessPolicy {
	return connector.SubprocessNone
}
func (c *windowsGenericCodexTestConnector) Setup(_ context.Context, opts connector.SetupOpts) error {
	if c.setupCalls != nil {
		(*c.setupCalls)++
	}
	lock, err := os.OpenFile(c.configPath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := lock.Close(); err != nil {
		return err
	}
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := connector.WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c); err != nil {
		return err
	}
	body, err := json.MarshalIndent(map[string]any{
		"model": "gpt-5",
		"hooks": []any{map[string]any{
			"command": connector.NativeHookExecutable(),
			"args":    []string{"hook", "--connector", c.Name()},
		}},
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.configPath, append(body, '\n'), 0o600)
}
func (c *windowsGenericCodexTestConnector) Teardown(_ context.Context, _ connector.SetupOpts) error {
	return os.WriteFile(c.configPath, []byte("{\"model\":\"gpt-5\"}\n"), 0o600)
}
func (c *windowsGenericCodexTestConnector) Authenticate(*http.Request) bool { return false }
func (c *windowsGenericCodexTestConnector) Route(*http.Request, []byte) (*connector.ConnectorSignals, error) {
	return nil, errors.New("test connector has no route")
}
func (c *windowsGenericCodexTestConnector) SetCredentials(string, string) {}
func (c *windowsGenericCodexTestConnector) VerifyClean(_ connector.SetupOpts) error {
	body, err := os.ReadFile(c.configPath)
	if err != nil {
		return err
	}
	if strings.Contains(string(body), "hook --connector "+c.Name()) {
		return errors.New("managed Codex test hook survived teardown")
	}
	return nil
}
func (c *windowsGenericCodexTestConnector) HookScriptNames(connector.SetupOpts) []string {
	return []string{"codex-hook.sh"}
}
func (c *windowsGenericCodexTestConnector) HookScripts(opts connector.SetupOpts) []string {
	return []string{filepath.Join(opts.DataDir, "hooks", "codex-hook.sh")}
}
func (c *windowsGenericCodexTestConnector) HookCapabilities(connector.SetupOpts) connector.HookCapability {
	return connector.HookCapability{
		CanBlock:           true,
		SupportsFailClosed: true,
		ConfigPath:         c.configPath,
	}
}
func (c *windowsGenericCodexTestConnector) AgentPaths(opts connector.SetupOpts) connector.AgentPaths {
	return connector.AgentPaths{
		PatchedFiles: []string{c.configPath},
		HookScripts:  c.HookScripts(opts),
		CreatedDirs:  []string{filepath.Join(opts.DataDir, "hooks")},
	}
}

func newWindowsGenericCodexFixture(t *testing.T) windowsGenericCodexFixture {
	return newWindowsGenericCodexFixtureBeforeProtection(t, nil)
}

// newWindowsTrustedHookExecutableFixture writes a launcher standing in for the
// administrator-owned sibling an enterprise install ships beside the gateway.
func newWindowsTrustedHookExecutableFixture(t *testing.T, targetSID *windows.SID) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "defenseclaw-hook.exe")
	if err := os.WriteFile(path, []byte("MZ test native hook"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(dir, targetSID, true); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(path, targetSID, false); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInstallWindowsGenericRejectsConnectorResolvingForeignHookExecutable(t *testing.T) {
	fixture := newWindowsGenericCodexFixture(t)
	foreign := newWindowsTrustedHookExecutableFixture(t, fixture.targetSID)
	restore := connector.PinNativeHookExecutableForTest(foreign)
	defer restore()

	_, _, err := platformInstall(context.Background(), fixture.opts)
	if err == nil {
		t.Fatal("install succeeded while the connector resolved a launcher the guardian never trusted")
	}
	if !strings.Contains(err.Error(), "non-authoritative hook executable") {
		t.Fatalf("error = %v, want non-authoritative hook executable rejection", err)
	}
	if !strings.Contains(err.Error(), foreign) {
		t.Fatalf("error = %v, want the connector-resolved path %s reported", err, foreign)
	}
}

func newWindowsGenericCodexFixtureBeforeProtection(
	t *testing.T,
	beforeProtection func(configPath string),
) windowsGenericCodexFixture {
	t.Helper()
	targetSID := currentWindowsTestSID(t)
	home := filepath.Join(t.TempDir(), "home")
	configDir := filepath.Join(home, ".codex")
	configPath := filepath.Join(configDir, "hooks.json")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("{\"model\":\"gpt-5\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if beforeProtection != nil {
		beforeProtection(configPath)
	}
	for _, path := range []struct {
		path string
		dir  bool
	}{{home, true}, {configDir, true}, {configPath, false}} {
		if err := setWindowsUserPathProtection(path.path, targetSID, path.dir); err != nil {
			t.Fatalf("protect generic Codex fixture %s: %v", path.path, err)
		}
	}

	// The guardian side and the connector side are pinned from separate sources
	// so the authoritative-launcher comparison stays falsifiable.
	trustedHookExe := newWindowsTrustedHookExecutableFixture(t, targetSID)
	restoreRenderedHook := connector.PinNativeHookExecutableForTest(trustedHookExe)

	originalAdmin := windowsEnterpriseAdministratorCheck
	originalIdentity := windowsEnterpriseMutationIdentityCheck
	originalImpersonation := windowsEnterpriseTargetImpersonation
	originalHook := windowsEnterpriseHookExecutable
	originalHookTrust := windowsEnterpriseHookTrustCheck
	originalCertification := windowsEnterpriseConnectorCertification
	originalGuardianRepair := windowsEnterpriseGuardianDACLRepair
	windowsEnterpriseAdministratorCheck = func() error { return nil }
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	windowsEnterpriseTargetImpersonation = func(_ *windows.SID, _ string, fn func() error) error {
		return runWindowsTestThreadImpersonatedAsSelf(fn)
	}
	windowsEnterpriseHookExecutable = func() (string, error) { return trustedHookExe, nil }
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	windowsEnterpriseConnectorCertification = func(string, connector.Connector) error { return nil }
	windowsEnterpriseGuardianDACLRepair = repairWindowsTargetOwnedPathDACLNoFollow
	t.Cleanup(func() {
		restoreRenderedHook()
		windowsEnterpriseAdministratorCheck = originalAdmin
		windowsEnterpriseMutationIdentityCheck = originalIdentity
		windowsEnterpriseTargetImpersonation = originalImpersonation
		windowsEnterpriseHookExecutable = originalHook
		windowsEnterpriseHookTrustCheck = originalHookTrust
		windowsEnterpriseConnectorCertification = originalCertification
		windowsEnterpriseGuardianDACLRepair = originalGuardianRepair
	})
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(&windowsGenericCodexTestConnector{configPath: configPath})
	opts := InstallOptions{
		ConnectorName: windowsGenericTestConnectorName,
		UserHome:      home,
		OwnerSID:      targetSID.String(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      strings.Repeat("c", 64),
		OTLPPathToken: strings.Repeat("d", 64),
		GuardrailMode: "action",
		HookFailMode:  "closed",
		AgentVersion:  "codex-cli 0.142.0",
		Registry:      registry,
	}
	return windowsGenericCodexFixture{
		home:      home,
		config:    configPath,
		targetSID: targetSID,
		opts:      opts,
	}
}

func newWindowsManagedInstallFixture(t *testing.T, basePolicy map[string]interface{}) windowsManagedInstallFixture {
	return newWindowsManagedInstallFixtureWithHomeSetup(t, basePolicy, nil)
}

func newWindowsManagedInstallFixtureWithHomeSetup(
	t *testing.T,
	basePolicy map[string]interface{},
	homeSetup func(home string, targetSID *windows.SID),
) windowsManagedInstallFixture {
	t.Helper()
	t.Setenv(connector.WindowsGatewayServiceNameEnv, "DefenseClawGateway-Test")
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
	if homeSetup != nil {
		homeSetup(home, targetSID)
	} else if err := setWindowsUserPathProtection(home, targetSID, true); err != nil {
		t.Fatalf("harden test home: %v", err)
	}

	originalAdmin := windowsEnterpriseAdministratorCheck
	originalMutationIdentity := windowsEnterpriseMutationIdentityCheck
	originalTargetImpersonation := windowsEnterpriseTargetImpersonation
	originalHook := windowsEnterpriseHookExecutable
	originalHookTrust := windowsEnterpriseHookTrustCheck
	originalPath := windowsClaudeManagedPolicyPathResolver
	originalHigher := windowsClaudeHigherPolicyCheck
	originalOwner := windowsManagedPolicyOwnerSID
	originalDirTrust := windowsManagedPolicyDirTrustCheck
	originalFileTrust := windowsManagedPolicyFileTrustCheck
	originalWriter := windowsManagedPolicyWriter
	originalProfile := windowsEnterpriseProfilePathResolver
	originalTransaction := windowsClaudeManagedPolicyTransaction
	originalVersionProbe := windowsClaudeManagedRuntimeVersionProbe
	originalGuardianRepair := windowsEnterpriseGuardianDACLRepair
	originalConnectorPolicyRoot := connector.ClaudeCodeManagedSettingsRootOverride
	windowsEnterpriseAdministratorCheck = func() error { return nil }
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	windowsEnterpriseTargetImpersonation = func(_ *windows.SID, _ string, fn func() error) error {
		return runWindowsTestThreadImpersonatedAsSelf(fn)
	}
	windowsClaudeHigherPolicyCheck = func() error { return nil }
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return targetSID, nil }
	windowsManagedPolicyDirTrustCheck = func(path string) error {
		return validateWindowsTestManagedPolicyProtection(path, targetSID, true)
	}
	windowsManagedPolicyFileTrustCheck = func(path string) error {
		return validateWindowsTestManagedPolicyProtection(path, targetSID, false)
	}
	windowsManagedPolicyWriter = writeWindowsManagedFile
	windowsClaudeManagedPolicyTransaction = func(fn func() error) error { return fn() }
	policyPath := filepath.Join(dropin, windowsClaudeManagedPolicyFile)
	windowsClaudeManagedPolicyPathResolver = func() (string, error) { return policyPath, nil }
	windowsEnterpriseProfilePathResolver = func() (string, error) { return home, nil }
	connector.ClaudeCodeManagedSettingsRootOverride = policyRoot

	for _, path := range []string{filepath.Dir(policyRoot), policyRoot, dropin} {
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

	trustedDir := filepath.Join(scope, "trusted")
	hookExe := filepath.Join(trustedDir, "defenseclaw-hook.exe")
	gatewayExe := filepath.Join(trustedDir, "defenseclaw-gateway.exe")
	if err := os.MkdirAll(trustedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{
		hookExe:    []byte("test native hook"),
		gatewayExe: []byte("test native gateway"),
	} {
		if err := os.WriteFile(path, body, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := setWindowsUserPathProtection(trustedDir, targetSID, true); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{hookExe, gatewayExe} {
		if err := setWindowsUserPathProtection(path, targetSID, false); err != nil {
			t.Fatal(err)
		}
	}
	windowsEnterpriseHookExecutable = func() (string, error) { return hookExe, nil }
	windowsEnterpriseHookTrustCheck = func(path string) error {
		return validateWindowsUserPathElement(path, targetSID, false, false, true)
	}
	windowsClaudeManagedRuntimeVersionProbe = func(path, expectedVersion string) error {
		if !sameWindowsEnterprisePath(path, gatewayExe) {
			return fmt.Errorf("managed runtime probe path = %s, want %s", path, gatewayExe)
		}
		if strings.TrimSpace(expectedVersion) == "" {
			return errors.New("managed runtime probe expected version is empty")
		}
		return nil
	}
	windowsEnterpriseGuardianDACLRepair = repairWindowsTargetOwnedPathDACLNoFollow
	t.Cleanup(func() {
		windowsEnterpriseAdministratorCheck = originalAdmin
		windowsEnterpriseMutationIdentityCheck = originalMutationIdentity
		windowsEnterpriseTargetImpersonation = originalTargetImpersonation
		windowsEnterpriseHookExecutable = originalHook
		windowsEnterpriseHookTrustCheck = originalHookTrust
		windowsClaudeManagedPolicyPathResolver = originalPath
		windowsClaudeHigherPolicyCheck = originalHigher
		windowsManagedPolicyOwnerSID = originalOwner
		windowsManagedPolicyDirTrustCheck = originalDirTrust
		windowsManagedPolicyFileTrustCheck = originalFileTrust
		windowsManagedPolicyWriter = originalWriter
		windowsEnterpriseProfilePathResolver = originalProfile
		windowsClaudeManagedPolicyTransaction = originalTransaction
		windowsClaudeManagedRuntimeVersionProbe = originalVersionProbe
		windowsEnterpriseGuardianDACLRepair = originalGuardianRepair
		connector.ClaudeCodeManagedSettingsRootOverride = originalConnectorPolicyRoot
	})
	return windowsManagedInstallFixture{
		home:       home,
		policyPath: policyPath,
		hookExe:    hookExe,
		gatewayExe: gatewayExe,
		targetSID:  targetSID,
	}
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

func windowsManagedRuntimeVersion(t *testing.T, fixture windowsManagedInstallFixture) string {
	t.Helper()
	entry := connector.LoadHookContractLockEntry(filepath.Join(fixture.home, ".defenseclaw"), "claudecode")
	if strings.TrimSpace(entry.DefenseClawVersion) == "" {
		t.Fatal("managed hook contract lock has no DefenseClaw runtime version")
	}
	return entry.DefenseClawVersion
}

func TestInstallWindowsClaudeManagedPolicySurvivesManagedOnlyHooks(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{
		"allowManagedHooksOnly": true,
		"companyAnnouncements":  []interface{}{"managed by test"},
	})
	opts := windowsManagedInstallOptions(fixture)
	result, err := Install(context.Background(), opts)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(result.HookConfigPaths) != 1 || !strings.EqualFold(result.HookConfigPaths[0], fixture.policyPath) {
		t.Fatalf("managed policy paths = %v, want %s", result.HookConfigPaths, fixture.policyPath)
	}
	lock := connector.LoadHookContractLockEntry(filepath.Join(fixture.home, ".defenseclaw"), "claudecode")
	if len(lock.Locations.HookConfigPaths) != 1 || !strings.EqualFold(lock.Locations.HookConfigPaths[0], fixture.policyPath) {
		t.Fatalf("managed hook lock paths = %v, want %s", lock.Locations.HookConfigPaths, fixture.policyPath)
	}
	if _, err := os.Lstat(filepath.Join(fixture.home, ".claude", "settings.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("enterprise install wrote user Claude settings: %v", err)
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
	if owner, err := windowsPathOwner(tokenPath); err != nil || !owner.Equals(fixture.targetSID) {
		t.Fatalf("runtime token owner = %v, err=%v, want %s", owner, err, fixture.targetSID)
	}
	if err := validateWindowsUserPathElement(tokenPath, fixture.targetSID, false, false, true); err != nil {
		t.Fatalf("runtime token DACL: %v", err)
	}
	if err := validateWindowsTestManagedPolicyProtection(
		fixture.policyPath,
		fixture.targetSID,
		false,
	); err != nil {
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

func TestInstallWindowsClaudeAutoHealsDeletedManagedPolicyFromExactState(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(
		t,
		map[string]interface{}{"allowManagedHooksOnly": true},
	)
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(
		filepath.Dir(fixture.policyPath),
		windowsClaudeManagedStateFile,
	)
	expectedPolicy, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	expectedState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture.policyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("auto-heal deleted managed policy: %v", err)
	}
	recoveredPolicy, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(recoveredPolicy) != string(expectedPolicy) {
		t.Fatal("auto-heal did not republish the exact freshly rendered policy")
	}
	recoveredState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(recoveredState) != string(expectedState) {
		t.Fatal("auto-heal changed protected target enrollment or ownership metadata")
	}
	if err := verifyWindowsClaudeManagedPolicy(
		fixture.policyPath,
		expectedPolicy,
	); err != nil {
		t.Fatalf("verify auto-healed policy: %v", err)
	}
}

func TestInstallWindowsClaudeDeletedPolicyRejectsMismatchedState(t *testing.T) {
	tests := []struct {
		name                 string
		mutate               func(*windowsClaudeManagedPolicyState, windowsManagedInstallFixture)
		noncanonicalEncoding bool
	}{
		{
			name: "policy hash",
			mutate: func(state *windowsClaudeManagedPolicyState, _ windowsManagedInstallFixture) {
				state.PolicySHA256 = "sha256:" + strings.Repeat("0", 64)
			},
		},
		{
			name: "hook identity",
			mutate: func(state *windowsClaudeManagedPolicyState, fixture windowsManagedInstallFixture) {
				state.HookExecutable = fixture.gatewayExe
			},
		},
		{
			name: "gateway address",
			mutate: func(state *windowsClaudeManagedPolicyState, _ windowsManagedInstallFixture) {
				state.GatewayAddr = "127.0.0.1:18971"
			},
		},
		{
			name: "gateway service",
			mutate: func(state *windowsClaudeManagedPolicyState, _ windowsManagedInstallFixture) {
				state.GatewayServiceName = "DefenseClawGateway-Other"
			},
		},
		{
			name: "target enrollment",
			mutate: func(state *windowsClaudeManagedPolicyState, _ windowsManagedInstallFixture) {
				state.TargetSIDs = []string{"S-1-5-21-111-222-333-1001"}
			},
		},
		{
			name: "schema",
			mutate: func(state *windowsClaudeManagedPolicyState, _ windowsManagedInstallFixture) {
				state.SchemaVersion = 1
			},
		},
		{
			name:                 "noncanonical encoding",
			mutate:               func(_ *windowsClaudeManagedPolicyState, _ windowsManagedInstallFixture) {},
			noncanonicalEncoding: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newWindowsManagedInstallFixture(
				t,
				map[string]interface{}{"allowManagedHooksOnly": true},
			)
			opts := windowsManagedInstallOptions(fixture)
			if _, err := Install(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			statePath := filepath.Join(
				filepath.Dir(fixture.policyPath),
				windowsClaudeManagedStateFile,
			)
			stateBody, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatal(err)
			}
			var state windowsClaudeManagedPolicyState
			if err := decodeWindowsClaudeManagedPolicyState(
				stateBody,
				&state,
			); err != nil {
				t.Fatal(err)
			}
			test.mutate(&state, fixture)
			if test.noncanonicalEncoding {
				stateBody, err = json.Marshal(state)
			} else {
				stateBody, err = json.MarshalIndent(state, "", "  ")
			}
			if err != nil {
				t.Fatal(err)
			}
			stateBody = append(stateBody, '\n')
			if err := windowsManagedPolicyWriter(
				statePath,
				stateBody,
				true,
			); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(fixture.policyPath); err != nil {
				t.Fatal(err)
			}
			if _, err := Install(context.Background(), opts); err == nil ||
				!strings.Contains(err.Error(), "missing-policy recovery") {
				t.Fatalf("Install error = %v, want missing-policy recovery refusal", err)
			}
			if _, err := os.Lstat(fixture.policyPath); !errors.Is(
				err,
				os.ErrNotExist,
			) {
				t.Fatalf("refused recovery published policy: %v", err)
			}
			persistedState, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatal(err)
			}
			if string(persistedState) != string(stateBody) {
				t.Fatal("refused recovery changed the mismatched sidecar")
			}
		})
	}
}

func TestWindowsClaudeManagedLifecycleOwnershipSurvivesRuntimeDamage(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(fixture.home, ".defenseclaw")
	owned, err := OwnsWindowsClaudeManagedLifecycle(dataDir)
	if err != nil || !owned {
		t.Fatalf("managed lifecycle ownership = %v, err=%v, want true", owned, err)
	}
	managedRuntimeVersion := windowsManagedRuntimeVersion(t, fixture)
	if err := VerifyWindowsClaudeManagedLifecycleRuntime(dataDir, managedRuntimeVersion); err != nil {
		t.Fatalf("healthy managed lifecycle runtime: %v", err)
	}
	if err := VerifyWindowsClaudeManagedLifecycleRuntime(dataDir, "stale-managed-runtime-version"); err == nil ||
		!strings.Contains(err.Error(), "does not match required Setup version") {
		t.Fatalf("stale managed lifecycle runtime verification = %v", err)
	}
	owned, err = OwnsWindowsClaudeManagedLifecycle(dataDir)
	if err != nil || !owned {
		t.Fatalf("stale runtime version changed lifecycle ownership = %v, err=%v", owned, err)
	}

	// Runtime damage is for the administrator guardian to reconcile. It must
	// never downgrade servicing back to the ordinary per-user writer.
	tokenPath := filepath.Join(dataDir, "hooks", ".hook-claudecode.token")
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	if _, registered, err := ResolveWindowsClaudeManagedHookRuntime(fixture.hookExe); err == nil || registered {
		t.Fatalf("damaged managed runtime resolved: registered=%v err=%v", registered, err)
	}
	if err := VerifyWindowsClaudeManagedLifecycleRuntime(dataDir, managedRuntimeVersion); err == nil ||
		!strings.Contains(err.Error(), ".hook-claudecode.token") {
		t.Fatalf("damaged managed lifecycle runtime verification = %v", err)
	}
	owned, err = OwnsWindowsClaudeManagedLifecycle(dataDir)
	if err != nil || !owned {
		t.Fatalf("damaged runtime changed lifecycle ownership = %v, err=%v", owned, err)
	}

	if err := RemoveManagedPolicy(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	owned, err = OwnsWindowsClaudeManagedLifecycle(dataDir)
	if err != nil || owned {
		t.Fatalf("removed managed policy ownership = %v, err=%v, want false", owned, err)
	}
}

func TestWindowsClaudeManagedRuntimeVerificationBindsHookAndContractIdentity(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(fixture.home, ".defenseclaw")
	managedRuntimeVersion := windowsManagedRuntimeVersion(t, fixture)

	originalHookTrust := windowsEnterpriseHookTrustCheck
	windowsEnterpriseHookTrustCheck = func(path string) error {
		if strings.EqualFold(path, fixture.hookExe) {
			return errors.New("enterprise hook image identity is untrusted")
		}
		return originalHookTrust(path)
	}
	if err := VerifyWindowsClaudeManagedLifecycleRuntime(dataDir, managedRuntimeVersion); err == nil ||
		!strings.Contains(err.Error(), "hook executable trust check") {
		t.Fatalf("untrusted enterprise hook runtime verification = %v", err)
	}
	windowsEnterpriseHookTrustCheck = originalHookTrust

	lockPath := filepath.Join(dataDir, "hook_contract_lock.json")
	lockBody, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	var lock map[string]interface{}
	if err := json.Unmarshal(lockBody, &lock); err != nil {
		t.Fatal(err)
	}
	connectors := lock["connectors"].(map[string]interface{})
	claude := connectors["claudecode"].(map[string]interface{})
	locations := claude["locations"].(map[string]interface{})
	locations["hook_config_paths"] = []interface{}{filepath.Join(fixture.home, ".claude", "settings.json")}
	damagedLock, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, append(damagedLock, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWindowsClaudeManagedLifecycleRuntime(dataDir, managedRuntimeVersion); err == nil ||
		!strings.Contains(err.Error(), "does not identify the active administrator policy") {
		t.Fatalf("foreign managed contract path verification = %v", err)
	}
}

func TestWindowsClaudeManagedRuntimeVerificationRejectsMissingGateway(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(fixture.home, ".defenseclaw")
	managedRuntimeVersion := windowsManagedRuntimeVersion(t, fixture)
	if err := os.Remove(fixture.gatewayExe); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWindowsClaudeManagedLifecycleRuntime(dataDir, managedRuntimeVersion); err == nil ||
		!strings.Contains(err.Error(), "gateway executable trust check failed") {
		t.Fatalf("missing managed gateway runtime verification = %v", err)
	}
	owned, err := OwnsWindowsClaudeManagedLifecycle(dataDir)
	if err != nil || !owned {
		t.Fatalf("missing gateway changed lifecycle ownership = %v, err=%v", owned, err)
	}
}

func TestInstallWindowsClaudeRejectsWrongTargetSIDBeforeMutation(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	opts.OwnerSID = "S-1-5-21-111-222-333-444"
	_, err := Install(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "is not target or a trusted profile-management principal") {
		t.Fatalf("Install error = %v, want wrong SID refusal", err)
	}
	if _, err := os.Lstat(fixture.policyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("policy created after wrong-SID refusal: %v", err)
	}
}

func TestInstallWindowsClaudeRequiresLocalSystemBeforeProfileMutation(t *testing.T) {
	home := t.TempDir()
	sentinel := errors.New("test elevated administrator is not LocalSystem")
	originalAdmin := windowsEnterpriseAdministratorCheck
	originalIdentity := windowsEnterpriseMutationIdentityCheck
	originalImpersonation := windowsEnterpriseTargetImpersonation
	windowsEnterpriseAdministratorCheck = func() error { return nil }
	windowsEnterpriseMutationIdentityCheck = func() error { return sentinel }
	impersonationCalled := false
	windowsEnterpriseTargetImpersonation = func(*windows.SID, string, func() error) error {
		impersonationCalled = true
		return nil
	}
	t.Cleanup(func() {
		windowsEnterpriseAdministratorCheck = originalAdmin
		windowsEnterpriseMutationIdentityCheck = originalIdentity
		windowsEnterpriseTargetImpersonation = originalImpersonation
	})

	_, err := Install(context.Background(), InstallOptions{
		ConnectorName: "claudecode",
		UserHome:      home,
		OwnerSID:      currentWindowsTestSID(t).String(),
		AgentVersion:  "2.1.187 (Claude Code)",
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Install error = %v, want LocalSystem guardian refusal", err)
	}
	if impersonationCalled {
		t.Fatal("target impersonation ran after LocalSystem identity refusal")
	}
	if _, statErr := os.Lstat(filepath.Join(home, ".defenseclaw")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("elevated administrator path created per-user runtime: %v", statErr)
	}
}

func TestInstallWindowsGenericRequiresLocalSystemBeforeProfileMutation(t *testing.T) {
	home := t.TempDir()
	sentinel := errors.New("test elevated administrator is not LocalSystem")
	originalAdmin := windowsEnterpriseAdministratorCheck
	originalIdentity := windowsEnterpriseMutationIdentityCheck
	originalImpersonation := windowsEnterpriseTargetImpersonation
	windowsEnterpriseAdministratorCheck = func() error { return nil }
	windowsEnterpriseMutationIdentityCheck = func() error { return sentinel }
	impersonationCalled := false
	windowsEnterpriseTargetImpersonation = func(*windows.SID, string, func() error) error {
		impersonationCalled = true
		return nil
	}
	t.Cleanup(func() {
		windowsEnterpriseAdministratorCheck = originalAdmin
		windowsEnterpriseMutationIdentityCheck = originalIdentity
		windowsEnterpriseTargetImpersonation = originalImpersonation
	})

	_, err := installWindowsGenericManagedResult(context.Background(), InstallOptions{
		ConnectorName: windowsGenericTestConnectorName,
		UserHome:      home,
		OwnerSID:      currentWindowsTestSID(t).String(),
		AgentVersion:  "codex-cli 0.142.0",
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Install error = %v, want LocalSystem guardian refusal", err)
	}
	if impersonationCalled {
		t.Fatal("target impersonation ran after LocalSystem identity refusal")
	}
	if _, statErr := os.Lstat(filepath.Join(home, ".defenseclaw")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("elevated administrator path created generic per-user runtime: %v", statErr)
	}
}

func TestWindowsGenericCodexInstallVerifyAndUninstallLifecycle(t *testing.T) {
	fixture := newWindowsGenericCodexFixture(t)
	result, err := installWindowsGenericManagedResult(context.Background(), fixture.opts)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if result.Connector != windowsGenericTestConnectorName {
		t.Fatalf("connector = %q, want %s", result.Connector, windowsGenericTestConnectorName)
	}
	config, err := os.ReadFile(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(string(config)), "defenseclaw") {
		t.Fatalf("Codex config does not contain managed hook wiring:\n%s", config)
	}

	before := snapshotWindowsTestTree(t, filepath.Dir(fixture.home))
	previousImpersonation := windowsEnterpriseTargetImpersonation
	windowsEnterpriseTargetImpersonation = func(*windows.SID, string, func() error) error {
		return errors.New("read-only generic verification attempted target impersonation")
	}
	if _, err := verifyWindowsGenericManagedResult(context.Background(), fixture.opts); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	after := snapshotWindowsTestTree(t, filepath.Dir(fixture.home))
	if before != after {
		t.Fatal("generic operator Verify changed bytes, metadata, or ACLs")
	}
	windowsEnterpriseTargetImpersonation = previousImpersonation

	removeOpts := InstallOptions{
		ConnectorName: fixture.opts.ConnectorName,
		UserHome:      fixture.home,
		OwnerSID:      fixture.targetSID.String(),
		Registry:      fixture.opts.Registry,
	}
	if err := removeWindowsGenericManagedRuntime(context.Background(), removeOpts); err != nil {
		t.Fatalf("RemoveManagedPolicy: %v", err)
	}
	config, err = os.ReadFile(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(config)), "defenseclaw") {
		t.Fatalf("Codex managed wiring survived uninstall:\n%s", config)
	}
	if lock := connector.LoadHookContractLockEntry(filepath.Join(fixture.home, ".defenseclaw"), "codex"); lock.Connector != "" {
		t.Fatalf("Codex hook contract lock survived uninstall: %+v", lock)
	}
}

func TestInstallWindowsGenericRejectsEmptyAgentVersionBeforeCachedFallback(t *testing.T) {
	fixture := newWindowsGenericCodexFixture(t)
	dataDir := filepath.Join(fixture.home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "agent_discovery.json"), []byte(`{
  "version": 1,
  "agents": {
    "codex": {
      "version": "codex-cli 0.142.0",
      "binary_path": "C:\\Users\\alice\\codex.exe"
    }
  }
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := fixture.opts
	opts.AgentVersion = " \t "
	_, err := Install(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "requires explicit agent_version") {
		t.Fatalf("Install error = %v, want explicit version refusal before user cache fallback", err)
	}
}

func TestWindowsEnterpriseRejectsUncertifiedConnectorBeforeImpersonation(t *testing.T) {
	originalAdmin := windowsEnterpriseAdministratorCheck
	originalIdentity := windowsEnterpriseMutationIdentityCheck
	originalImpersonation := windowsEnterpriseTargetImpersonation
	originalCertification := windowsEnterpriseConnectorCertification
	windowsEnterpriseAdministratorCheck = func() error { return nil }
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	impersonated := false
	windowsEnterpriseTargetImpersonation = func(*windows.SID, string, func() error) error {
		impersonated = true
		return errors.New("uncertified connector crossed impersonation boundary")
	}
	windowsEnterpriseConnectorCertification = certifyWindowsEnterpriseConnector
	t.Cleanup(func() {
		windowsEnterpriseAdministratorCheck = originalAdmin
		windowsEnterpriseMutationIdentityCheck = originalIdentity
		windowsEnterpriseTargetImpersonation = originalImpersonation
		windowsEnterpriseConnectorCertification = originalCertification
	})

	setupCalls := 0
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(&windowsGenericCodexTestConnector{name: "codex", setupCalls: &setupCalls})
	_, err := Install(context.Background(), InstallOptions{
		ConnectorName: "codex",
		AgentVersion:  "codex-cli 0.142.0",
		Registry:      registry,
	})
	if err == nil || !strings.Contains(err.Error(), "not the certified built-in Windows implementation") {
		t.Fatalf("Install error = %v, want uncertified connector refusal", err)
	}
	if impersonated {
		t.Fatal("uncertified connector reached the target-token impersonation callback")
	}
	if setupCalls != 0 {
		t.Fatalf("uncertified connector Setup called %d time(s)", setupCalls)
	}
}

func TestWindowsEnterpriseConnectorCertificationAllowsOnlyBuiltins(t *testing.T) {
	tests := []struct {
		name string
		conn connector.Connector
	}{
		{name: "codex", conn: connector.NewCodexConnector()},
		{name: "claudecode", conn: connector.NewClaudeCodeConnector()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := certifyWindowsEnterpriseConnector(tc.name, tc.conn); err != nil {
				t.Fatalf("certifyWindowsEnterpriseConnector: %v", err)
			}
		})
	}
}

func TestWindowsEnterpriseImpersonationSetupRejectsProcessLaunchingOptions(t *testing.T) {
	base := connector.SetupOpts{ManagedEnterprise: true}
	if err := validateWindowsEnterpriseImpersonationSetup(base); err != nil {
		t.Fatalf("safe setup rejected: %v", err)
	}
	tests := []struct {
		name  string
		setup connector.SetupOpts
	}{
		{
			name:  "agent executable",
			setup: connector.SetupOpts{ManagedEnterprise: true, AgentExecutable: `C:\Users\alice\codex.exe`},
		},
		{
			name:  "CodeGuard plugin install",
			setup: connector.SetupOpts{ManagedEnterprise: true, InstallCodeGuard: true},
		},
		{
			name:  "interactive callback",
			setup: connector.SetupOpts{ManagedEnterprise: true, Interactive: true},
		},
		{
			name:  "managed mode omitted",
			setup: connector.SetupOpts{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateWindowsEnterpriseImpersonationSetup(tc.setup); err == nil {
				t.Fatalf("unsafe setup accepted: %+v", tc.setup)
			}
		})
	}
}

func TestInstallWindowsGenericRejectsSparseOversizedConfigBeforeConnectorSetup(t *testing.T) {
	fixture := newWindowsGenericCodexFixture(t)
	file, err := os.OpenFile(fixture.config, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(windowsEnterpriseUserFileMaxBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(fixture.config, fixture.targetSID, false); err != nil {
		t.Fatal(err)
	}

	setupCalls := 0
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(&windowsGenericCodexTestConnector{
		configPath: fixture.config,
		setupCalls: &setupCalls,
	})
	opts := fixture.opts
	opts.Registry = registry
	_, err = installWindowsGenericManagedResult(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "refusing oversized hook config") {
		t.Fatalf("Install error = %v, want bounded preflight refusal", err)
	}
	if setupCalls != 0 {
		t.Fatalf("connector Setup called %d time(s) after oversized sparse config", setupCalls)
	}
}

func TestInstallWindowsGenericRepairsAuthorizedSparseOversizedConfig(t *testing.T) {
	stubWindowsAuthorizedRepairIdentityChecks(t)
	fixture := newWindowsGenericCodexFixture(t)
	file, err := os.OpenFile(fixture.config, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(windowsEnterpriseUserFileMaxBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(
		fixture.config,
		fixture.targetSID,
		false,
	); err != nil {
		t.Fatal(err)
	}

	setupCalls := 0
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(&windowsGenericCodexTestConnector{
		configPath: fixture.config,
		setupCalls: &setupCalls,
	})
	opts := fixture.opts
	opts.Registry = registry
	opts.AllowMissingHookConfigRepair = true
	if _, err := installWindowsGenericManagedResult(
		context.Background(),
		opts,
	); err != nil {
		t.Fatalf("authorized sparse-file repair: %v", err)
	}
	if setupCalls != 1 {
		t.Fatalf("connector Setup called %d time(s), want 1", setupCalls)
	}
	info, err := os.Stat(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > windowsEnterpriseUserFileMaxBytes {
		t.Fatalf("repaired config remains oversized: %d bytes", info.Size())
	}
	if _, err := os.Lstat(
		windowsManagedObstructionQuarantinePath(fixture.config),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversized obstruction quarantine survived repair: %v", err)
	}
}

func TestInstallWindowsClaudePreservesProfileRootDACL(t *testing.T) {
	fixture := newWindowsManagedInstallFixtureWithHomeSetup(
		t,
		map[string]interface{}{"allowManagedHooksOnly": true},
		func(home string, targetSID *windows.SID) {
			setWindowsTestUntrustedWriteDACL(t, home, targetSID)
		},
	)
	before := windowsTestSecurityDescriptorString(t, fixture.home)
	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatalf("Install with enterprise-managed profile-root DACL: %v", err)
	}
	after := windowsTestSecurityDescriptorString(t, fixture.home)
	if after != before {
		t.Fatalf("enterprise install rewrote profile root DACL:\nbefore=%s\nafter=%s", before, after)
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

func TestInstallWindowsClaudeRepairsAuthorizedTargetOwnedReparseDataDir(t *testing.T) {
	stubWindowsAuthorizedRepairIdentityChecks(t)
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(fixture.home, ".defenseclaw")
	originalDataDir := dataDir + ".test-original"
	if err := os.Rename(dataDir, originalDataDir); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(fixture.home), "outside-reparse-target")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinelPath := filepath.Join(outside, "sentinel.txt")
	const sentinel = "outside target must remain unchanged\n"
	if err := os.WriteFile(sentinelPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, dataDir); err != nil {
		output, junctionErr := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", dataDir, outside).CombinedOutput()
		if junctionErr != nil {
			t.Fatalf("create reparse fixture after symlink error %v: %v: %s", err, junctionErr, output)
		}
	}

	opts.AllowMissingHookConfigRepair = true
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("authorized repair Install: %v", err)
	}
	info, err := os.Lstat(dataDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("repaired data dir = %#v err=%v", info, err)
	}
	if got, err := os.ReadFile(sentinelPath); err != nil || string(got) != sentinel {
		t.Fatalf("outside reparse target changed: %q err=%v", got, err)
	}
	if _, err := os.Lstat(windowsManagedObstructionQuarantinePath(dataDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bounded reparse quarantine survived successful repair: %v", err)
	}
}

func TestInstallWindowsClaudeRepairsAuthorizedRegularFileAtDataDir(t *testing.T) {
	stubWindowsAuthorizedRepairIdentityChecks(t)
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(fixture.home, ".defenseclaw")
	if err := os.Rename(dataDir, dataDir+".test-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataDir, []byte("target-owned obstruction"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(dataDir, fixture.targetSID, false); err != nil {
		t.Fatal(err)
	}

	opts.AllowMissingHookConfigRepair = true
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("authorized repair Install: %v", err)
	}
	info, err := os.Lstat(dataDir)
	if err != nil || !info.IsDir() {
		t.Fatalf("repaired data dir = %#v err=%v", info, err)
	}
	if _, err := os.Lstat(windowsManagedObstructionQuarantinePath(dataDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bounded file quarantine survived successful repair: %v", err)
	}
}

func TestWindowsAuthorizedRepairRecyclesNonEmptyQuarantineWithoutFollowingJunction(t *testing.T) {
	stubWindowsAuthorizedRepairIdentityChecks(t)
	fixture := newWindowsGenericCodexFixture(t)
	outside := filepath.Join(filepath.Dir(fixture.home), "outside-quarantine-target")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinelPath := filepath.Join(outside, "sentinel.txt")
	const sentinel = "outside quarantine target must remain unchanged\n"
	if err := os.WriteFile(sentinelPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}

	makeObstruction := func(cycle string, withJunction bool) {
		t.Helper()
		if err := os.Mkdir(fixture.config, 0o700); err != nil {
			t.Fatalf("%s create obstruction: %v", cycle, err)
		}
		nested := filepath.Join(fixture.config, "nested")
		if err := os.Mkdir(nested, 0o700); err != nil {
			t.Fatalf("%s create nested obstruction: %v", cycle, err)
		}
		if err := os.WriteFile(filepath.Join(nested, "payload.txt"), []byte(cycle), 0o600); err != nil {
			t.Fatalf("%s create obstruction payload: %v", cycle, err)
		}
		if withJunction {
			link := filepath.Join(fixture.config, "outside-link")
			if err := os.Symlink(outside, link); err != nil {
				output, junctionErr := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, outside).CombinedOutput()
				if junctionErr != nil {
					t.Fatalf(
						"%s create reparse fixture after symlink error %v: %v: %s",
						cycle,
						err,
						junctionErr,
						output,
					)
				}
			}
		}
	}

	if err := os.Remove(fixture.config); err != nil {
		t.Fatal(err)
	}
	makeObstruction("first", true)
	if err := prepareWindowsGenericPath(
		fixture.home,
		fixture.config,
		fixture.targetSID,
		false,
		false,
		true,
		"hook config",
	); err != nil {
		t.Fatalf("first authorized repair: %v", err)
	}
	quarantine := windowsManagedObstructionQuarantinePath(fixture.config)
	if _, err := os.Lstat(quarantine); err != nil {
		t.Fatalf("first non-empty quarantine missing: %v", err)
	}

	if err := os.WriteFile(fixture.config, []byte("{\"model\":\"gpt-5\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(fixture.config, fixture.targetSID, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture.config); err != nil {
		t.Fatal(err)
	}
	makeObstruction("second", false)
	if err := prepareWindowsGenericPath(
		fixture.home,
		fixture.config,
		fixture.targetSID,
		false,
		false,
		true,
		"hook config",
	); err != nil {
		t.Fatalf("second authorized repair with occupied quarantine: %v", err)
	}

	if err := os.WriteFile(fixture.config, []byte("{\"model\":\"gpt-5\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanupWindowsManagedObstructionQuarantine(fixture.config, fixture.targetSID)
	if _, err := os.Lstat(quarantine); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second bounded quarantine survived cleanup: %v", err)
	}
	if got, err := os.ReadFile(sentinelPath); err != nil || string(got) != sentinel {
		t.Fatalf("outside junction target changed: %q err=%v", got, err)
	}
}

func TestWindowsAuthorizedRepairReplacesManagedLockObstructions(t *testing.T) {
	stubWindowsAuthorizedRepairIdentityChecks(t)
	for _, tc := range []struct {
		name       string
		lockPath   func(windowsGenericCodexFixture) string
		useReparse bool
	}{
		{
			name:     "codex config lock directory",
			lockPath: func(f windowsGenericCodexFixture) string { return f.config + ".lock" },
		},
		{
			name: "hook sidecar lock directory",
			lockPath: func(f windowsGenericCodexFixture) string {
				return filepath.Join(f.home, ".defenseclaw", "hooks", ".hookcfg.lock")
			},
		},
		{
			name: "contract lock reparse",
			lockPath: func(f windowsGenericCodexFixture) string {
				return filepath.Join(f.home, ".defenseclaw", "hook_contract_lock.json.lock")
			},
			useReparse: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newWindowsGenericCodexFixture(t)
			if _, err := installWindowsGenericManagedResult(context.Background(), fixture.opts); err != nil {
				t.Fatalf("initial Install: %v", err)
			}
			lockPath := tc.lockPath(fixture)
			if err := os.Remove(lockPath); err != nil {
				t.Fatalf("remove canonical lock fixture: %v", err)
			}

			var sentinelPath string
			if tc.useReparse {
				outside := filepath.Join(filepath.Dir(fixture.home), "outside-lock-target")
				if err := os.MkdirAll(outside, 0o700); err != nil {
					t.Fatal(err)
				}
				sentinelPath = filepath.Join(outside, "sentinel.txt")
				if err := os.WriteFile(sentinelPath, []byte("outside lock target\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, lockPath); err != nil {
					output, junctionErr := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", lockPath, outside).CombinedOutput()
					if junctionErr != nil {
						t.Fatalf("create lock reparse after symlink error %v: %v: %s", err, junctionErr, output)
					}
				}
			} else {
				if err := os.Mkdir(lockPath, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(lockPath, "pin.txt"), []byte("pin"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			opts := fixture.opts
			opts.AllowMissingHookConfigRepair = true
			if _, err := installWindowsGenericManagedResult(context.Background(), opts); err != nil {
				t.Fatalf("authorized lock obstruction repair: %v", err)
			}
			info, err := os.Lstat(lockPath)
			if err != nil || !info.Mode().IsRegular() {
				t.Fatalf("repaired lock = %#v err=%v, want regular file", info, err)
			}
			if _, err := os.Lstat(windowsManagedObstructionQuarantinePath(lockPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("lock obstruction quarantine survived repair: %v", err)
			}
			if sentinelPath != "" {
				if got, err := os.ReadFile(sentinelPath); err != nil || string(got) != "outside lock target\n" {
					t.Fatalf("outside lock reparse target changed: %q err=%v", got, err)
				}
			}
		})
	}
}

func TestVerifyWindowsClaudeIsReadOnlyAndDoesNotImpersonate(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	before := snapshotWindowsTestTree(t, filepath.Dir(fixture.home))
	previousImpersonation := windowsEnterpriseTargetImpersonation
	windowsEnterpriseTargetImpersonation = func(*windows.SID, string, func() error) error {
		return errors.New("read-only verification attempted target impersonation")
	}
	t.Cleanup(func() { windowsEnterpriseTargetImpersonation = previousImpersonation })

	if _, err := Verify(context.Background(), opts); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	after := snapshotWindowsTestTree(t, filepath.Dir(fixture.home))
	if before != after {
		t.Fatal("operator Verify changed bytes, metadata, or ACLs")
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
	for _, path := range []string{fixture.policyPath, filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("managed policy artifact survived rollback at %s: %v", path, err)
		}
	}
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

func TestEnsureWindowsManagedPolicyDirectoryRejectsWritableAncestorWithoutArtifacts(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, nil)
	policyDir := filepath.Dir(fixture.policyPath)
	policyRoot := filepath.Dir(policyDir)
	policyParent := filepath.Dir(policyRoot)
	if err := os.Remove(policyDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(policyRoot); err != nil {
		t.Fatal(err)
	}
	setWindowsTestUntrustedWriteDACL(t, policyParent, fixture.targetSID)

	err := ensureWindowsManagedPolicyDirectory(policyDir)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "untrusted") {
		t.Fatalf("ensureWindowsManagedPolicyDirectory error = %v, want writable-ancestor refusal", err)
	}
	for _, path := range []string{policyRoot, policyDir} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("managed policy artifact created below untrusted ancestor %s: %v", path, statErr)
		}
	}
}

func TestWindowsClaudeManagedPolicyTransactionRejectsHostilePrecreatedLock(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, nil)
	lockPath := filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedLockFile)
	if err := os.WriteFile(lockPath, []byte("hostile"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsManagedPolicyProtection(lockPath, false, false); err != nil {
		t.Fatal(err)
	}
	setWindowsTestUntrustedWriteDACL(t, lockPath, fixture.targetSID)
	called := false
	err := withWindowsClaudeManagedPolicyTransaction(func() error {
		called = true
		return nil
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "lock is untrusted") {
		t.Fatalf("transaction error = %v, want hostile lock refusal", err)
	}
	if called {
		t.Fatal("transaction callback ran with hostile precreated lock")
	}
}

func TestWindowsClaudeManagedPolicyTransactionHeldLockTimesOut(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, nil)
	lockPath := filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedLockFile)
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsManagedPolicyProtection(lockPath, false, false); err != nil {
		t.Fatal(err)
	}
	held, err := openWindowsClaudeManagedPolicyLockFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(held)
	previousTimeout := windowsClaudeManagedLockTimeout
	previousRetry := windowsClaudeManagedLockRetry
	windowsClaudeManagedLockTimeout = 100 * time.Millisecond
	windowsClaudeManagedLockRetry = 10 * time.Millisecond
	t.Cleanup(func() {
		windowsClaudeManagedLockTimeout = previousTimeout
		windowsClaudeManagedLockRetry = previousRetry
	})
	called := false
	start := time.Now()
	err = withWindowsClaudeManagedPolicyTransaction(func() error {
		called = true
		return nil
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "timed out") {
		t.Fatalf("transaction error = %v, want bounded timeout", err)
	}
	if called {
		t.Fatal("transaction callback ran while the protected lock was held")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("bounded lock acquisition took %s", elapsed)
	}
}

func TestInspectWindowsClaudeFilePolicyCompatibilityRejectsOversizedPolicyBeforeRead(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, nil)
	basePath := filepath.Join(filepath.Dir(filepath.Dir(fixture.policyPath)), "managed-settings.json")
	if err := os.WriteFile(basePath, make([]byte, windowsClaudeManagedPolicyLimit+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsManagedPolicyProtection(basePath, false, true); err != nil {
		t.Fatal(err)
	}
	err := inspectWindowsClaudeFilePolicyCompatibility(fixture.policyPath)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "too large") {
		t.Fatalf("compatibility error = %v, want pre-read size refusal", err)
	}
}

func TestRejectWindowsClaudeRegistryPolicyWriteACEs(t *testing.T) {
	for _, test := range []struct {
		name    string
		sddl    string
		wantErr bool
	}{
		{
			name: "trusted administrators and system",
			sddl: "O:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)",
		},
		{
			name:    "builtin users can write",
			sddl:    "O:SYD:P(A;;KA;;;SY)(A;;KW;;;BU)",
			wantErr: true,
		},
		{
			name:    "everyone can replace key",
			sddl:    "O:SYD:P(A;;KA;;;SY)(A;;WD;;;WD)",
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(test.sddl)
			if err != nil {
				t.Fatal(err)
			}
			dacl, _, err := descriptor.DACL()
			if err != nil {
				t.Fatal(err)
			}
			err = rejectWindowsClaudeRegistryPolicyWriteACEs("test key", dacl)
			if (err != nil) != test.wantErr {
				t.Fatalf("rejectWindowsClaudeRegistryPolicyWriteACEs() error = %v, wantErr=%v", err, test.wantErr)
			}
		})
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
	if got, err := os.ReadFile(fixture.policyPath); err != nil || !strings.EqualFold(string(got), string(tampered)) {
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
	if _, registered, err := ResolveWindowsClaudeManagedHookRuntime(fixture.hookExe); err == nil ||
		registered ||
		!strings.Contains(err.Error(), "enterprise_managed_sid_unregistered") {
		t.Fatalf("removed target did not fail closed as unregistered: registered=%v err=%v", registered, err)
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

func stubWindowsAuthorizedRepairIdentityChecks(t *testing.T) {
	t.Helper()
	// These tests exercise bounded repair after authorization. Windows CI can
	// run as elevated RID-500, which production correctly rejects as a per-user
	// target; exact-token and LocalSystem refusals have dedicated tests.
	originalMutationIdentity := windowsEnterpriseMutationIdentityCheck
	originalTargetTokenCheck := windowsQuarantineTargetTokenCheck
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	windowsQuarantineTargetTokenCheck = func(*windows.SID) error { return nil }
	t.Cleanup(func() {
		windowsEnterpriseMutationIdentityCheck = originalMutationIdentity
		windowsQuarantineTargetTokenCheck = originalTargetTokenCheck
	})
}

// ImpersonateSelf names the process user, so both token accessors agree here.
// The connector package covers them disagreeing.
func runWindowsTestThreadImpersonatedAsSelf(fn func() error) (result error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		return fmt.Errorf("install same-user test impersonation token: %w", err)
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			result = errors.Join(result, fmt.Errorf("revert same-user test impersonation: %w", err))
		}
	}()
	return fn()
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

func windowsTestSecurityDescriptorString(t *testing.T, path string) string {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("read security descriptor for %s: %v", path, err)
	}
	return sd.String()
}

func snapshotWindowsTestTree(t *testing.T, root string) string {
	t.Helper()
	var snapshot strings.Builder
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		extended, err := winpath.Extended(path)
		if err != nil {
			return err
		}
		descriptor, err := windows.GetNamedSecurityInfo(
			extended,
			windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
		)
		if err != nil {
			return err
		}
		fmt.Fprintf(
			&snapshot,
			"%s|%s|%d|%d|%s\n",
			relative,
			info.Mode(),
			info.Size(),
			info.ModTime().UnixNano(),
			descriptor.String(),
		)
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fmt.Fprintf(&snapshot, "%x\n", data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.String()
}

func TestWindowsEnterpriseManagedAgentVersionMinimums(t *testing.T) {
	for _, tc := range []struct {
		name      string
		connector string
		version   string
		wantErr   bool
	}{
		{name: "codex below", connector: "codex", version: "0.130.0", wantErr: true},
		{name: "codex minimum", connector: "codex", version: "0.131.0"},
		{name: "codex malformed", connector: "codex", version: "not-a-version", wantErr: true},
		{name: "claude below", connector: "claudecode", version: "2.1.151", wantErr: true},
		{name: "claude minimum", connector: "claudecode", version: "2.1.152"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := requireWindowsEnterpriseManagedAgentVersion(tc.connector, tc.version)
			if (err != nil) != tc.wantErr {
				t.Fatalf(
					"requireWindowsEnterpriseManagedAgentVersion(%q, %q) error = %v, wantErr=%t",
					tc.connector,
					tc.version,
					err,
					tc.wantErr,
				)
			}
		})
	}
}
