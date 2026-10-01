// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// useWindowsEnvTestRegistry points the user hives and the machine
// environment key at a scratch tree under HKCU (a test cannot load a hive
// under HKEY_USERS) and removes the tree afterwards. It returns the paths
// standing in for HKEY_USERS and the machine key.
func useWindowsEnvTestRegistry(t *testing.T) (hives, machine string) {
	t.Helper()
	base := fmt.Sprintf(`Software\DefenseClawTest-foreign-env-%d-%d`, os.Getpid(), time.Now().UnixNano())
	hives, machine = base+`\hives`, base+`\machine`
	previousHives, previousMachine := enterpriseForeignHookUserHives, enterpriseForeignHookMachineEnvironment
	enterpriseForeignHookUserHives = windowsRegistryPath{root: registry.CURRENT_USER, path: hives}
	enterpriseForeignHookMachineEnvironment = windowsRegistryPath{root: registry.CURRENT_USER, path: machine}
	t.Cleanup(func() {
		enterpriseForeignHookUserHives, enterpriseForeignHookMachineEnvironment = previousHives, previousMachine
		if err := deleteWindowsTestRegistryTree(registry.CURRENT_USER, base); err != nil {
			t.Errorf("remove the scratch registry tree HKCU\\%s: %v", base, err)
		}
	})
	return hives, machine
}

func deleteWindowsTestRegistryTree(root registry.Key, path string) error {
	key, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	names, err := key.ReadSubKeyNames(0)
	key.Close()
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := deleteWindowsTestRegistryTree(root, path+`\`+name); err != nil {
			return err
		}
	}
	return registry.DeleteKey(root, path)
}

func writeWindowsTestEnvKey(t *testing.T, path string, values ...windowsEnvValue) {
	t.Helper()
	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	for _, value := range values {
		set := key.SetStringValue
		if value.expand {
			set = key.SetExpandStringValue
		}
		if err := set(value.name, value.value); err != nil {
			t.Fatal(err)
		}
	}
}

// The guardian runs as LocalSystem, without the user's environment. For a
// user whose persistent environment moves an agent's user config
// (CODEX_HOME, CLAUDE_CONFIG_DIR, COPILOT_HOME, XDG_CONFIG_HOME,
// OPENCODE_CONFIG_DIR), the per-user pass reads the variables from the
// user's loaded hive and cleans the moved folders too; for a user whose
// hive is not loaded it cleans the default locations and reports the skip.
func TestWindowsForeignCleanupCleansFoldersTheUserEnvironmentNames(t *testing.T) {
	if _, _, _, err := standaloneEnterprisePolicyLayout(); err != nil {
		t.Fatalf("the trusted machine roots must resolve on Windows: %v", err)
	}
	hives, _ := useWindowsEnvTestRegistry(t)
	previousCfg, previousRunAs := cfg, enterpriseForeignHookRunAsTarget
	previousOptions, previousProfiles := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles
	t.Cleanup(func() {
		cfg, enterpriseForeignHookRunAsTarget = previousCfg, previousRunAs
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles = previousOptions, previousProfiles
		enterpriseHookWindowsForeignCleanupState.last, enterpriseHookWindowsForeignCleanupState.fingerprint = time.Time{}, ""
	})
	enterpriseHookWindowsForeignCleanupState.last, enterpriseHookWindowsForeignCleanupState.fingerprint = time.Time{}, ""
	connectors := []string{"claudecode", "codex", "copilot", "opencode"}
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{
			Profile: managed.ProfileStandalone,
			MachinePolicy: config.EnterpriseMachinePolicyConfig{Connectors: map[string]config.EnterpriseConnectorPolicy{
				"claudecode": {ManagedHooksOnly: config.ManagedHooksOnlyPreserve},
				"codex":      {ManagedHooksOnly: config.ManagedHooksOnlyPreserve},
				"copilot":    {},
				"opencode":   {},
			}},
		},
	}
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{}, connectors, true, nil
	}
	const alice, bob = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	aliceHome, bobHome := filepath.Join(t.TempDir(), "alice"), filepath.Join(t.TempDir(), "bob")
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		return []enterprisehooks.TargetCredentials{
			{UserHome: aliceHome, UID: -1, GID: -1, SID: alice},
			{UserHome: bobHome, UID: -1, GID: -1, SID: bob},
		}, nil
	}
	ranAs := map[string]int{}
	enterpriseForeignHookRunAsTarget = func(target enterprisehooks.TargetCredentials, fn func() error) error {
		ranAs[target.SID]++
		return fn()
	}

	// Alice's hive is loaded; her variables move agents' user configs out of
	// the profile defaults, one through a reference to another variable.
	moved := filepath.Join(aliceHome, "moved")
	writeWindowsTestEnvKey(t, hives+`\`+alice+`\Volatile Environment`, windowsEnvValue{name: "USERPROFILE", value: aliceHome})
	writeWindowsTestEnvKey(t, hives+`\`+alice+`\Environment`,
		windowsEnvValue{name: "CLAUDE_CONFIG_DIR", value: `%USERPROFILE%\moved\claude`, expand: true},
		windowsEnvValue{name: "MOVED_ROOT", value: moved},
		windowsEnvValue{name: "Copilot_Home", value: `%moved_root%\copilot`, expand: true},
	)
	grouped := `{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./rewrite.cmd"}]}]}}`
	rewritten := map[string]string{
		filepath.Join(moved, "claude", "settings.json"):          grouped,
		filepath.Join(moved, "copilot", "hooks", "rewrite.json"): `{"hooks": {"preToolUse": [{"powershell": "./rewrite.cmd"}]}}`,
		// Bob has no loaded hive: his default location is still cleaned.
		filepath.Join(bobHome, ".copilot", "hooks", "rewrite.json"): `{"hooks": {"preToolUse": [{"powershell": "./rewrite.cmd"}]}}`,
	}
	for path, body := range rewritten {
		writeForeignEnvTestFile(t, path, body)
	}

	var log bytes.Buffer
	enterpriseHookStandalonePlatformFinish(context.Background(), &log, nil, time.Now())
	output := log.String()
	for path := range rewritten {
		data, err := os.ReadFile(path)
		if err != nil || strings.Contains(string(data), "rewrite.cmd") {
			t.Errorf("the foreign hook in %s must be removed (%v): %s\n%s", path, err, data, output)
		}
		if !strings.Contains(output, path) {
			t.Errorf("the removal from %s must be logged:\n%s", path, output)
		}
	}
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "cleanup for") && strings.Contains(line, aliceHome+":") {
			t.Errorf("alice's cleanup must succeed: %s", line)
		}
	}
	if !strings.Contains(output, bob) || !strings.Contains(output, errWindowsUserHiveNotLoaded.Error()) {
		t.Errorf("the skipped environment of a user whose hive is not loaded must be reported:\n%s", output)
	}
	if ranAs[alice] == 0 || ranAs[bob] == 0 {
		t.Errorf("every cleanup runs as its user: %v", ranAs)
	}
}

func writeForeignEnvTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The environment is layered as at sign-in: user variables override
// machine ones, the sign-in's profile variables override user ones, and
// REG_EXPAND_SZ values expand against what came before.
func TestWindowsUserPersistentEnvironmentLayersLikeSignIn(t *testing.T) {
	hives, machine := useWindowsEnvTestRegistry(t)
	const sid = "S-1-5-21-1-2-3-1001"
	home := filepath.Join(t.TempDir(), "alice")
	writeWindowsTestEnvKey(t, machine,
		windowsEnvValue{name: "CODEX_HOME", value: `C:\machine\codex`},
		windowsEnvValue{name: "XDG_CONFIG_HOME", value: `%SystemDrive%\machine\xdg`, expand: true},
	)
	writeWindowsTestEnvKey(t, hives+`\`+sid+`\Volatile Environment`,
		windowsEnvValue{name: "USERPROFILE", value: home},
		windowsEnvValue{name: "APPDATA", value: `\\files\profiles\alice\Roaming`},
	)
	writeWindowsTestEnvKey(t, hives+`\`+sid+`\Environment`,
		windowsEnvValue{name: "CODEX_HOME", value: `%USERPROFILE%\codex`, expand: true},
		windowsEnvValue{name: "APPDATA", value: `C:\elsewhere`},
		windowsEnvValue{name: "UNKNOWN_REF", value: `C:\%NO_SUCH_VARIABLE%\x`, expand: true},
		windowsEnvValue{name: "LITERAL", value: `%USERPROFILE%\not-expanded`},
	)
	env, err := windowsUserPersistentEnvironment(sid, home)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"CODEX_HOME":      filepath.Join(home, "codex"),
		"XDG_CONFIG_HOME": os.Getenv("SystemDrive") + `\machine\xdg`,
		"APPDATA":         `\\files\profiles\alice\Roaming`,
		"LOCALAPPDATA":    filepath.Join(home, "AppData", "Local"),
		"UNKNOWN_REF":     `C:\%NO_SUCH_VARIABLE%\x`,
		"LITERAL":         `%USERPROFILE%\not-expanded`,
	}
	for key, value := range want {
		if env[key] != value {
			t.Errorf("%s = %q, want %q", key, env[key], value)
		}
	}

	redirectsFor := func(connector string) ([]enterprisepolicy.EnvRedirect, error) {
		return enterpriseForeignHookUserEnvRedirects(
			enterprisehooks.TargetCredentials{UserHome: home, SID: sid},
			enterprisepolicy.GuardRequest{Connector: connector, GOOS: "windows", Home: home, AccountHome: home,
				Policy: enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true}},
		)
	}
	redirects, err := redirectsFor("codex")
	if err != nil || len(redirects) != 1 || redirects[0].Vars["CODEX_HOME"] != filepath.Join(home, "codex") {
		t.Fatalf("the moved Codex home must be a redirect: %+v %v", redirects, err)
	}
	// Cursor reads no location variable: nothing moves its user config.
	if redirects, err := redirectsFor("cursor"); err != nil || len(redirects) != 0 {
		t.Fatalf("an unmoved user config has no redirect: %+v %v", redirects, err)
	}

	const signedOut = "S-1-5-21-1-2-3-1002"
	if env, err := windowsUserPersistentEnvironment(signedOut, home); env != nil || !errors.Is(err, errWindowsUserHiveNotLoaded) {
		t.Fatalf("a user whose hive is not loaded is skipped: %v %v", env, err)
	}
	if _, err := windowsUserPersistentEnvironment(`S-1-5-21-1\..\x`, home); err == nil {
		t.Fatal("a malformed SID must be refused")
	}
}

func TestExpandWindowsEnvironmentMatchesExpandEnvironmentStrings(t *testing.T) {
	env := map[string]string{"A": "a", "USERPROFILE": `C:\Users\alice`}
	for value, want := range map[string]string{
		`%UserProfile%\x`: `C:\Users\alice\x`,
		`%A%%A%`:          "aa",
		`%%`:              "%%",
		`100%`:            "100%",
		`%B%%A%`:          "%B%a",
		`%B%A%`:           "%Ba",
		`x%A`:             "x%A",
	} {
		if got := expandWindowsEnvironment(value, env); got != want {
			t.Errorf("expand %q = %q, want %q", value, got, want)
		}
	}
}
