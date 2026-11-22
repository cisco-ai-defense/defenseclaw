// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

var errHookImageResolverStop = errors.New("test: stop after the layout pins were checked")

// rel-1-0-10 GAP-0856: hook-image retire's Codex requirements reconcile ran
// with the service pins alone, so the real layout resolver refused the
// administrator's and SYSTEM's run with "DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR
// must be an exact absolute protected path" (and then the gateway service
// name). Under the guardian's record pins the resolver accepts the
// guardian's own authorization directory for the root forms a host gives
// (%ProgramFiles% and %ProgramData% with or without a trailing backslash, in
// any case). The resolver runs for real; it is stopped right after, so no
// file is read or written.
func TestHookImageRetireCodexReconcileCarriesTheGuardianAuthDir(t *testing.T) {
	base := t.TempDir()
	for _, form := range []struct{ name, programFiles, programData string }{
		{"plain", filepath.Join(base, "Program Files"), filepath.Join(base, "ProgramData")},
		{"trailing backslash", filepath.Join(base, "Program Files") + `\`, filepath.Join(base, "ProgramData") + `\`},
		{"other case", strings.ToUpper(filepath.Join(base, "Program Files")), strings.ToLower(filepath.Join(base, "ProgramData"))},
	} {
		t.Run(form.name, func(t *testing.T) {
			layout, err := managed.StandaloneWindowsLayoutForRoots(form.programFiles, form.programData)
			if err != nil {
				t.Fatal(err)
			}
			// The caller's shell has none of the pins (an elevated
			// administrator over ssh, or a SYSTEM task).
			for _, name := range []string{managed.HookGuardianAuthorizationDirEnv, connector.WindowsGatewayServiceNameEnv,
				managed.DeploymentModeEnv, managed.ConfigPathEnv, "DEFENSECLAW_HOME"} {
				t.Setenv(name, "")
				_ = os.Unsetenv(name)
			}
			savedLayout, savedPreflight := windowsEnterpriseHotConfigLayout, enterpriseHooksPlatformPreflight
			savedResolver, savedExecutable := windowsCodexRequirementsLayoutResolver, windowsCodexRequirementsExecutable
			t.Cleanup(func() {
				windowsEnterpriseHotConfigLayout, enterpriseHooksPlatformPreflight = savedLayout, savedPreflight
				windowsCodexRequirementsLayoutResolver, windowsCodexRequirementsExecutable = savedResolver, savedExecutable
			})
			windowsEnterpriseHotConfigLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
			enterpriseHooksPlatformPreflight = func() error { return nil }
			windowsCodexRequirementsExecutable = func() (string, error) {
				return filepath.Join(layout.BinDir, "defenseclaw-gateway.exe"), nil
			}
			var resolved error
			windowsCodexRequirementsLayoutResolver = func(action string) (connector.WindowsCodexMachineRequirementsOptions, error) {
				if action != "reconcile" {
					t.Errorf("retire resolved the %q layout, want reconcile", action)
				}
				if got := os.Getenv(managed.HookGuardianAuthorizationDirEnv); got != layout.GuardianAuthDir {
					t.Errorf("%s = %q, want the guardian's %q", managed.HookGuardianAuthorizationDirEnv, got, layout.GuardianAuthDir)
				}
				_, resolved = resolveWindowsCodexRequirementsLayout(action)
				return connector.WindowsCodexMachineRequirementsOptions{}, errHookImageResolverStop
			}
			err = reconcileWindowsCodexRequirementsForHookImage(managed.StandaloneWindowsGatewaySvc)
			if !errors.Is(err, errHookImageResolverStop) {
				t.Fatalf("reconcile = %v; want it to reach the layout resolver", err)
			}
			// The resolver gets past every pin and stops at the config
			// load, which the temporary roots do not have.
			for _, refused := range []string{"must be an exact absolute protected path", "must already be canonical",
				"does not match the derived managed StateRoot", "managed gateway service name", "must be pinned to managed_enterprise"} {
				if resolved != nil && strings.Contains(resolved.Error(), refused) {
					t.Fatalf("the layout resolver refused retire's pins: %v", resolved)
				}
			}
			if resolved == nil || !strings.Contains(resolved.Error(), "load protected Windows enterprise config") {
				t.Fatalf("resolver = %v; want it to stop at the protected config load", resolved)
			}
			// The pins are the reconcile's own: the caller's environment is
			// as it was.
			if got, set := os.LookupEnv(managed.HookGuardianAuthorizationDirEnv); set {
				t.Fatalf("%s left set to %q after the reconcile", managed.HookGuardianAuthorizationDirEnv, got)
			}
		})
	}
}

// The retire runtime selector step asks the guardian's own session check
// only for enrolled accounts of the manifest, groups what it dropped by
// account, and keys a failure by its selector file.
func TestHookImageRetireDeselectsOnlyEnrolledSignedOutAccounts(t *testing.T) {
	base := t.TempDir()
	layout, err := managed.StandaloneWindowsLayoutForRoots(filepath.Join(base, "Program Files"), filepath.Join(base, "ProgramData"))
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Dir(layout.DataDir)
	const signedOut, signedIn, stranger = "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1003"
	savedManifest := windowsHookImageManifestLoader
	t.Cleanup(func() { windowsHookImageManifestLoader = savedManifest })
	windowsHookImageManifestLoader = func(path string) (enterprisehooks.Manifest, error) {
		if want := filepath.Join(stateRoot, "hook-guardian", "targets.yaml"); path != want {
			t.Errorf("manifest %q, want %q", path, want)
		}
		return enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{
			{Connector: "claudecode", User: `DCLAB\std2`, SID: signedOut, UserHome: `C:\Users\std2`},
			{Connector: "copilot", User: `DCLAB\std2`, SID: signedOut, UserHome: `C:\Users\std2`},
			{Connector: "claudecode", User: `DCLAB\std1`, SID: signedIn, UserHome: `C:\Users\std1`},
		}}, nil
	}
	savedLayout, savedDeselector := windowsEnterpriseHotConfigLayout, windowsHookImageDeselector
	savedSession := enterpriseHookWindowsTargetSessionCheck
	t.Cleanup(func() {
		windowsEnterpriseHotConfigLayout, windowsHookImageDeselector = savedLayout, savedDeselector
		enterpriseHookWindowsTargetSessionCheck = savedSession
	})
	windowsEnterpriseHotConfigLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
	enterpriseHookWindowsTargetSessionCheck = func(sid, home string) error {
		if sid == signedIn {
			return nil
		}
		return &enterprisehooks.WindowsTargetSessionUnavailableError{SID: sid}
	}
	bin := layout.BinDir
	asked := map[string]bool{}
	selector := `C:\ProgramData\Cisco\DefenseClaw-HookRuntime\copilot\.defenseclaw-managed-runtime-selector.state`
	windowsHookImageDeselector = func(gotBin string, out func(string) (bool, error)) ([]enterprisehooks.WindowsLaunchSelection, map[string]error) {
		if gotBin != bin {
			t.Errorf("bin %q, want %q", gotBin, bin)
		}
		if got := os.Getenv(managed.HookGuardianAuthorizationDirEnv); got != layout.GuardianAuthDir {
			t.Errorf("the selector step ran without the guardian's pins: %s=%q", managed.HookGuardianAuthorizationDirEnv, got)
		}
		for _, sid := range []string{signedOut, signedIn, stranger} {
			o, err := out(sid)
			if err != nil {
				t.Errorf("session of %s: %v", sid, err)
			}
			asked[sid] = o
		}
		return []enterprisehooks.WindowsLaunchSelection{
				{Connector: "copilot", SID: signedOut, Selector: selector},
				{Connector: "claudecode", SID: signedOut, Selector: `C:\Program Files\ClaudeCode\managed-settings.d\.defenseclaw-managed-runtime-selector.state`},
			}, map[string]error{
				`C:\ProgramData\OpenAI\Codex\.defenseclaw-managed-runtime-selector.state`: errors.New("selector lock busy"),
			}
	}
	result := deselectWindowsHookImageSignedOutSelections(winpath.EnterpriseRoots{StateRoot: stateRoot}, bin, managed.StandaloneWindowsGatewaySvc)
	if !asked[signedOut] || asked[signedIn] || asked[stranger] {
		t.Fatalf("signed out = %v; only the enrolled signed-out account may be dropped", asked)
	}
	if len(result.Profiles) != 1 || result.Profiles[0].SID != signedOut || result.Profiles[0].Account != `DCLAB\std2` ||
		strings.Join(result.Profiles[0].Connectors, ",") != "claudecode,copilot" {
		t.Fatalf("profiles = %+v", result.Profiles)
	}
	if result.Errors[strings.ToLower(`C:\ProgramData\OpenAI\Codex\.defenseclaw-managed-runtime-selector.state`)] != "selector lock busy" || result.Error != "" {
		t.Fatalf("errors = %+v / %q", result.Errors, result.Error)
	}
}
