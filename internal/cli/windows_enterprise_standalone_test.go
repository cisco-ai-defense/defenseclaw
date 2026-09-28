// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
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
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func stubWindowsEnterpriseDeployments(t *testing.T, states map[string]winpath.EnterpriseDeploymentState) {
	t.Helper()
	original := windowsEnterpriseDeploymentInspector
	windowsEnterpriseDeploymentInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
		state, ok := states[profile]
		if !ok {
			state = winpath.EnterpriseDeploymentAbsent
		}
		return winpath.EnterpriseDeployment{Profile: profile, State: state}, nil
	}
	// Keep the host's installed config (and its enterprise.trust) out of
	// profile resolution unless a test installs one.
	originalConfig := windowsEnterpriseInstalledConfigPath
	missing := filepath.Join(t.TempDir(), "installed-config.yaml")
	windowsEnterpriseInstalledConfigPath = func() (string, error) { return missing, nil }
	t.Cleanup(func() {
		windowsEnterpriseDeploymentInspector = original
		windowsEnterpriseInstalledConfigPath = originalConfig
	})
}

func TestWindowsEnterpriseProfileDefaultsToSecureClientWithUnchangedArguments(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, nil)
	opts := &windowsEnterpriseLifecycleOptions{gatewayBinary: `C:\p\defenseclaw-gateway.exe`, jsonOutput: true}
	before := windowsEnterprisePowerShellArgs("install", opts)
	if err := resolveWindowsEnterpriseLifecycleProfile("install", opts); err != nil {
		t.Fatal(err)
	}
	if opts.resolvedProfile != "secure_client" {
		t.Fatalf("resolved %q", opts.resolvedProfile)
	}
	after := windowsEnterprisePowerShellArgs("install", opts)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("Secure Client arguments changed:\n before %q\n after  %q", before, after)
	}
	for _, arg := range after {
		if strings.Contains(arg, "Profile") || strings.Contains(arg, "TrustMode") || arg == "-ProductVersion" {
			t.Fatalf("Secure Client arguments carry standalone flag %q", arg)
		}
	}
}

func TestWindowsEnterpriseProfileResolution(t *testing.T) {
	for _, tc := range []struct {
		name    string
		states  map[string]winpath.EnterpriseDeploymentState
		opts    windowsEnterpriseLifecycleOptions
		action  string
		want    string
		wantErr string
	}{
		{name: "flag standalone", opts: windowsEnterpriseLifecycleOptions{profile: "Standalone"}, action: "install", want: "standalone"},
		{name: "installed standalone", states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentInstalled}, action: "status", want: "standalone"},
		{name: "unreadable standalone", states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentUnknown}, action: "status", want: "standalone"},
		{name: "standalone tombstone with profile", states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentTombstone}, opts: windowsEnterpriseLifecycleOptions{profile: "standalone"}, action: "uninstall", want: "standalone"},
		// A standalone uninstall tombstone never redirects the unmodified
		// Secure Client Setup, which passes no --profile.
		{name: "standalone tombstone keeps secure client install", states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentTombstone}, opts: windowsEnterpriseLifecycleOptions{brokerBinary: `C:\stage\defenseclaw-cmid-broker.exe`}, action: "install", want: "secure_client"},
		{name: "standalone tombstone keeps secure client status", states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentTombstone}, action: "status", want: "secure_client"},
		{name: "standalone tombstone keeps secure client uninstall", states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentTombstone}, action: "uninstall", want: "secure_client"},
		{name: "secure client install next to standalone tombstone", states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentTombstone, "secure_client": winpath.EnterpriseDeploymentInstalled}, action: "upgrade", want: "secure_client"},
		{name: "secure client tombstone allows standalone", states: map[string]winpath.EnterpriseDeploymentState{"secure_client": winpath.EnterpriseDeploymentTombstone}, opts: windowsEnterpriseLifecycleOptions{profile: "standalone"}, action: "install", want: "standalone"},
		{name: "explicit secure client on standalone host", states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentInstalled}, opts: windowsEnterpriseLifecycleOptions{profile: "secure_client"}, action: "uninstall", wantErr: "profile_conflict"},
		{name: "standalone on secure client host", states: map[string]winpath.EnterpriseDeploymentState{"secure_client": winpath.EnterpriseDeploymentInstalled}, opts: windowsEnterpriseLifecycleOptions{profile: "standalone"}, action: "install", wantErr: "profile_conflict"},
		{name: "both installed", states: map[string]winpath.EnterpriseDeploymentState{"secure_client": winpath.EnterpriseDeploymentInstalled, "standalone": winpath.EnterpriseDeploymentInstalled}, action: "status", wantErr: "profile_conflict"},
		{name: "certification scope skips detection", states: map[string]winpath.EnterpriseDeploymentState{"secure_client": winpath.EnterpriseDeploymentInstalled}, opts: windowsEnterpriseLifecycleOptions{profile: "standalone", gatewayServiceName: "DefenseClawCertGateway_0a1b2c3d4e"}, action: "install", want: "standalone"},
		{name: "unknown profile", opts: windowsEnterpriseLifecycleOptions{profile: "cloud"}, action: "install", wantErr: "invalid arguments"},
		{name: "broker on standalone", opts: windowsEnterpriseLifecycleOptions{profile: "standalone", brokerBinary: `C:\b.exe`}, action: "install", wantErr: "no CMID credential broker"},
		{name: "trust mode on secure client", opts: windowsEnterpriseLifecycleOptions{trustMode: "hash_pinned"}, action: "install", wantErr: "apply only to the standalone profile"},
		{name: "hash pinned needs manifest", opts: windowsEnterpriseLifecycleOptions{profile: "standalone", trustMode: "hash_pinned"}, action: "install", wantErr: "requires --payload-manifest"},
		{name: "manifest needs hash pinned", opts: windowsEnterpriseLifecycleOptions{profile: "standalone", payloadManifest: `C:\m.json`}, action: "install", wantErr: "applies only to --trust-mode hash_pinned"},
		{name: "bad signer", opts: windowsEnterpriseLifecycleOptions{profile: "standalone", allowedSigners: []string{"abc"}}, action: "install", wantErr: "not a SHA-256"},
		{name: "ensure on secure client", action: "ensure", wantErr: "ensure is available only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubWindowsEnterpriseDeployments(t, tc.states)
			opts := tc.opts
			err := resolveWindowsEnterpriseLifecycleProfile(tc.action, &opts)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if opts.resolvedProfile != tc.want {
				t.Fatalf("resolved %q, want %q", opts.resolvedProfile, tc.want)
			}
		})
	}
}

func TestWindowsEnterpriseProfileFromConfig(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, nil)
	dir := t.TempDir()
	standalone := filepath.Join(dir, "standalone.yaml")
	if err := os.WriteFile(standalone, []byte("deployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := &windowsEnterpriseLifecycleOptions{configPath: standalone}
	if err := resolveWindowsEnterpriseLifecycleProfile("install", opts); err != nil {
		t.Fatal(err)
	}
	if opts.resolvedProfile != "standalone" {
		t.Fatalf("resolved %q", opts.resolvedProfile)
	}
	conflict := &windowsEnterpriseLifecycleOptions{configPath: standalone, profile: "secure_client"}
	if err := resolveWindowsEnterpriseLifecycleProfile("install", conflict); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("flag/config conflict: %v", err)
	}
	plain := filepath.Join(dir, "plain.yaml")
	if err := os.WriteFile(plain, []byte("deployment_mode: managed_enterprise\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts = &windowsEnterpriseLifecycleOptions{configPath: plain}
	if err := resolveWindowsEnterpriseLifecycleProfile("install", opts); err != nil || opts.resolvedProfile != "secure_client" {
		t.Fatalf("plain config resolved %q, %v", opts.resolvedProfile, err)
	}
}

func TestWindowsEnterpriseStandaloneArguments(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, nil)
	signer := strings.Repeat("AB", 32)
	opts := &windowsEnterpriseLifecycleOptions{
		profile:         "standalone",
		trustMode:       "HASH_PINNED",
		payloadManifest: `C:\stage\payload-trust.json`,
		allowedSigners:  []string{signer, strings.Repeat("cd", 32)},
		productVersion:  "1.4.0",
	}
	if err := resolveWindowsEnterpriseLifecycleProfile("install", opts); err != nil {
		t.Fatal(err)
	}
	args := windowsEnterprisePowerShellArgs("install", opts)
	want := []string{
		"-EnterpriseProfile", "Standalone",
		"-TrustMode", "HashPinned", "-PayloadManifest", `C:\stage\payload-trust.json`,
		"-AllowedSigners", strings.ToLower(signer) + "," + strings.Repeat("cd", 32),
		"-ProductVersion", "1.4.0",
	}
	if got := args[len(args)-len(want):]; !reflect.DeepEqual(got, want) {
		t.Fatalf("standalone tail %q, want %q", got, want)
	}
	defaulted := &windowsEnterpriseLifecycleOptions{profile: "standalone"}
	if err := resolveWindowsEnterpriseLifecycleProfile("status", defaulted); err != nil {
		t.Fatal(err)
	}
	if defaulted.trustMode != "authenticode" || defaulted.productVersion != strings.TrimSpace(appVersion) {
		t.Fatalf("defaults: trust %q version %q", defaulted.trustMode, defaulted.productVersion)
	}
}

func writeWindowsEnterpriseTrustConfig(t *testing.T, dir, name, trust string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	body := "deployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n" + trust
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func windowsEnterpriseArgValue(args []string, name string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == name {
			return args[index+1]
		}
	}
	return ""
}

// Without --config a mutation keeps the installed config's trust, so a Setup
// /ensure or a remediation run cannot drop the administrator's signer pin;
// read-only actions do not consult it.
func TestWindowsEnterpriseInstalledConfigTrustAppliesToMutations(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentInstalled})
	signer := strings.Repeat("ef", 32)
	installed := writeWindowsEnterpriseTrustConfig(t, t.TempDir(), "config.yaml",
		"  trust:\n    mode: authenticode\n    allowed_signers: ["+signer+"]\n")
	windowsEnterpriseInstalledConfigPath = func() (string, error) { return installed, nil }

	ensure := &windowsEnterpriseLifecycleOptions{profile: "standalone"}
	if err := resolveWindowsEnterpriseLifecycleProfile("ensure", ensure); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ensure.allowedSigners, []string{signer}) {
		t.Fatalf("ensure signers %q", ensure.allowedSigners)
	}
	status := &windowsEnterpriseLifecycleOptions{profile: "standalone"}
	if err := resolveWindowsEnterpriseLifecycleProfile("status", status); err != nil || len(status.allowedSigners) != 0 {
		t.Fatalf("status signers %q, %v", status.allowedSigners, err)
	}
	unsigned := &windowsEnterpriseLifecycleOptions{profile: "standalone", trustMode: "hash_pinned", payloadManifest: `C:\stage\payload-trust.json`}
	if err := resolveWindowsEnterpriseLifecycleProfile("ensure", unsigned); err == nil || !strings.Contains(err.Error(), "admits only Authenticode-signed payloads") {
		t.Fatalf("unsigned Setup over an authenticode config: %v", err)
	}
}

func TestParseWindowsEnterprisePayloadManifest(t *testing.T) {
	digest := strings.Repeat("0f", 32)
	pins, err := parseWindowsEnterprisePayloadManifest([]byte(`{"schema_version":1,"files":{"Install-Enterprise.ps1":"` + strings.ToUpper(digest) + `"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if pins["install-enterprise.ps1"] != digest {
		t.Fatalf("pins %v", pins)
	}
	for _, bad := range []string{
		`{"schema_version":2,"files":{"a.exe":"` + digest + `"}}`,
		`{"schema_version":1,"files":{}}`,
		`{"schema_version":1,"files":{"..\\a.exe":"` + digest + `"}}`,
		`{"schema_version":1,"files":{"a.exe":"xyz"}}`,
		`{"schema_version":1,"files":{"a.exe":"` + digest + `"},"extra":1}`,
	} {
		if _, err := parseWindowsEnterprisePayloadManifest([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestWindowsPowerShell7Selection(t *testing.T) {
	for value, ok := range map[string]bool{"7.4.6": true, "7.5.0": true, "8.0": true, "7.5.0-preview.3": false, "6.2.7": false, "": false, "7": false, "7.x": false} {
		if _, got := parseWindowsPowerShell7Version(value); got != ok {
			t.Fatalf("parse %q = %t", value, got)
		}
	}
	older, _ := parseWindowsPowerShell7Version("7.4.6")
	newer, _ := parseWindowsPowerShell7Version("7.10.0")
	if compareWindowsVersions(newer, older) <= 0 {
		t.Fatal("7.10.0 must sort after 7.4.6")
	}
	for location, want := range map[string]string{
		`C:\Program Files\PowerShell\7\`:  `C:\Program Files\PowerShell\7`,
		`c:\program files\PowerShell\7`:   `c:\program files\PowerShell\7`,
		`C:\Program Files`:                "",
		`C:\Users\x\PowerShell\7`:         "",
		`%ProgramFiles%\PowerShell\7`:     "",
		`C:\Program Files (x86)\PS\7`:     "",
		`C:\Program Files\..\Temp\pwsh\7`: "",
	} {
		got, ok := windowsPowerShell7Home(location, `C:\Program Files`)
		if (want == "") == ok || got != want {
			t.Fatalf("home(%q) = %q, %t; want %q", location, got, ok, want)
		}
	}
}

func TestCompareWindowsEnterpriseVersions(t *testing.T) {
	for _, tc := range []struct {
		left, right string
		want        int
	}{
		{"1.4.0", "1.4.0", 0},
		{"v1.4.1", "1.4.0", 1},
		{"1.4.0", "1.10.0", -1},
		{"1.4.0-rc.1", "1.4.0", -1},
		{"1.4.0+build.7", "1.4.0", 0},
		{"1.4.0", "", 1},
		{"dev", "1.4.0", 1},
	} {
		if got := compareWindowsEnterpriseVersions(tc.left, tc.right); got != tc.want {
			t.Fatalf("compare(%q, %q) = %d, want %d", tc.left, tc.right, got, tc.want)
		}
	}
}

func TestPlanWindowsEnterpriseEnsure(t *testing.T) {
	original := windowsEnterpriseEnsureDriftDetector
	drift := ""
	windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return drift, nil }
	t.Cleanup(func() { windowsEnterpriseEnsureDriftDetector = original })
	full := windowsEnterpriseLifecycleOptions{
		profile: "standalone", resolvedProfile: "standalone", productVersion: "1.4.0",
		gatewayBinary: "g", acpBinary: "a", hookBinary: "h", sensorHelperBinary: "s", configPath: "c",
	}
	for _, tc := range []struct {
		name    string
		status  windowsEnterpriseInstallerReport
		opts    windowsEnterpriseLifecycleOptions
		drift   string
		want    string
		wantErr string
	}{
		{name: "pending", status: windowsEnterpriseInstallerReport{Installed: true, TransactionPending: true}, opts: full, want: "repair"},
		{name: "absent", status: windowsEnterpriseInstallerReport{}, opts: full, want: "install"},
		{name: "absent without config", status: windowsEnterpriseInstallerReport{}, opts: windowsEnterpriseLifecycleOptions{productVersion: "1.4.0", gatewayBinary: "g"}, wantErr: "requires --config"},
		{name: "older", status: windowsEnterpriseInstallerReport{Installed: true, InstalledVersion: "1.3.9"}, opts: full, want: "upgrade"},
		{name: "newer", status: windowsEnterpriseInstallerReport{Installed: true, InstalledVersion: "1.5.0"}, opts: full, wantErr: "downgrade_refused"},
		{name: "drift", status: windowsEnterpriseInstallerReport{Installed: true, InstalledVersion: "1.4.0"}, opts: full, drift: "config", want: "upgrade"},
		{name: "compliant", status: windowsEnterpriseInstallerReport{Installed: true, InstalledVersion: "1.4.0"}, opts: full, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drift = tc.drift
			opts := tc.opts
			plan, err := planWindowsEnterpriseEnsure(&tc.status, &opts, `C:\stage\install-enterprise.ps1`)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if plan.Action != tc.want {
				t.Fatalf("plan %+v, want %q", plan, tc.want)
			}
		})
	}
}

func TestWindowsEnterpriseStandaloneActionReportsSchemaTwo(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, nil)
	originalRunner := windowsEnterpriseStandaloneRunner
	originalObserver := windowsEnterpriseStandaloneObserver
	originalSC := windowsEnterpriseCommandRunner
	t.Cleanup(func() {
		windowsEnterpriseStandaloneRunner = originalRunner
		windowsEnterpriseStandaloneObserver = originalObserver
		windowsEnterpriseCommandRunner = originalSC
	})
	windowsEnterpriseCommandRunner = func(context.Context, *cobra.Command, string, []string) error {
		t.Fatal("the standalone profile must not use the Windows PowerShell runner")
		return nil
	}
	var gotArgs []string
	windowsEnterpriseStandaloneRunner = func(_ context.Context, _ *cobra.Command, _ string, args []string) (windowsEnterpriseStandaloneRun, error) {
		gotArgs = args
		body, _ := json.Marshal(map[string]any{
			"schema_version": 1, "ok": true, "action": "status", "installed": true,
			"gateway_service": "DefenseClawGateway", "gateway_service_state": "running",
			"guardian_service": "DefenseClawHookGuardian", "guardian_service_state": "running",
			"enumerator_service": "DefenseClawHookEnumerator", "enumerator_service_state": "running",
			"sensor_helper_service": "DefenseClawSensorHelper", "sensor_helper_service_state": "running",
			"gateway_ready": true, "guardian_ready": true, "security_complete": true,
			"installed_version": "1.4.0", "errors": []string{},
		})
		return windowsEnterpriseStandaloneRun{Output: append([]byte("WARNING: noise\n"), body...)}, nil
	}
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string {
		return `C:\Windows\Logs\DefenseClaw\enterprise-lifecycle.log`
	}

	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	opts := &windowsEnterpriseLifecycleOptions{profile: "standalone", resolvedProfile: "standalone", productVersion: "1.4.0", jsonOutput: true, trustMode: "authenticode"}
	if err := runWindowsEnterpriseStandaloneAction(context.Background(), command, "status", opts, `C:\x\install-enterprise.ps1`, windowsEnterprisePowerShellArgs("status", opts)); err != nil {
		t.Fatal(err)
	}
	if !containsString(gotArgs, "-Json") || !containsString(gotArgs, "Standalone") {
		t.Fatalf("installer args %q", gotArgs)
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode %q: %v", stdout.String(), err)
	}
	if result.SchemaVersion != 2 || !result.OK || result.Profile != "standalone" || result.ExitCode != 0 ||
		len(result.Services) != 4 || !result.Readiness.Enumerator || result.InstalledVersion != "1.4.0" ||
		result.LogPath == "" {
		t.Fatalf("result %+v", result)
	}
}

func TestWindowsEnterpriseStandaloneFailureCodes(t *testing.T) {
	for _, tc := range []struct {
		message string
		code    string
		exit    int
	}{
		{"another DefenseClaw enterprise lifecycle mutation holds the protected file lock for more than 30 seconds", "lifecycle_busy", 1618},
		{"invalid arguments: --profile must be secure_client or standalone", "invalid_arguments", 1639},
		{"powershell7_required: the standalone enterprise lifecycle requires PowerShell 7", "powershell7_required", 1603},
		{"profile_conflict: a Cisco Secure Client DefenseClaw deployment exists", "profile_conflict", 1603},
		{"Install requires -Config", "lifecycle_error", 1603},
	} {
		result := enterprisestatus.New("install", "standalone", "windows", "1.4.0")
		result.AddError(windowsEnterpriseMessageCode(tc.message, "lifecycle_error"), tc.message)
		if result.Errors[0].Code != tc.code {
			t.Fatalf("%q classified %q, want %q", tc.message, result.Errors[0].Code, tc.code)
		}
		if got := result.Finish("windows", windowsEnterpriseFailureCodeFor(result)); got != tc.exit {
			t.Fatalf("%q exit %d, want %d", tc.message, got, tc.exit)
		}
	}
}

func TestWindowsEnterpriseStandaloneUninstallOnCleanHostIsNoop(t *testing.T) {
	originalFootprint := windowsEnterpriseStandaloneFootprint
	originalRunner := windowsEnterpriseStandaloneRunner
	originalObserver := windowsEnterpriseStandaloneObserver
	t.Cleanup(func() {
		windowsEnterpriseStandaloneFootprint = originalFootprint
		windowsEnterpriseStandaloneRunner = originalRunner
		windowsEnterpriseStandaloneObserver = originalObserver
	})
	windowsEnterpriseStandaloneFootprint = func() (bool, error) { return false, nil }
	windowsEnterpriseStandaloneRunner = func(context.Context, *cobra.Command, string, []string) (windowsEnterpriseStandaloneRun, error) {
		return windowsEnterpriseStandaloneRun{}, errors.New("installer must not run on a clean host")
	}
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	opts := &windowsEnterpriseLifecycleOptions{resolvedProfile: "standalone", jsonOutput: true}
	if err := runWindowsEnterpriseStandaloneAction(context.Background(), command, "uninstall", opts, `C:\x\install-enterprise.ps1`, nil); err != nil {
		t.Fatal(err)
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || !result.Noop || result.NoopReason != "not_installed" {
		t.Fatalf("result %+v", result)
	}
}

func TestWindowsEnterpriseEventMapping(t *testing.T) {
	for _, tc := range []struct {
		action string
		ok     bool
		noop   bool
		code   string
		id     uint32
		logged bool
	}{
		{action: "install", ok: true, id: 100, logged: true},
		{action: "upgrade", ok: true, id: 101, logged: true},
		{action: "repair", ok: true, id: 102, logged: true},
		{action: "uninstall", ok: true, id: 110, logged: true},
		{action: "ensure", ok: true, noop: true, id: 111, logged: true},
		{action: "ensure", ok: true, id: 112, logged: true},
		{action: "status", ok: true, logged: false},
		{action: "verify", ok: false, code: "not_ready", id: 120, logged: true},
		{action: "install", ok: false, code: "lifecycle_error", id: 130, logged: true},
		{action: "ensure", ok: false, code: "lifecycle_busy", id: 140, logged: true},
		{action: "install", ok: false, code: "powershell7_required", id: 150, logged: true},
	} {
		result := enterprisestatus.New(tc.action, "standalone", "windows", "1.4.0")
		result.Noop = tc.noop
		if tc.code != "" {
			result.AddError(tc.code, "x")
		}
		result.Finish("windows", 0)
		id, _, logged := windowsEnterpriseEventFor(result)
		if logged != tc.logged || id != tc.id {
			t.Fatalf("%+v: got id %d logged %t", tc, id, logged)
		}
	}
}

func TestValidateWindowsEnterpriseStandaloneHostRefusesEmulation(t *testing.T) {
	original := windowsEnterpriseNativeMachine
	t.Cleanup(func() { windowsEnterpriseNativeMachine = original })
	windowsEnterpriseNativeMachine = func() (uint16, error) { return 0xAA64, nil } // IMAGE_FILE_MACHINE_ARM64
	if err := validateWindowsEnterpriseStandaloneHost(); err == nil || !strings.HasPrefix(err.Error(), "unsupported_architecture:") {
		t.Fatalf("ARM64 host: %v", err)
	}
	windowsEnterpriseNativeMachine = func() (uint16, error) { return windowsImageFileMachineAMD64, nil }
	if err := validateWindowsEnterpriseStandaloneHost(); err != nil {
		t.Fatalf("x64 host: %v", err)
	}
}

func TestWindowsEnterpriseStderrCodeKeepsInstallerRefusals(t *testing.T) {
	for body, want := range map[string]string{
		"powershell7_required: the standalone enterprise lifecycle requires PowerShell 7\r\nAt line:1":    "powershell7_required: the standalone enterprise lifecycle requires PowerShell 7",
		"Exception: powershell_32bit_host: run the standalone enterprise lifecycle from a 64-bit process": "powershell_32bit_host: run the standalone enterprise lifecycle from a 64-bit process",
		"powershell_constrained_language: the standalone enterprise lifecycle compiles":                   "powershell_constrained_language: the standalone enterprise lifecycle compiles",
		"unrelated failure": "",
	} {
		if got := windowsEnterpriseStderrCode([]byte(body)); got != want {
			t.Fatalf("stderr %q: got %q, want %q", body, got, want)
		}
	}
	result := enterprisestatus.New("install", "standalone", "windows", "1.4.0")
	result.AddError(windowsEnterpriseMessageCode("powershell_constrained_language: requires FullLanguage (exit status 1)", "x"), "m")
	if result.Errors[0].Code != "powershell_constrained_language" {
		t.Fatalf("code %q", result.Errors[0].Code)
	}
}

func TestWindowsEnterpriseStandalonePreflightFailureIsSchemaTwo(t *testing.T) {
	originalObserver := windowsEnterpriseStandaloneObserver
	t.Cleanup(func() { windowsEnterpriseStandaloneObserver = originalObserver })
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
	for _, tc := range []struct {
		cause error
		code  string
		exit  int
	}{
		{windowsEnterpriseInvalidArguments("--trust-mode must be authenticode or hash_pinned"), "invalid_arguments", 1639},
		{errors.Join(errPowerShell7Required, errors.New("not registered")), "powershell7_required", 1603},
		{errors.New("profile_conflict: this host carries a secure_client enterprise deployment"), "profile_conflict", 1603},
	} {
		command := &cobra.Command{}
		var stdout bytes.Buffer
		command.SetOut(&stdout)
		err := writeWindowsEnterpriseStandalonePreflightFailure(command, "install", &windowsEnterpriseLifecycleOptions{jsonOutput: true}, tc.cause)
		if got := commandExitCode(err); got != tc.exit {
			t.Fatalf("%v: exit %d, want %d", tc.cause, got, tc.exit)
		}
		var result enterprisestatus.Result
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.SchemaVersion != 2 || result.OK || len(result.Errors) != 1 || result.Errors[0].Code != tc.code || result.ExitCode != tc.exit {
			t.Fatalf("%v: result %+v", tc.cause, result)
		}
	}
}

// On a host without the log folder the first run created it but still
// reported it missing, so a first install carried lifecycle_log_failed.
func TestWindowsEnterpriseLogDirectoryIsUsableOnFirstCreate(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "DefenseClaw")
	if err := ensureWindowsEnterpriseLogDirectory(directory); errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the log folder this call created is reported missing: %v", err)
	}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		t.Fatalf("the log folder was not created: %v", err)
	}
}

func TestWindowsEnterpriseLifecycleLogRotatesFiveGenerations(t *testing.T) {
	directory := t.TempDir()
	originalLimit := windowsEnterpriseLogLimit
	t.Cleanup(func() { windowsEnterpriseLogLimit = originalLimit })
	windowsEnterpriseLogLimit = 600
	for run := 0; run < 40; run++ {
		result := enterprisestatus.New("status", "standalone", "windows", "1.4.0")
		result.Finish("windows", 0)
		path, err := writeWindowsEnterpriseLifecycleLog(directory, result, nil)
		if err != nil {
			t.Fatal(err)
		}
		if path != filepath.Join(directory, windowsEnterpriseLogName) || result.LogPath != path {
			t.Fatalf("log path %q / %q", path, result.LogPath)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	want := []string{
		windowsEnterpriseLogName, windowsEnterpriseLogName + ".1", windowsEnterpriseLogName + ".2",
		windowsEnterpriseLogName + ".3", windowsEnterpriseLogName + ".4", windowsEnterpriseLastResult,
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("log files %q, want %q", names, want)
	}
	body, err := os.ReadFile(filepath.Join(directory, windowsEnterpriseLastResult))
	if err != nil {
		t.Fatal(err)
	}
	var last enterprisestatus.Result
	if err := json.Unmarshal(body, &last); err != nil || last.SchemaVersion != 2 || last.Action != "status" {
		t.Fatalf("last result %q: %v", body, err)
	}
}

func TestWindowsEnterpriseRecoveredFailedInstallIsRecognizedOnlyAlone(t *testing.T) {
	recovered := &windowsEnterpriseInstallerReport{
		Error: "Uninstall recovered a failed initial install; run Install to create a deployment",
	}
	if !windowsEnterpriseRecoveredFailedInstall(recovered) {
		t.Fatal("the rolled-back first install was not recognized")
	}
	for name, report := range map[string]*windowsEnterpriseInstallerReport{
		"ok":        {OK: true},
		"installed": {Installed: true, Error: recovered.Error},
		"pending":   {TransactionPending: true, Error: recovered.Error},
		"other":     {Errors: []string{recovered.Error, "service DefenseClawGateway failed to stop"}},
		"empty":     {},
	} {
		if windowsEnterpriseRecoveredFailedInstall(report) {
			t.Fatalf("%s report was treated as a recovered first install", name)
		}
	}
}

// Secure Client preflight documents keep their historical text exactly; only
// the standalone profile classifies --purge/--no-start misuse as invalid
// arguments (1639) and accepts --no-start with ensure.
func TestWindowsEnterpriseMisusePreflightKeepsSecureClientText(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, nil)
	originalObserver := windowsEnterpriseStandaloneObserver
	originalHost := windowsEnterpriseStandaloneHostValidator
	t.Cleanup(func() {
		windowsEnterpriseStandaloneObserver = originalObserver
		windowsEnterpriseStandaloneHostValidator = originalHost
	})
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
	windowsEnterpriseStandaloneHostValidator = func() error { return nil }

	for _, tc := range []struct {
		name string
		opts windowsEnterpriseLifecycleOptions
		want string
	}{
		{"purge", windowsEnterpriseLifecycleOptions{purge: true, jsonOutput: true}, "--purge is valid only with enterprise windows uninstall"},
		{"no-start", windowsEnterpriseLifecycleOptions{noStart: true, jsonOutput: true}, "--no-start is valid only with install, upgrade, or repair"},
	} {
		t.Run("secure client "+tc.name, func(t *testing.T) {
			command := &cobra.Command{}
			var stdout bytes.Buffer
			command.SetOut(&stdout)
			opts := tc.opts
			if err := runWindowsEnterpriseLifecycle(context.Background(), command, "status", &opts); err == nil {
				t.Fatal("misuse accepted")
			}
			var report windowsEnterpriseLifecyclePreflightFailure
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatalf("decode %q: %v", stdout.String(), err)
			}
			if report.SchemaVersion != 1 || report.Error != tc.want || len(report.Errors) != 1 || report.Errors[0] != tc.want {
				t.Fatalf("Secure Client preflight changed: %+v", report)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		action string
		opts   windowsEnterpriseLifecycleOptions
	}{
		{"purge", "status", windowsEnterpriseLifecycleOptions{profile: "standalone", purge: true, jsonOutput: true}},
		{"no-start", "status", windowsEnterpriseLifecycleOptions{profile: "standalone", noStart: true, jsonOutput: true}},
	} {
		t.Run("standalone "+tc.name, func(t *testing.T) {
			command := &cobra.Command{}
			var stdout bytes.Buffer
			command.SetOut(&stdout)
			opts := tc.opts
			err := runWindowsEnterpriseLifecycle(context.Background(), command, tc.action, &opts)
			if got := commandExitCode(err); got != 1639 {
				t.Fatalf("exit %d (%v), want 1639", got, err)
			}
			var result enterprisestatus.Result
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if len(result.Errors) != 1 || result.Errors[0].Code != "invalid_arguments" {
				t.Fatalf("result %+v", result)
			}
		})
	}
}

// ensureStub scripts the installer runs one ensure makes.
type ensureStub struct {
	t       *testing.T
	replies []map[string]any
	calls   [][]string
}

func (stub *ensureStub) install(t *testing.T) {
	t.Helper()
	originalRunner := windowsEnterpriseStandaloneRunner
	originalObserver := windowsEnterpriseStandaloneObserver
	originalDrift := windowsEnterpriseEnsureDriftDetector
	t.Cleanup(func() {
		windowsEnterpriseStandaloneRunner = originalRunner
		windowsEnterpriseStandaloneObserver = originalObserver
		windowsEnterpriseEnsureDriftDetector = originalDrift
	})
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
	windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "", nil }
	windowsEnterpriseStandaloneRunner = func(_ context.Context, _ *cobra.Command, _ string, args []string) (windowsEnterpriseStandaloneRun, error) {
		stub.calls = append(stub.calls, args)
		if len(stub.replies) == 0 {
			stub.t.Fatalf("unexpected installer run %q", args)
		}
		reply := stub.replies[0]
		stub.replies = stub.replies[1:]
		body, _ := json.Marshal(reply)
		run := windowsEnterpriseStandaloneRun{Output: body}
		if ok, _ := reply["ok"].(bool); !ok {
			run.ExitCode = 1
		}
		return run, nil
	}
}

func ensureTestOptions() *windowsEnterpriseLifecycleOptions {
	return &windowsEnterpriseLifecycleOptions{
		profile: "standalone", resolvedProfile: "standalone", productVersion: "1.4.0", trustMode: "authenticode",
		gatewayBinary: `C:\stage\defenseclaw-gateway.exe`, acpBinary: `C:\stage\defenseclaw-acp.exe`,
		hookBinary: `C:\stage\defenseclaw-hook.exe`, sensorHelperBinary: `C:\stage\defenseclaw-sensor-helper.exe`,
		configPath: `C:\stage\config.yaml`, manifestPath: `C:\stage\targets.yaml`,
		noStart: true, jsonOutput: true,
	}
}

func installedStatus(action string) map[string]any {
	return map[string]any{
		"schema_version": 1, "ok": true, "action": action, "installed": true, "transaction_pending": false,
		"installed_version": "1.4.0", "gateway_ready": true, "guardian_ready": true, "errors": []string{},
	}
}

// ensure's Status and Verify probes carry no mutation inputs: the installer
// refuses -NoStart, -Mode, and -Connector for them, and a refused probe must
// not be read as "not installed".
func TestWindowsEnterpriseEnsureProbesCarryNoMutationInputs(t *testing.T) {
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("verify")}}
	stub.install(t)
	opts := ensureTestOptions()
	opts.configPath, opts.manifestPath = "", ""
	opts.mode, opts.connector = "action", "codex"
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	if err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`); err != nil {
		t.Fatalf("ensure on a compliant host: %v\n%s", err, stdout.String())
	}
	if len(stub.calls) != 2 {
		t.Fatalf("installer runs %q", stub.calls)
	}
	for _, args := range stub.calls {
		for _, forbidden := range []string{"-NoStart", "-Mode", "-Connector", "-Config", "-Manifest", "-GatewayBinary", "-HookBinary"} {
			if containsString(args, forbidden) {
				t.Fatalf("probe %s carries %s: %q", args[1], forbidden, args)
			}
		}
		if !containsString(args, "Standalone") || !containsString(args, "-ProductVersion") {
			t.Fatalf("probe lost its profile or trust arguments: %q", args)
		}
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || !result.Noop || result.NoopReason != "compliant" {
		t.Fatalf("result %+v", result)
	}
}

func TestWindowsEnterpriseEnsureRefusesToPlanFromAFailedProbe(t *testing.T) {
	refusal := "DefenseClaw enterprise installer rejected its module before import: Authenticode signature is not valid (NotSigned)"
	stub := &ensureStub{t: t, replies: []map[string]any{
		{"schema_version": 1, "ok": false, "action": "status", "error": refusal, "errors": []string{refusal}},
	}}
	stub.install(t)
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, ensureTestOptions(), `C:\stage\install-enterprise.ps1`)
	if got := commandExitCode(err); got != 1603 {
		t.Fatalf("exit %d (%v), want 1603", got, err)
	}
	if len(stub.calls) != 1 {
		t.Fatalf("ensure ran the installer after a failed probe: %q", stub.calls)
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.OK || len(result.Errors) != 1 || result.Errors[0].Code != "status_failed" || !strings.Contains(result.Errors[0].Message, "NotSigned") {
		t.Fatalf("result %+v", result)
	}
}

func TestParseWindowsEnterpriseInstallerReportMarksStatelessFailures(t *testing.T) {
	failure, err := parseWindowsEnterpriseInstallerReport([]byte(`{"schema_version":1,"ok":false,"action":"status","error":"x","errors":["x"]}`))
	if err != nil || !failure.probeFailed {
		t.Fatalf("failure document %+v, %v", failure, err)
	}
	for _, body := range []string{
		`{"schema_version":1,"ok":false,"action":"status","installed":false,"transaction_pending":false,"errors":[]}`,
		`{"schema_version":1,"ok":true,"action":"status","installed":false,"transaction_pending":false,"errors":[]}`,
	} {
		report, err := parseWindowsEnterpriseInstallerReport([]byte(body))
		if err != nil || report.probeFailed {
			t.Fatalf("%s: %+v, %v", body, report, err)
		}
	}
}

// Two ensure runs overlap on a clean device: this one planned Install from a
// stale status and the lifecycle then found the host installed. It re-plans
// once instead of reporting a failed install on a healthy host.
func TestWindowsEnterpriseEnsureReplansAfterLosingAnInstallRace(t *testing.T) {
	absent := map[string]any{"schema_version": 1, "ok": true, "action": "status", "installed": false, "transaction_pending": false, "errors": []string{}}
	already := "DefenseClaw enterprise mode is already installed; use Upgrade or Repair"
	stub := &ensureStub{t: t, replies: []map[string]any{
		absent,
		{"schema_version": 1, "ok": false, "action": "install", "error": already, "errors": []string{already}},
		installedStatus("status"),
		installedStatus("verify"),
	}}
	stub.install(t)
	opts := ensureTestOptions()
	opts.noStart = false
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	if err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`); err != nil {
		t.Fatalf("ensure after a lost install race: %v\n%s", err, stdout.String())
	}
	if len(stub.calls) != 4 || stub.calls[1][1] != "Install" || stub.calls[3][1] != "Verify" {
		t.Fatalf("installer runs %q", stub.calls)
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || !result.Noop || len(result.Errors) != 0 {
		t.Fatalf("result %+v", result)
	}
	found := false
	for _, warning := range result.Warnings {
		found = found || warning.Code == "concurrent_install"
	}
	if !found {
		t.Fatalf("warnings %+v", result.Warnings)
	}

	// A second loss is reported, not retried forever.
	stub = &ensureStub{t: t, replies: []map[string]any{
		absent,
		{"schema_version": 1, "ok": false, "action": "install", "error": already, "errors": []string{already}},
		absent,
		{"schema_version": 1, "ok": false, "action": "install", "error": already, "errors": []string{already}},
	}}
	stub.install(t)
	stdout.Reset()
	err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, ensureTestOptions(), `C:\stage\install-enterprise.ps1`)
	if got := commandExitCode(err); got != 1603 || len(stub.calls) != 4 {
		t.Fatalf("exit %d after %d runs (%v)", got, len(stub.calls), err)
	}
}

// A standalone root a standard user created first cannot hold a deployment:
// ensure plans Install (which moves the tree aside) instead of failing every
// retry, and uninstall does not count the tree as a DefenseClaw footprint.
func TestWindowsEnterpriseEnsurePlansInstallOverASquattedRoot(t *testing.T) {
	original := windowsEnterpriseEnsureDriftDetector
	windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "", nil }
	t.Cleanup(func() { windowsEnterpriseEnsureDriftDetector = original })
	squat := `root_squatted: C:\ProgramData\Cisco is owned by S-1-5-21-1-2-3-1001, not an administrator; no DefenseClaw deployment can use it.`
	status, err := parseWindowsEnterpriseInstallerReport([]byte(`{"schema_version":1,"ok":false,"action":"status","error":` + strconvQuote(squat) + `,"errors":[` + strconvQuote(squat) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	opts := ensureTestOptions()
	plan, err := planWindowsEnterpriseEnsure(status, opts, `C:\stage\install-enterprise.ps1`)
	if err != nil || plan.Action != "install" || plan.Reason != "root_squatted" {
		t.Fatalf("plan %+v, %v", plan, err)
	}
	opts.configPath = ""
	if _, err := planWindowsEnterpriseEnsure(status, opts, `C:\stage\install-enterprise.ps1`); err == nil || !strings.Contains(err.Error(), "requires --config") {
		t.Fatalf("squatted host without a config: %v", err)
	}
	// Any other stateless failure is still refused.
	other, _ := parseWindowsEnterpriseInstallerReport([]byte(`{"schema_version":1,"ok":false,"action":"status","error":"untrusted ancestor owner S-1-5-21-1-2-3-1001 can replace managed content through: C:\\ProgramData\\Cisco"}`))
	if _, err := planWindowsEnterpriseEnsure(other, ensureTestOptions(), `C:\stage\install-enterprise.ps1`); err == nil {
		t.Fatal("planned from a failed probe")
	}
}

func TestWindowsEnterpriseFootprintIgnoresUserCreatedPaths(t *testing.T) {
	original := windowsEnterpriseFootprintOwner
	t.Cleanup(func() { windowsEnterpriseFootprintOwner = original })
	user, _ := windows.StringToSid("S-1-5-21-1111111111-2222222222-3333333333-1001")
	administrators, _ := windows.StringToSid("S-1-5-32-544")
	system, _ := windows.StringToSid("S-1-5-18")
	for _, tc := range []struct {
		owner *windows.SID
		err   error
		want  bool
	}{
		{owner: user, want: true},
		{owner: administrators, want: false},
		{owner: system, want: false},
		{err: windows.ERROR_ACCESS_DENIED, want: false},
	} {
		windowsEnterpriseFootprintOwner = func(string) (*windows.SID, error) { return tc.owner, tc.err }
		if got := windowsEnterpriseFootprintUserCreated(`C:\ProgramData\Cisco\DefenseClaw`); got != tc.want {
			t.Fatalf("owner %v err %v: user-created %t, want %t", tc.owner, tc.err, got, tc.want)
		}
	}
	windowsEnterpriseFootprintOwner = original
	path := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if owner, err := windowsEnterpriseFootprintOwner(path); err != nil || owner == nil || !owner.IsValid() {
		t.Fatalf("read owner: %v, %v", owner, err)
	}
}

func strconvQuote(value string) string {
	body, _ := json.Marshal(value)
	return string(body)
}

// enterprise.trust in the supplied config is enforced for the standalone
// profile: it fills unset flags, and a disagreement with a flag is refused.
func TestWindowsEnterpriseConfigTrustIsApplied(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, nil)
	dir := t.TempDir()
	signerA, signerB := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	write := func(name, trust string) string {
		path := filepath.Join(dir, name)
		body := "deployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n" + trust
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	signers := write("signers.yaml", "  trust:\n    mode: authenticode\n    allowed_signers: ["+strings.ToUpper(signerA)+", "+signerB+"]\n")
	pinned := write("pinned.yaml", "  trust:\n    mode: hash_pinned\n")
	for _, tc := range []struct {
		name        string
		opts        windowsEnterpriseLifecycleOptions
		wantErr     string
		wantMode    string
		wantSigners []string
	}{
		{name: "config signers pin authenticode", opts: windowsEnterpriseLifecycleOptions{configPath: signers}, wantMode: "authenticode", wantSigners: []string{signerA, signerB}},
		{name: "matching flag signers", opts: windowsEnterpriseLifecycleOptions{configPath: signers, allowedSigners: []string{signerB, signerA}}, wantMode: "authenticode", wantSigners: []string{signerB, signerA}},
		{name: "conflicting flag signers", opts: windowsEnterpriseLifecycleOptions{configPath: signers, allowedSigners: []string{signerA}}, wantErr: "conflicts with enterprise.trust.allowed_signers"},
		// The unsigned Setup always passes --trust-mode hash_pinned; a
		// config that requires authenticode refuses it and says how to
		// resolve it.
		{name: "unsigned Setup under an authenticode config", opts: windowsEnterpriseLifecycleOptions{configPath: signers, trustMode: "hash_pinned", payloadManifest: `C:\m.json`}, wantErr: "use a signed Setup or set enterprise.trust.mode hash_pinned"},
		// hash_pinned, like an unset mode, admits the unsigned payload by its
		// pins and still verifies a signed payload by its signature.
		{name: "signed run under a hash_pinned config", opts: windowsEnterpriseLifecycleOptions{configPath: pinned, trustMode: "authenticode"}, wantMode: "authenticode"},
		{name: "no flag under a hash_pinned config", opts: windowsEnterpriseLifecycleOptions{configPath: pinned}, wantMode: "authenticode"},
		{name: "unsigned Setup under a hash_pinned config", opts: windowsEnterpriseLifecycleOptions{configPath: pinned, trustMode: "hash_pinned", payloadManifest: `C:\m.json`}, wantMode: "hash_pinned"},
		{name: "unknown mode", opts: windowsEnterpriseLifecycleOptions{configPath: write("mode.yaml", "  trust:\n    mode: signed\n")}, wantErr: "enterprise.trust.mode"},
		{name: "malformed signer", opts: windowsEnterpriseLifecycleOptions{configPath: write("signer.yaml", "  trust:\n    allowed_signers: [abc]\n")}, wantErr: "not a SHA-256 certificate thumbprint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			err := resolveWindowsEnterpriseLifecycleProfile("install", &opts)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !errors.Is(err, errWindowsEnterpriseInvalidArguments) {
					t.Fatalf("err = %v, want invalid arguments %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if opts.trustMode != tc.wantMode || (tc.wantSigners != nil && !reflect.DeepEqual(opts.allowedSigners, tc.wantSigners)) {
				t.Fatalf("trust %q signers %q", opts.trustMode, opts.allowedSigners)
			}
			if tc.wantSigners != nil && windowsEnterpriseArgValue(windowsEnterprisePowerShellArgs("install", &opts), "-AllowedSigners") != strings.Join(tc.wantSigners, ",") {
				t.Fatal("configured signers did not reach the installer")
			}
		})
	}
	// A Secure Client config is untouched by trust keys.
	secureClient := filepath.Join(dir, "secure-client.yaml")
	if err := os.WriteFile(secureClient, []byte("deployment_mode: managed_enterprise\nenterprise:\n  trust:\n    mode: hash_pinned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := &windowsEnterpriseLifecycleOptions{configPath: secureClient}
	before := windowsEnterprisePowerShellArgs("install", opts)
	if err := resolveWindowsEnterpriseLifecycleProfile("install", opts); err != nil || opts.resolvedProfile != "secure_client" {
		t.Fatalf("Secure Client config: %q, %v", opts.resolvedProfile, err)
	}
	if after := windowsEnterprisePowerShellArgs("install", opts); !reflect.DeepEqual(before, after) {
		t.Fatalf("Secure Client arguments changed: %q -> %q", before, after)
	}

	// Without a payload manifest the installer re-admits a hash-pinned
	// deployment's payload by its recorded pins and keeps it hash-pinned, even
	// when --trust-mode is omitted or authenticode. mode authenticode therefore
	// refuses a mutation over such a deployment before any change, as it refuses
	// --trust-mode hash_pinned, whether the config is supplied or installed.
	t.Run("recorded hash-pinned deployment", func(t *testing.T) {
		stubWindowsEnterpriseDeployments(t, map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentInstalled})
		recorded := "hash_pinned"
		stubWindowsEnterpriseRecordedTrust(t, &recorded)
		dir := t.TempDir()
		authenticode := writeWindowsEnterpriseTrustConfig(t, dir, "authenticode.yaml", "  trust:\n    mode: authenticode\n")
		hashPinned := writeWindowsEnterpriseTrustConfig(t, dir, "hash.yaml", "  trust:\n    mode: hash_pinned\n")
		unset := writeWindowsEnterpriseTrustConfig(t, dir, "unset.yaml", "")
		refused := func(t *testing.T, action string, opts *windowsEnterpriseLifecycleOptions) {
			t.Helper()
			err := resolveWindowsEnterpriseLifecycleProfile(action, opts)
			if err == nil || !errors.Is(err, errWindowsEnterpriseInvalidArguments) ||
				!strings.Contains(err.Error(), "is hash_pinned") ||
				!strings.Contains(err.Error(), `install\deployment.json`) {
				t.Fatalf("%s: err = %v, want the recorded hash_pinned trust refused as invalid arguments", action, err)
			}
		}
		accepted := func(t *testing.T, action string, opts *windowsEnterpriseLifecycleOptions) {
			t.Helper()
			if err := resolveWindowsEnterpriseLifecycleProfile(action, opts); err != nil {
				t.Fatalf("%s: %v", action, err)
			}
		}

		for _, action := range []string{"install", "upgrade", "repair", "ensure"} {
			refused(t, action, &windowsEnterpriseLifecycleOptions{configPath: authenticode})
			refused(t, action, &windowsEnterpriseLifecycleOptions{configPath: authenticode, trustMode: "authenticode"})
		}
		// Read-only actions and uninstall bring no payload.
		for _, action := range []string{"status", "verify", "uninstall"} {
			accepted(t, action, &windowsEnterpriseLifecycleOptions{configPath: authenticode})
		}
		// A config that admits the hash-pinned deployment keeps working.
		accepted(t, "ensure", &windowsEnterpriseLifecycleOptions{configPath: hashPinned})
		accepted(t, "ensure", &windowsEnterpriseLifecycleOptions{configPath: unset})

		// The installed config applies to a remediation run without --config.
		windowsEnterpriseInstalledConfigPath = func() (string, error) { return authenticode, nil }
		refused(t, "ensure", &windowsEnterpriseLifecycleOptions{profile: "standalone"})
		refused(t, "repair", &windowsEnterpriseLifecycleOptions{profile: "standalone"})

		// An Authenticode deployment, or none recorded, is not refused.
		for _, trust := range []string{"authenticode", ""} {
			recorded = trust
			accepted(t, "ensure", &windowsEnterpriseLifecycleOptions{profile: "standalone"})
			accepted(t, "ensure", &windowsEnterpriseLifecycleOptions{configPath: authenticode})
		}
	})
}

// After a repair finished a pending transaction, a follow-up status probe
// that cannot read the host leaves the completed repair as the result.
func TestWindowsEnterpriseEnsureKeepsARepairWhenTheFollowUpProbeFails(t *testing.T) {
	pending := installedStatus("status")
	pending["transaction_pending"] = true
	refusal := "DefenseClaw enterprise installer rejected its module before import: transient"
	stub := &ensureStub{t: t, replies: []map[string]any{
		pending,
		installedStatus("repair"),
		{"schema_version": 1, "ok": false, "action": "status", "error": refusal, "errors": []string{refusal}},
	}}
	stub.install(t)
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	opts := ensureTestOptions()
	opts.noStart = false
	if err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`); err != nil {
		t.Fatalf("ensure: %v\n%s", err, stdout.String())
	}
	if len(stub.calls) != 3 || stub.calls[1][1] != "Repair" {
		t.Fatalf("installer runs %q", stub.calls)
	}
}

// The marker's TrustMode describes the deployment, not the run's request:
// the MDM scripts demand an Authenticode signature on the installed CLI
// when it reads authenticode.
func TestWindowsEnterpriseMarkerTrustModeFollowsTheDeployment(t *testing.T) {
	for _, tc := range []struct {
		name, requested, recorded, want string
	}{
		{"recorded hash_pinned wins over the authenticode default", "authenticode", "hash_pinned", "hash_pinned"},
		{"recorded authenticode wins over a hash_pinned request", "hash_pinned", "authenticode", "authenticode"},
		{"recorded value is normalized", "authenticode", " Hash_Pinned ", "hash_pinned"},
		{"no record falls back to the request", "hash_pinned", "", "hash_pinned"},
		{"an unrecognized record falls back to the request", "hash_pinned", "signed", "hash_pinned"},
		{"nothing known is authenticode", "", "", "authenticode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := &windowsEnterpriseLifecycleOptions{trustMode: tc.requested, deploymentTrustMode: tc.recorded}
			if got := windowsEnterpriseMarkerTrustMode(opts); got != tc.want {
				t.Fatalf("marker TrustMode = %q, want %q", got, tc.want)
			}
		})
	}
	if got := windowsEnterpriseMarkerTrustMode(nil); got != "authenticode" {
		t.Fatalf("nil options: %q", got)
	}
}

// The installed CLI (Remediate-Fix, Add/Remove Programs, an administrator)
// runs ensure and repair with no --trust-mode, which defaults to
// authenticode. On a hash-pinned deployment the marker it rewrites after a
// successful run must stay hash_pinned, or every later detect, remediation
// and uninstall refuses the unsigned CLI with untrusted_install.
func TestWindowsEnterpriseInstalledCLIKeepsAHashPinnedMarker(t *testing.T) {
	pinned := func(action string) map[string]any {
		reply := installedStatus(action)
		reply["trust_mode"] = "hash_pinned"
		return reply
	}
	failedVerify := pinned("verify")
	failedVerify["ok"] = false
	failedVerify["gateway_ready"] = false
	failedVerify["errors"] = []string{"gateway is not ready"}
	for _, tc := range []struct {
		name     string
		action   string
		replies  []map[string]any
		wantRuns []string
	}{
		{name: "compliant ensure", action: "ensure", replies: []map[string]any{pinned("status"), pinned("verify")}, wantRuns: []string{"Status", "Verify"}},
		{name: "ensure repairs a failed verify", action: "ensure", replies: []map[string]any{pinned("status"), failedVerify, pinned("repair")}, wantRuns: []string{"Status", "Verify", "Repair"}},
		{name: "repair", action: "repair", replies: []map[string]any{pinned("repair")}, wantRuns: []string{"Repair"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &ensureStub{t: t, replies: tc.replies}
			stub.install(t)
			markerTrust := ""
			windowsEnterpriseStandaloneObserver = func(result *enterprisestatus.Result, opts *windowsEnterpriseLifecycleOptions) string {
				if result.OK && result.Installed {
					markerTrust = windowsEnterpriseMarkerTrustMode(opts)
				}
				return ""
			}
			command := &cobra.Command{}
			var stdout bytes.Buffer
			command.SetOut(&stdout)
			command.SetErr(&bytes.Buffer{})
			opts := &windowsEnterpriseLifecycleOptions{
				profile: "standalone", resolvedProfile: "standalone", productVersion: "1.4.0",
				trustMode: "authenticode", jsonOutput: true,
			}
			script := `C:\stage\install-enterprise.ps1`
			var err error
			if tc.action == "ensure" {
				err = runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, script)
			} else {
				err = runWindowsEnterpriseStandaloneAction(context.Background(), command, tc.action, opts, script, windowsEnterprisePowerShellArgs(tc.action, opts))
			}
			if err != nil {
				t.Fatalf("%s: %v\n%s", tc.action, err, stdout.String())
			}
			var runs []string
			for _, call := range stub.calls {
				runs = append(runs, call[1])
			}
			if !reflect.DeepEqual(runs, tc.wantRuns) {
				t.Fatalf("installer runs %q, want %q", runs, tc.wantRuns)
			}
			if markerTrust != "hash_pinned" {
				t.Fatalf("marker TrustMode after %s = %q, want hash_pinned", tc.name, markerTrust)
			}
		})
	}
}

// A committed uninstall that could not act as some users (signed out, or not
// run as LocalSystem) says which DefenseClaw per-user registrations stay. A
// malformed forwarded value never hides the lifecycle's report.
func TestWindowsEnterpriseUninstallReportsTheUserRegistrationsItLeft(t *testing.T) {
	warnings := func(line string) []enterprisestatus.Message {
		t.Helper()
		report, err := parseWindowsEnterpriseInstallerReport([]byte(line))
		if err != nil {
			t.Fatalf("parse %s: %v", line, err)
		}
		result := enterprisestatus.New("uninstall", "standalone", "windows", "test")
		applyWindowsEnterpriseInstallerReport(result, nil, report, windowsEnterpriseStandaloneRun{})
		if len(result.Errors) != 0 {
			t.Fatalf("errors = %+v", result.Errors)
		}
		return result.Warnings
	}
	const base = `{"schema_version":1,"ok":true,"action":"Uninstall","installed":false,"transaction_pending":false`
	sid := "S-1-5-21-1000000000-2000000000-3000000000-1017"

	got := warnings(base + `,"user_registrations_removed":1,"user_registrations_pending":["devin/` + sid + `","hermes/` + sid +
		`"],"user_registrations_failed":["per-user registrations were not removed: requires the LocalSystem guardian service"]}`)
	if len(got) != 2 || got[0].Code != "user_registrations_pending" || got[1].Code != "user_registrations_failed" {
		t.Fatalf("warnings = %+v", got)
	}
	if !strings.Contains(got[0].Message, "2 user connector registration(s)") ||
		!strings.Contains(got[0].Message, "devin/"+sid+"; hermes/"+sid) ||
		!strings.Contains(got[1].Message, "requires the LocalSystem guardian service") {
		t.Fatalf("warnings = %+v", got)
	}

	if got := warnings(base + `,"user_registrations_removed":2,"user_registrations_pending":[],"user_registrations_failed":[]}`); len(got) != 0 {
		t.Fatalf("a complete cleanup warned: %+v", got)
	}
	if got := warnings(base + `}`); len(got) != 0 {
		t.Fatalf("a report without the cleanup fields warned: %+v", got)
	}
	if got := warnings(base + `,"user_registrations_pending":"amp/` + sid + `","user_registrations_failed":{"value":["x"],"Count":1}}`); len(got) != 1 ||
		!strings.Contains(got[0].Message, "1 user connector registration(s)") {
		t.Fatalf("lenient decoding: %+v", got)
	}

	many := make([]string, 25)
	for index := range many {
		many[index] = strconvQuote("opencode/" + sid + "-" + string(rune('a'+index)))
	}
	if got := warnings(base + `,"user_registrations_pending":[` + strings.Join(many, ",") + `]}`); len(got) != 1 ||
		!strings.Contains(got[0].Message, "25 user connector") || !strings.HasSuffix(got[0].Message, "; and 5 more") {
		t.Fatalf("bounded list: %+v", got)
	}
}

// A failed lifecycle that left its transaction pending names the exact
// recovery command, states a permission failure plainly (the internal detail
// stays in a lifecycle_diagnostic warning), and records which gateway the
// recovery ran and why.
func TestWindowsEnterpriseFailedLifecycleNamesTheRecoveryStep(t *testing.T) {
	internalDetail := `managed Windows DACL on C:\Users\alice\.defenseclaw\hooks has 2 ACEs, expected 7`
	failure := `managed-hook lifecycle snapshot retire failed: retire amp managed runtime generations for SID S-1-5-21-1-2-3-1017: ` + internalDetail
	document, err := json.Marshal(map[string]any{
		"schema_version": 1, "ok": false, "action": "repair",
		"error": failure, "errors": []string{failure},
		"transaction_pending": true,
		"recovery_gateway_refusal": map[string]string{
			"action": "retire", "code": "not_local_system", "message": "recovery runs the Setup gateway only as LocalSystem",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := parseWindowsEnterpriseInstallerReport(document)
	if err != nil {
		t.Fatal(err)
	}
	result := enterprisestatus.New("ensure", "standalone", "windows", "1.0.42")
	opts := &windowsEnterpriseLifecycleOptions{configPath: `C:\Staging\config.yaml`}
	applyWindowsEnterpriseInstallerReport(result, opts, report, windowsEnterpriseStandaloneRun{ExitCode: 1})
	if !result.TransactionPending || len(result.Errors) != 1 {
		t.Fatalf("result = %+v", result)
	}
	message := result.Errors[0].Message
	for _, want := range []string{
		`the permissions on C:\Users\alice\.defenseclaw\hooks are not the ones DefenseClaw set`,
		"Next step: run the same Setup as LocalSystem",
		`DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure CONFIG=C:\Staging\config.yaml JSON=1`,
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("error %q does not contain %q", message, want)
		}
	}
	if strings.Contains(message, "ACEs") || strings.Contains(message, "DACL") {
		t.Fatalf("error repeats internal detail: %q", message)
	}
	codes := map[string]string{}
	for _, warning := range result.Warnings {
		codes[warning.Code] = warning.Message
	}
	if !strings.Contains(codes["lifecycle_diagnostic"], internalDetail) || codes["recovery_gateway_not_used"] == "" {
		t.Fatalf("warnings = %+v", result.Warnings)
	}

	// A successful recovery records the gateway it ran once, even when ensure
	// applies the same report twice.
	success, err := json.Marshal(map[string]any{
		"schema_version": 1, "ok": true, "action": "install", "installed": true, "transaction_pending": false,
		"errors": []string{},
		"recovery_gateway_runs": []map[string]string{{
			"action": "retire", "binary": `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe`,
			"source": `C:\ProgramData\DefenseClaw-Enterprise-Setup-0f\defenseclaw-gateway.exe`,
			"sha256": strings.Repeat("c", 64), "trust": "hash_pinned", "identity": `NT AUTHORITY\SYSTEM`,
			"staged_error": failure, "outcome": "succeeded",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err = parseWindowsEnterpriseInstallerReport(success)
	if err != nil {
		t.Fatal(err)
	}
	result = enterprisestatus.New("ensure", "standalone", "windows", "1.0.42")
	addWindowsEnterpriseRecoveryGatewayWarnings(result, report)
	applyWindowsEnterpriseInstallerReport(result, opts, report, windowsEnterpriseStandaloneRun{})
	fallbacks := 0
	for _, warning := range result.Warnings {
		if warning.Code == "recovery_gateway_fallback" {
			fallbacks++
			if !strings.Contains(warning.Message, `binary C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe`) ||
				!strings.Contains(warning.Message, "trust hash_pinned") {
				t.Fatalf("fallback warning %q", warning.Message)
			}
		}
	}
	if fallbacks != 1 || len(result.Errors) != 0 {
		t.Fatalf("result = %+v", result)
	}

	// Status and verify keep their full detail and get no recovery step.
	result = enterprisestatus.New("verify", "standalone", "windows", "1.0.42")
	report, _ = parseWindowsEnterpriseInstallerReport(document)
	applyWindowsEnterpriseInstallerReport(result, opts, report, windowsEnterpriseStandaloneRun{ExitCode: 1})
	if result.Errors[0].Message != failure {
		t.Fatalf("verify error rewritten: %q", result.Errors[0].Message)
	}
}
