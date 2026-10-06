// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// withUnixManagedHostDescriptor points the managed-host guard at a trusted
// descriptor in a temporary directory and returns its path.
func withUnixManagedHostDescriptor(t *testing.T) string {
	t.Helper()
	descriptor := filepath.Join(t.TempDir(), "managed-runtime.json")
	if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	restore, restoreWindows, restoreTrust := managedHostDescriptorPath, managedHostWindowsStandalone, managedHostRecordTrusted
	managedHostDescriptorPath = func() string { return descriptor }
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	managedHostRecordTrusted = func(string) error { return nil }
	t.Cleanup(func() {
		managedHostDescriptorPath, managedHostWindowsStandalone, managedHostRecordTrusted = restore, restoreWindows, restoreTrust
	})
	t.Setenv(managed.DeploymentModeEnv, "")
	return descriptor
}

// unixPlatformForTest names this OS the way the `enterprise` group does.
func unixPlatformForTest() string {
	if runtime.GOOS == "darwin" {
		return "macos"
	}
	return "linux"
}

// withManagedHostCallerUID makes the guard see uid as the caller.
func withManagedHostCallerUID(t *testing.T, uid int) {
	t.Helper()
	restore := managedHostCallerUID
	managedHostCallerUID = func() int { return uid }
	t.Cleanup(func() { managedHostCallerUID = restore })
}

func unixStandaloneLayoutForTest(t *testing.T) managed.StandaloneLayout {
	t.Helper()
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		t.Skipf("no unix standalone layout on %s", runtime.GOOS)
	}
	return layout
}

// The refusal's hint must be a command that runs as typed: the package puts
// no DefenseClaw command on PATH and sudo's secure_path does not include the
// install directory. An administrator who runs start/stop/restart is told
// how to restart, repair and check the managed gateway service instead of
// the standard-user text.
func TestManagedHostRefusalNamesTheInstalledGatewayCommands(t *testing.T) {
	layout := unixStandaloneLayoutForTest(t)
	withUnixManagedHostDescriptor(t)
	gateway := layout.BinDir + "/defenseclaw-gateway"
	platform := unixPlatformForTest()

	withManagedHostCallerUID(t, 1000)
	err := refusePerUserGatewayOnManagedHost()
	if want := "`sudo " + gateway + " enterprise " + platform + " status`"; err == nil || !strings.Contains(err.Error(), want) ||
		strings.Contains(err.Error(), "`sudo defenseclaw-gateway ") {
		t.Fatalf("standard-user refusal = %v, want the absolute command %s", err, want)
	}

	withManagedHostCallerUID(t, 0)
	err = refusePerUserGatewayOnManagedHost()
	if err == nil {
		t.Fatal("a managed host allowed a per-user gateway for root")
	}
	restart := "systemctl restart defenseclaw-gateway.service"
	if runtime.GOOS == "darwin" {
		restart = "launchctl kickstart -k system/com.cisco.defenseclaw.gateway"
	}
	for _, want := range []string{
		"managed by your organization",
		"`" + restart + "`",
		"`" + gateway + " enterprise " + platform + " repair`",
		"`" + gateway + " enterprise " + platform + " status`",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("administrator refusal = %q, want %s", err, want)
		}
	}
	if strings.Contains(err.Error(), "an administrator can check") {
		t.Errorf("administrator refusal still addresses a standard user: %q", err)
	}
}

// The restart hint names the service the unix lifecycle installs.
func TestManagedHostServiceNamesMatchTheLifecycle(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve the test source path")
	}
	services, err := os.ReadFile(filepath.Join(filepath.Dir(source), "..", "enterpriseunix", "services.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{managedHostLinuxGatewayUnit, managedHostDarwinGatewayLabel} {
		if !strings.Contains(string(services), `"`+name+`"`) {
			t.Errorf("internal/enterpriseunix/services.go does not define the gateway service %q", name)
		}
	}
}

// On a managed host `defenseclaw-gateway stop` refuses like start and
// restart; it used to print "Watchdog is not running / Gateway sidecar is
// not running" and exit 0 while the managed gateway ran. A per-user watchdog
// left over from before the managed deployment is still stopped: it would
// keep trying to restart its gateway.
func TestStopRefusesOnAManagedHostAndStopsALeftoverWatchdog(t *testing.T) {
	unixStandaloneLayoutForTest(t)
	withUnixManagedHostDescriptor(t)
	withManagedHostCallerUID(t, 1000)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	stopped := 0
	previous := stopLeftoverWatchdogOnManagedHost
	stopLeftoverWatchdogOnManagedHost = func() { stopped++ }
	t.Cleanup(func() { stopLeftoverWatchdogOnManagedHost = previous })

	err := runStop(stopCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "managed by your organization") {
		t.Fatalf("stop on a managed host = %v, want the managed-host refusal", err)
	}
	if stopped != 1 {
		t.Fatalf("the leftover watchdog stop ran %d times, want once before the refusal", stopped)
	}
}

// The bare daemon refuses before loading config or opening the audit
// store, so a standard user's ~/.defenseclaw gets no audit.db.
func TestBareDaemonRefusesBeforeCreatingTheAuditStore(t *testing.T) {
	unixStandaloneLayoutForTest(t)
	withUnixManagedHostDescriptor(t)
	withManagedHostCallerUID(t, 1000)
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv(managed.ConfigPathEnv, "")
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("config_version: 8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousConfig, previousStore, previousLog := cfg, auditStore, auditLog
	t.Cleanup(func() {
		if auditStore != nil && auditStore != previousStore {
			_ = auditStore.Close()
		}
		cfg, auditStore, auditLog = previousConfig, previousStore, previousLog
	})

	err := rootPersistentPreRunE(rootCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "managed by your organization") {
		t.Fatalf("bare daemon pre-run = %v, want the managed-host refusal", err)
	}
	entries, readErr := os.ReadDir(home)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "audit.db") {
			t.Fatalf("the refused bare daemon created %s", filepath.Join(home, entry.Name()))
		}
	}
}

// A deployment pin set by hand does not get a standard user past the
// refusal; only the managed service account's pin counts, and the service
// uid comes from the descriptor. Unknown service identity keeps honoring the
// pin.
func TestLifecycleGuardHonorsThePinOnlyForTheServiceAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-runtime.json")
	descriptor := `{"schema_version":1,"profile":"standalone","product_version":"1.0.0","service_user":"defenseclaw",` +
		`"service_uid":987,"service_gid":987,"api_addr":"127.0.0.1:18970","machine_policy_connectors":[],` +
		`"disable_self_update":true,"installed_at":"2026-09-27T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(descriptor), 0o644); err != nil {
		t.Fatal(err)
	}
	if uid, ok := managedHostServiceUID(path); !ok || uid != 987 {
		t.Fatalf("managedHostServiceUID = %d, %t; want 987, true", uid, ok)
	}

	unixStandaloneLayoutForTest(t)
	withUnixManagedHostDescriptor(t)
	restoreService := managedHostServiceUID
	t.Cleanup(func() { managedHostServiceUID = restoreService })
	managedHostServiceUID = func(string) (int, bool) { return 991, true }
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)

	withManagedHostCallerUID(t, 1000)
	if err := refuseGatewayLifecycleOnManagedHost(); err == nil || !strings.Contains(err.Error(), "managed by your organization") {
		t.Fatalf("standard user with a hand-set pin = %v, want the managed-host refusal", err)
	}
	withManagedHostCallerUID(t, 0)
	if err := refuseGatewayLifecycleOnManagedHost(); err == nil || !strings.Contains(err.Error(), "restart it with") {
		t.Fatalf("administrator with a hand-set pin = %v, want the administrator refusal", err)
	}
	withManagedHostCallerUID(t, 991)
	if err := refuseGatewayLifecycleOnManagedHost(); err != nil {
		t.Fatalf("the managed gateway service was refused: %v", err)
	}
	managedHostServiceUID = func(string) (int, bool) { return 0, false }
	withManagedHostCallerUID(t, 1000)
	if err := refuseGatewayLifecycleOnManagedHost(); err != nil {
		t.Fatalf("an unknown service identity must keep honoring the pin: %v", err)
	}
	// The Secure Client per-user refusal is unchanged.
	if err := refusePerUserGatewayOnManagedHost(); err != nil {
		t.Fatalf("the pinned per-user guard changed: %v", err)
	}
}

// withManagedStandaloneDeployment makes the admin commands see a trusted
// standalone deployment whose paths live in a temporary directory, and
// clears the environment the admin defaults set.
func withManagedStandaloneDeployment(t *testing.T, serviceUID int) managed.StandaloneLayout {
	t.Helper()
	root := t.TempDir()
	layout := managed.StandaloneLayout{
		GOOS:            runtime.GOOS,
		ConfigPath:      filepath.Join(root, "etc", "config.yaml"),
		ManifestPath:    filepath.Join(root, "etc", "hook-guardian", "targets.yaml"),
		DescriptorPath:  filepath.Join(root, "etc", "managed-runtime.json"),
		DataDir:         filepath.Join(root, "runtime"),
		GuardianAuthDir: filepath.Join(root, "hook-guardian-state"),
		ServiceUser:     "defenseclaw",
	}
	restore := managedStandaloneAdminDeployment
	managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return layout, &managed.RuntimeDescriptor{Profile: managed.ProfileStandalone, ServiceUID: serviceUID}, nil
	}
	t.Cleanup(func() { managedStandaloneAdminDeployment = restore })
	for _, key := range managedStandaloneAdminEnvKeys {
		t.Setenv(key, "")
	}
	return layout
}

var managedStandaloneAdminEnvKeys = []string{
	managed.ConfigPathEnv, "DEFENSECLAW_HOME", managed.DeploymentModeEnv,
	managed.EnterpriseProfileEnv, managed.HookGuardianAuthorizationDirEnv,
}

func clearManagedStandaloneAdminEnv(t *testing.T) {
	t.Helper()
	for _, key := range managedStandaloneAdminEnvKeys {
		if err := os.Setenv(key, ""); err != nil {
			t.Fatal(err)
		}
	}
}

// An administrator's status, audit and enterprise hooks commands read the
// standalone deployment without extra environment variables; root used to
// read /root/.defenseclaw/config.yaml.
func TestManagedStandaloneAdminEnvPointsAdministratorsAtTheDeployment(t *testing.T) {
	layout := withManagedStandaloneDeployment(t, 991)
	want := map[string]string{
		managed.ConfigPathEnv:                   layout.ConfigPath,
		"DEFENSECLAW_HOME":                      layout.DataDir,
		managed.DeploymentModeEnv:               managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv:            managed.ProfileStandalone,
		managed.HookGuardianAuthorizationDirEnv: layout.GuardianAuthDir,
	}
	for _, uid := range []int{0, 991} {
		clearManagedStandaloneAdminEnv(t)
		withManagedHostCallerUID(t, uid)
		if !applyManagedStandaloneAdminEnv(nil) {
			t.Fatalf("uid %d: the admin defaults were not applied", uid)
		}
		for key, value := range want {
			if got := os.Getenv(key); got != value {
				t.Errorf("uid %d: %s = %q, want %q", uid, key, got, value)
			}
		}
	}

	clearManagedStandaloneAdminEnv(t)
	withManagedHostCallerUID(t, 1000)
	if applyManagedStandaloneAdminEnv(nil) || os.Getenv(managed.ConfigPathEnv) != "" {
		t.Fatal("a standard user was pointed at the administrator-owned deployment")
	}

	clearManagedStandaloneAdminEnv(t)
	withManagedHostCallerUID(t, 0)
	t.Setenv(managed.ConfigPathEnv, "/srv/custom/config.yaml")
	if applyManagedStandaloneAdminEnv(nil) || os.Getenv(managed.ConfigPathEnv) != "/srv/custom/config.yaml" ||
		os.Getenv("DEFENSECLAW_HOME") != "" {
		t.Fatal("the admin defaults replaced a config the caller chose")
	}

	// No trusted standalone deployment: nothing changes for anyone.
	clearManagedStandaloneAdminEnv(t)
	managedStandaloneAdminDeployment = func() (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{}, nil, managed.ErrNoRuntimeDescriptor
	}
	if applyManagedStandaloneAdminEnv(nil) || os.Getenv(managed.ConfigPathEnv) != "" {
		t.Fatal("a host without a standalone deployment got the managed defaults")
	}
}

// policy show and policy validate are administrator commands on a managed
// host: as root they read the standalone deployment, as policy digest does.
// They used to read /var/root/.defenseclaw/config.yaml, fail, and tell the
// administrator to run the same command with sudo.
func TestPolicyShowAndValidateReadTheManagedDeploymentAsAdministrator(t *testing.T) {
	layout := withManagedStandaloneDeployment(t, 991)
	previous := cfg
	t.Cleanup(func() { cfg = previous })
	for _, command := range []*cobra.Command{policyShowCmd, policyValidateCmd} {
		clearManagedStandaloneAdminEnv(t)
		withManagedHostCallerUID(t, 0)
		if command.PersistentPreRunE == nil {
			t.Fatalf("policy %s inherits the per-user pre-run", command.Name())
		}
		// The temporary layout holds no config.yaml, so the load itself fails;
		// the pin it was aimed at is what this checks.
		_ = command.PersistentPreRunE(command, nil)
		if got := os.Getenv(managed.ConfigPathEnv); got != layout.ConfigPath {
			t.Errorf("policy %s read %q, want the managed config %q", command.Name(), got, layout.ConfigPath)
		}
	}
}

// The guardian manifest and authorization directory come from this OS's
// layout for a standalone config; `enterprise hooks status` on macOS used
// to default to the Linux manifest and a data-dir-derived authorization
// directory and reported a healthy host as unhealthy.
func TestStandaloneHookGuardianDefaultsUseTheLayout(t *testing.T) {
	layout, err := managed.StandaloneLayoutFor("darwin")
	if err != nil {
		t.Fatal(err)
	}
	previous := cfg
	t.Cleanup(func() { cfg = previous })
	standalone := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: layout.DataDir}
	standalone.Enterprise.Profile = managed.ProfileStandalone
	cfg = standalone
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, "")

	newCommand := func(defaultManifest string) (*cobra.Command, *string) {
		manifest := new(string)
		cmd := &cobra.Command{Use: "status"}
		cmd.Flags().StringVar(manifest, "manifest", defaultManifest, "")
		return cmd, manifest
	}
	status, manifest := newCommand(defaultEnterpriseHookManifest)
	applyStandaloneHookGuardianLayout(status, layout)
	if *manifest != layout.ManifestPath {
		t.Errorf("status --manifest = %q, want %q", *manifest, layout.ManifestPath)
	}
	if got := os.Getenv(managed.HookGuardianAuthorizationDirEnv); got != layout.GuardianAuthDir {
		t.Errorf("%s = %q, want %q", managed.HookGuardianAuthorizationDirEnv, got, layout.GuardianAuthDir)
	}
	enumerate, enumerateManifest := newCommand("")
	applyStandaloneHookGuardianLayout(enumerate, layout)
	if *enumerateManifest != layout.ManifestPath {
		t.Errorf("enumerate --manifest = %q, want %q", *enumerateManifest, layout.ManifestPath)
	}

	explicit, explicitManifest := newCommand(defaultEnterpriseHookManifest)
	if err := explicit.Flags().Set("manifest", "/srv/targets.yaml"); err != nil {
		t.Fatal(err)
	}
	applyStandaloneHookGuardianLayout(explicit, layout)
	if *explicitManifest != "/srv/targets.yaml" {
		t.Errorf("an explicit --manifest was replaced with %q", *explicitManifest)
	}

	// The Secure Client profile keeps its explicit service arguments.
	secureClient := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: layout.DataDir}
	cfg = secureClient
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, "")
	other, otherManifest := newCommand(defaultEnterpriseHookManifest)
	applyStandaloneHookGuardianLayout(other, layout)
	if *otherManifest != defaultEnterpriseHookManifest || os.Getenv(managed.HookGuardianAuthorizationDirEnv) != "" {
		t.Error("a Secure Client config got the standalone guardian defaults")
	}
}

// A standard user's `enterprise hooks status` on a managed host explains
// that an administrator runs it, instead of a raw per-user config-load
// error. Administrators, the service account, callers that name a config
// and the per-user worker keep the ordinary path.
func TestEnterpriseHooksTellAStandardUserThatAnAdministratorRunsThem(t *testing.T) {
	layout := withManagedStandaloneDeployment(t, 991)
	previousConfig := cfg
	t.Cleanup(func() { cfg = previousConfig })
	previousFull, previousConfigOnly := enterpriseHooksFullRootPersistentPreRun, enterpriseHooksConfigOnlyPersistentPreRun
	t.Cleanup(func() {
		enterpriseHooksFullRootPersistentPreRun, enterpriseHooksConfigOnlyPersistentPreRun = previousFull, previousConfigOnly
	})
	loaded := 0
	enterpriseHooksFullRootPersistentPreRun = func(*cobra.Command, []string) error { loaded++; return nil }
	enterpriseHooksConfigOnlyPersistentPreRun = func(*cobra.Command, []string) error { loaded++; return nil }

	withManagedHostCallerUID(t, 1000)
	err := enterpriseHooksNativePersistentPreRun(enterpriseHooksStatusCmd, nil)
	if err == nil {
		t.Fatal("a standard user's enterprise hooks status was not refused")
	}
	for _, want := range []string{"managed by your organization", layout.DescriptorPath, "`sudo ", "/defenseclaw-gateway enterprise hooks status`"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal = %q, want %q", err, want)
		}
	}
	if loaded != 0 {
		t.Fatal("the refused command still loaded a config")
	}

	for _, uid := range []int{0, 991} {
		clearManagedStandaloneAdminEnv(t)
		withManagedHostCallerUID(t, uid)
		if err := enterpriseHooksNativePersistentPreRun(enterpriseHooksStatusCmd, nil); err != nil {
			t.Fatalf("uid %d was refused: %v", uid, err)
		}
	}

	clearManagedStandaloneAdminEnv(t)
	withManagedHostCallerUID(t, 1000)
	t.Setenv(managed.ConfigPathEnv, "/srv/custom/config.yaml")
	if err := enterpriseHooksNativePersistentPreRun(enterpriseHooksStatusCmd, nil); err != nil {
		t.Fatalf("a standard user who named a config was refused: %v", err)
	}
	t.Setenv(managed.ConfigPathEnv, "")
	if err := enterpriseHooksNativePersistentPreRun(enterpriseHooksApplyTargetCmd, nil); err != nil {
		t.Fatalf("the per-user worker was refused: %v", err)
	}
}
