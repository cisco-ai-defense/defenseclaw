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

package enterpriseunix

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// restrictPolicyViewsConfig is the default managed config with the
// administrator's opt-in to the host-wide kernel restriction.
func restrictPolicyViewsConfig(t *testing.T, h *testHost) string {
	t.Helper()
	const anchor = "enterprise:\n  profile: standalone\n"
	defaults := string(DefaultConfig(h.env.Layout))
	if !strings.Contains(defaults, anchor) {
		t.Fatalf("default config has no %q block", anchor)
	}
	body := strings.Replace(defaults, anchor, anchor+"  machine_policy:\n    linux:\n      namespaces_and_ptrace: restrict\n", 1)
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// writeKernelSetting writes one fake /proc/sys value (or other host file).
func writeKernelSetting(t *testing.T, h *testHost, canonical, value string) {
	t.Helper()
	writeHostFile(t, h, canonical, value)
}

// restrictKernelBeforeThisBoot gives h the state DefenseClaw's restriction
// leaves after a reboot: both live settings closed, the persistent file in
// place, and both markers naming an earlier boot.
func restrictKernelBeforeThisBoot(t *testing.T, h *testHost) {
	t.Helper()
	writeKernelSetting(t, h, sysctlMaxUserNamespaces, "0\n")
	writeKernelSetting(t, h, sysctlPtraceScope, "2\n")
	writeKernelSetting(t, h, userNamespaceBootIDPath, "boot-before\n")
	writeKernelSetting(t, h, userNamespacesConfigPath, string(userNamespacesConfig))
	for _, marker := range []string{userNamespaceBootMarker, ptraceBootMarker} {
		if err := os.WriteFile(h.env.P(marker), []byte("boot-prior\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// restrictedHost is a Linux host restricted before this boot, with the
// config that keeps it restricted for the first install (later runs reuse
// the installed config).
func restrictedHost(t *testing.T) (*testHost, string) {
	t.Helper()
	h := newTestHost(t, "linux")
	restrictKernelBeforeThisBoot(t, h)
	return h, restrictPolicyViewsConfig(t, h)
}

// openKernel leaves h as stock RHEL 9 ships: user namespaces and
// same-user ptrace open, no DefenseClaw sysctl file and no markers.
func openKernel(t *testing.T, h *testHost) {
	t.Helper()
	writeKernelSetting(t, h, sysctlMaxUserNamespaces, "63229\n")
	writeKernelSetting(t, h, sysctlPtraceScope, "0\n")
	writeKernelSetting(t, h, userNamespaceBootIDPath, "boot-before\n")
}

// requireKernelUntouched fails when a default (leave) deployment changed a
// host-wide kernel setting or wrote any of the restriction's files: the
// restriction stops required sandboxes and is the administrator's choice.
func requireKernelUntouched(t *testing.T, h *testHost, label string) {
	t.Helper()
	if got := h.read(sysctlMaxUserNamespaces); got != "63229\n" {
		t.Fatalf("%s changed user.max_user_namespaces to %q without the administrator's opt-in", label, got)
	}
	if got := h.read(sysctlPtraceScope); got != "0\n" {
		t.Fatalf("%s changed kernel.yama.ptrace_scope to %q without the administrator's opt-in", label, got)
	}
	for _, path := range []string{userNamespacesConfigPath, userNamespaceBootMarker, ptraceBootMarker, userNamespaceUninstalled} {
		if _, err := os.Stat(h.env.P(path)); !os.IsNotExist(err) {
			t.Fatalf("%s wrote %s without the administrator's opt-in (err=%v)", label, path, err)
		}
	}
	if record, err := h.env.loadDeployment(); err == nil && record != nil && record.Files[userNamespacesConfigPath] != "" {
		t.Fatalf("%s tracks the managed sysctl file without the opt-in", label)
	}
}

// By default a managed Linux install leaves user namespaces and ptrace as
// the host has them: the restriction broke Codex's workspace sandbox,
// RootlessKit and OpenShell Docker sandboxes on managed RHEL. verify names
// the open routes and the opt-in instead, as the 1.0.3 release did for user
// namespaces, and a later ensure stays a no-op.
func TestLinuxDefaultConfigLeavesKernelSettingsAlone(t *testing.T) {
	h := newTestHost(t, "linux")
	openKernel(t, h)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4")}))
	requireKernelUntouched(t, h, "install")
	status := h.run(Options{Action: ActionStatus})
	if hasMessageCode(status.Errors, codeUserNamespaces) || hasMessageCode(status.Errors, codeUnprivilegedPtrace) {
		t.Fatalf("status failed a default deployment on host kernel settings: %+v", status.Errors)
	}
	if status.SecurityComplete || !hasWarning(status, codeUserNamespaces) || !hasWarning(status, codeUnprivilegedPtrace) {
		t.Fatalf("status hid the open policy-view routes: security_complete=%v warnings=%+v", status.SecurityComplete, status.Warnings)
	}
	verify := h.run(Options{Action: ActionVerify})
	if hasMessageCode(verify.Errors, codeUserNamespaces) || hasMessageCode(verify.Errors, codeUnprivilegedPtrace) {
		t.Fatalf("verify failed a default deployment on host kernel settings: %+v", verify.Errors)
	}
	for _, code := range []string{codeUserNamespaces, codeUnprivilegedPtrace} {
		if !hasWarning(verify, code) {
			t.Fatalf("verify did not warn %s on an open host: %+v", code, verify.Warnings)
		}
	}
	if verify.SecurityComplete {
		t.Fatal("verify reported complete security while a process can hide machine policy")
	}
	for _, warning := range verify.Warnings {
		if (warning.Code == codeUserNamespaces || warning.Code == codeUnprivilegedPtrace) &&
			!strings.Contains(warning.Message, "namespaces_and_ptrace: restrict") {
			t.Fatalf("%s warning does not name the opt-in: %q", warning.Code, warning.Message)
		}
	}
	again := h.run(Options{Action: ActionEnsure})
	requireOK(t, again)
	if !again.Noop {
		t.Fatalf("ensure of an unchanged default deployment was not a no-op: %+v", again)
	}
	requireKernelUntouched(t, h, "ensure")
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	requireKernelUntouched(t, h, "uninstall")

	// A host whose administrator closed both routes gets no warning.
	closed := newTestHost(t, "linux")
	writeKernelSetting(t, closed, sysctlMaxUserNamespaces, "0\n")
	writeKernelSetting(t, closed, sysctlPtraceScope, "3\n")
	requireOK(t, closed.run(Options{Action: ActionInstall, PayloadDir: closed.payload("1.0.4")}))
	verify = closed.run(Options{Action: ActionVerify})
	if hasWarning(verify, codeUserNamespaces) || hasWarning(verify, codeUnprivilegedPtrace) {
		t.Fatalf("verify warned on a host the administrator closed: %+v", verify.Warnings)
	}
	if got := closed.read(sysctlPtraceScope); got != "3\n" {
		t.Fatalf("a default install changed the administrator's ptrace scope: %q", got)
	}
}

func TestLinuxOpenPolicyViewStatusCannotClaimUnreadableKernelSettings(t *testing.T) {
	h := newTestHost(t, "linux")
	openKernel(t, h)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4")}))
	for _, path := range []string{sysctlMaxUserNamespaces, sysctlPtraceScope} {
		if err := os.Remove(h.env.P(path)); err != nil {
			t.Fatal(err)
		}
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		if result.SecurityComplete || !hasWarning(result, codeUserNamespaces) || !hasWarning(result, codeUnprivilegedPtrace) {
			t.Fatalf("%s claimed protection without readable kernel settings: %+v", action, result)
		}
	}
}

// Closing both live settings during this boot cannot rule out namespaces and
// tracers that were already running when the restriction was applied. That
// remains true after the administrator changes the deployment back to leave.
func TestLinuxLeaveModeKeepsSameBootRestrictionWarning(t *testing.T) {
	h := newTestHost(t, "linux")
	openKernel(t, h)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4")}))
	restricted := h.run(Options{Action: ActionEnsure, ConfigFile: restrictPolicyViewsConfig(t, h)})
	if !restricted.Installed || restricted.SecurityComplete {
		t.Fatalf("opt-in did not require a reboot: %+v", restricted)
	}
	leave := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(leave, DefaultConfig(h.env.Layout), 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: leave}))
	if got := h.read(sysctlMaxUserNamespaces); got != "0\n" {
		t.Fatalf("opt-out unexpectedly changed the live namespace limit: %q", got)
	}
	if got := h.read(sysctlPtraceScope); got != "2\n" {
		t.Fatalf("opt-out unexpectedly changed the live ptrace scope: %q", got)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if r.SecurityComplete || !hasWarning(r, codeUserNamespaces) || !hasWarning(r, codeUnprivilegedPtrace) {
			t.Fatalf("%s hid surviving same-boot namespaces or tracers: %+v", action, r)
		}
	}
	writeKernelSetting(t, h, userNamespaceBootIDPath, "boot-after\n")
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if hasWarning(r, codeUserNamespaces) || hasWarning(r, codeUnprivilegedPtrace) {
			t.Fatalf("%s kept the same-boot warning after a later boot: %+v", action, r.Warnings)
		}
	}
}

// An aborted opt-in from leave must restore the host's live kernel settings
// along with its deployment. The fault is after both sysctls were written.
func TestLinuxFailedOptInRestoresLiveKernelSettings(t *testing.T) {
	h := newTestHost(t, "linux")
	openKernel(t, h)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4")}))
	setLifecycleTestFault(t, h, testFaultAfterServices)
	failed := h.run(Options{Action: ActionEnsure, ConfigFile: restrictPolicyViewsConfig(t, h)})
	if failed.OK || !hasWarning(failed, codeRolledBack) {
		t.Fatalf("opt-in did not roll back: %+v", failed)
	}
	if got := h.read(sysctlMaxUserNamespaces); got != "63229\n" {
		t.Fatalf("rollback kept the uncommitted namespace restriction: %q", got)
	}
	if got := h.read(sysctlPtraceScope); got != "0\n" {
		t.Fatalf("rollback kept the uncommitted ptrace restriction: %q", got)
	}
	if _, err := os.Stat(h.env.P(userNamespacesConfigPath)); !os.IsNotExist(err) {
		t.Fatalf("rollback kept the persistent restriction: %v", err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if r.SecurityComplete || !hasWarning(r, codeUserNamespaces) || !hasWarning(r, codeUnprivilegedPtrace) {
			t.Fatalf("%s hid the open routes after rollback: %+v", action, r)
		}
	}
}

func TestLinuxRolledBackOptInOnClosedHostNeedsLaterBoot(t *testing.T) {
	h := newTestHost(t, "linux")
	writeKernelSetting(t, h, sysctlMaxUserNamespaces, "0\n")
	writeKernelSetting(t, h, sysctlPtraceScope, "2\n")
	writeKernelSetting(t, h, userNamespaceBootIDPath, "boot-before\n")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4")}))
	setLifecycleTestFault(t, h, testFaultAfterServices)
	failed := h.run(Options{Action: ActionEnsure, ConfigFile: restrictPolicyViewsConfig(t, h)})
	if failed.OK || !hasWarning(failed, codeRolledBack) {
		t.Fatalf("opt-in did not roll back: %+v", failed)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if r.SecurityComplete || !hasWarning(r, codeUserNamespaces) || !hasWarning(r, codeUnprivilegedPtrace) {
			t.Fatalf("%s hid the current-boot opt-in after rollback: %+v", action, r)
		}
	}
	writeKernelSetting(t, h, userNamespaceBootIDPath, "boot-after\n")
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if hasWarning(r, codeUserNamespaces) || hasWarning(r, codeUnprivilegedPtrace) {
			t.Fatalf("%s kept an obsolete boot warning: %+v", action, r.Warnings)
		}
	}
}

func TestLinuxRollbackReportsLiveSettingItCannotRestore(t *testing.T) {
	h := newTestHost(t, "linux")
	openKernel(t, h)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4")}))
	// Model an administrator raising ptrace_scope to 3 after opt-in wrote 2.
	// A rollback cannot lower it again, so it must keep the stricter value
	// and say that the host-wide setting was not restored.
	h.env.Services = &hookedServices{
		fakeServices: h.services,
		onStart:      writeOnce(t, h, unitGateway, sysctlPtraceScope, []byte("3\n")),
	}
	setLifecycleTestFault(t, h, testFaultAfterServices)
	failed := h.run(Options{Action: ActionEnsure, ConfigFile: restrictPolicyViewsConfig(t, h)})
	if failed.OK || !hasMessageCode(failed.Errors, codeRollbackFailed) ||
		!strings.Contains(messagesOf(failed.Errors, codeRollbackFailed), sysctlPtraceScope) {
		t.Fatalf("rollback did not report the live setting it could not restore: %+v", failed)
	}
	if got := h.read(sysctlMaxUserNamespaces); got != "63229\n" {
		t.Fatalf("rollback did not restore the independent namespace setting: %q", got)
	}
	if got := h.read(sysctlPtraceScope); got != "3\n" {
		t.Fatalf("rollback overwrote the administrator's stricter ptrace scope: %q", got)
	}
}

// A failed machine-policy removal keeps the deployment and its sysctl file.
// It has not uninstalled the restriction, so it must not spend boot proof.
func TestLinuxAbortedUninstallKeepsRestrictionBootProof(t *testing.T) {
	h, cfg := restrictedHost(t)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg}))
	fail := true
	h.env.MachinePolicy = failingRemovePolicy{MachinePolicyManager: h.env.MachinePolicy, fail: &fail}
	failed := h.run(Options{Action: ActionUninstall, Purge: true})
	if !hasMessageCode(failed.Errors, codeUninstallIncomplete) || !exists(h.env.P(userNamespacesConfigPath)) || !exists(h.env.deploymentPath()) {
		t.Fatalf("uninstall did not stop with the restriction intact: %+v", failed)
	}
	if _, err := os.Stat(h.env.P(userNamespaceUninstalled)); !os.IsNotExist(err) {
		t.Fatalf("aborted uninstall recorded a removed restriction: %v", err)
	}
	writeKernelSetting(t, h, userNamespaceBootIDPath, "boot-after\n")
	h.env.ProductVersion = "1.0.5"
	upgraded := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.5")})
	if !upgraded.Installed {
		t.Fatalf("upgrade after aborted uninstall failed: %+v", upgraded)
	}
	requireProvenBoot(t, h, "upgrade after aborted uninstall", upgraded, "boot-prior\n")
}

func TestLinuxFailedSysctlFileRemovalDoesNotRecordUninstall(t *testing.T) {
	h, cfg := restrictedHost(t)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg}))
	path := h.env.P(userNamespacesConfigPath)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "held"), 0o700); err != nil {
		t.Fatal(err)
	}
	failed := h.run(Options{Action: ActionUninstall, Purge: true})
	if failed.OK || !exists(path) {
		t.Fatalf("uninstall unexpectedly removed the persistent path: %+v", failed)
	}
	if _, err := os.Stat(h.env.P(userNamespaceUninstalled)); !os.IsNotExist(err) {
		t.Fatalf("failed sysctl removal recorded an uninstall: %v", err)
	}
}

// Upgrades from every released 1.0.x keep the host's kernel settings with
// the default config. An administrator who later opts in gets the
// restriction and the reboot requirement; opting out again removes the
// managed sysctl file and stops failing status.
func TestLinuxUpgradeFromReleasesLeavesKernelUntilOptIn(t *testing.T) {
	for _, version := range []string{"1.0.0", "1.0.1", "1.0.2", "1.0.3"} {
		t.Run(version, func(t *testing.T) {
			h := newTestHost(t, "linux")
			openKernel(t, h)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload(version)}))
			h.env.ProductVersion = "1.0.4"
			requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.4")}))
			requireKernelUntouched(t, h, "upgrade from "+version)
			if status := h.run(Options{Action: ActionStatus}); hasMessageCode(status.Errors, codeUserNamespaces) || hasMessageCode(status.Errors, codeUnprivilegedPtrace) {
				t.Fatalf("status failed the upgraded default deployment: %+v", status.Errors)
			}

			restrict := restrictPolicyViewsConfig(t, h)
			opted := h.run(Options{Action: ActionEnsure, ConfigFile: restrict})
			if !opted.Installed || opted.SecurityComplete || !hasMessageCode(opted.Errors, codeUserNamespaces) {
				t.Fatalf("opt-in did not restrict the host and require a reboot: %+v", opted)
			}
			if h.read(sysctlMaxUserNamespaces) != "0\n" || h.read(sysctlPtraceScope) != "2\n" ||
				h.read(userNamespacesConfigPath) != string(userNamespacesConfig) {
				t.Fatal("opt-in did not apply and persist both restrictions")
			}
			writeKernelSetting(t, h, userNamespaceBootIDPath, "boot-after\n")
			if status := h.run(Options{Action: ActionStatus}); hasMessageCode(status.Errors, codeUserNamespaces) {
				t.Fatalf("opt-in stayed incomplete after reboot: %+v", status.Errors)
			}

			leave := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(leave, DefaultConfig(h.env.Layout), 0o600); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: leave}))
			if _, err := os.Stat(h.env.P(userNamespacesConfigPath)); !os.IsNotExist(err) {
				t.Fatalf("opting out kept the managed sysctl file: %v", err)
			}
			if record, err := h.env.loadDeployment(); err != nil || record.Files[userNamespacesConfigPath] != "" {
				t.Fatalf("opting out still tracks the managed sysctl file: err=%v", err)
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				if r := h.run(Options{Action: action}); hasMessageCode(r.Errors, codeUserNamespaces) || hasMessageCode(r.Errors, codeUnprivilegedPtrace) {
					t.Fatalf("%s failed after opting out: %+v", action, r.Errors)
				}
			}
		})
	}
}

// A package run whose restriction could not be applied rolled back to the
// previous deployment, which restricts nothing. Status and verify must keep
// naming that failure (GAP-0469) instead of reading the namespace error as
// a reboot the committed package waits for.
func TestLinuxRolledBackRestrictionStaysAPackageFailure(t *testing.T) {
	h := packageHost(t, "1.0.3")
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true, Reason: "package"}))
	// No /proc/sys/user/max_user_namespaces: the opt-in cannot be applied.
	failed := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package", ConfigFile: restrictPolicyViewsConfig(t, h)})
	if failed.OK || !failed.Installed || !hasMessageCode(failed.Errors, codeUserNamespaces) || !hasWarning(failed, codeRolledBack) {
		t.Fatalf("want a rolled-back namespace failure: %+v", failed)
	}
	raw, err := json.Marshal(failed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.env.P(h.env.Layout.LifecycleDir), lastPackageResultFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if failure := h.env.lastPackageInstallFailure(); !strings.HasPrefix(failure, codeUserNamespaces+": ") {
		t.Fatalf("rolled-back package failure hidden as a pending reboot: %q", failure)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		if r := h.run(Options{Action: action}); !hasWarning(r, codePackageInstallFailed) {
			t.Fatalf("%s hid the rolled-back package failure: %+v", action, r.Warnings)
		}
	}
}

// Only a committed run (installed, nothing rolled back) whose errors are all
// the pending-reboot namespace errors is not a package failure.
func TestLastPackageInstallFailureOnlyIgnoresCommittedReboot(t *testing.T) {
	const (
		userns   = `{"code":"unprivileged_user_namespaces","message":"reboot this host"}`
		fault    = `{"code":"lifecycle_test_fault","message":"apply failed"}`
		rollback = `{"code":"rollback_failed","message":"snapshot kept"}`
	)
	for name, tc := range map[string]struct {
		installed bool
		errors    string
		warnings  string
		want      string
	}{
		"committed pending reboot":     {true, userns, `{"code":"security_incomplete","message":"reboot pending"}`, ""},
		"committed without warnings":   {true, userns, ``, ""},
		"rolled back":                  {true, userns, `{"code":"rolled_back","message":"restored the previous deployment"}`, "unprivileged_user_namespaces: reboot this host"},
		"rollback failed warning":      {true, userns, `{"code":"rollback_failed","message":""}`, "unprivileged_user_namespaces: reboot this host"},
		"rollback failed error":        {true, userns + "," + rollback, ``, "rollback_failed: snapshot kept"},
		"mixed errors":                 {true, userns + "," + fault, ``, "lifecycle_test_fault: apply failed"},
		"rolled back mixed errors":     {true, userns + "," + fault, `{"code":"rolled_back","message":""}`, "lifecycle_test_fault: apply failed"},
		"first install did not commit": {false, userns, ``, "unprivileged_user_namespaces: reboot this host"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			dir := h.env.P(h.env.Layout.LifecycleDir)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			doc := fmt.Sprintf(`{"ok":false,"installed":%t,"action":"ensure","errors":[%s],"warnings":[%s]}`, tc.installed, tc.errors, tc.warnings)
			if err := os.WriteFile(filepath.Join(dir, lastPackageResultFile), []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := h.env.lastPackageInstallFailure(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A private mount namespace can hide every managed connector's policy from
// an agent. With the administrator's opt-in the Linux host setting must be
// applied before an agent can run, and status must stop reporting a
// complete deployment if it is loosened.
func TestLinuxManagedUserNamespacesAreDisabledAndDetected(t *testing.T) {
	h, cfg := restrictedHost(t)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg}))
	if got := h.read(sysctlMaxUserNamespaces); got != "0\n" {
		t.Fatalf("install left user namespaces enabled: %q", got)
	}
	if got := h.read(userNamespacesConfigPath); got != string(userNamespacesConfig) {
		t.Fatalf("install did not persist the restriction: %q", got)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if hasMessageCode(r.Errors, codeUserNamespaces) {
			t.Fatalf("%s rejects a restricted host: %+v", action, r.Errors)
		}
	}
	if err := os.WriteFile(h.env.P(sysctlMaxUserNamespaces), []byte("63229\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if r.OK || r.SecurityComplete || !hasMessageCode(r.Errors, codeUserNamespaces) {
			t.Fatalf("%s missed namespace bypass: ok=%v security_complete=%v errors=%+v", action, r.OK, r.SecurityComplete, r.Errors)
		}
	}
	repaired := h.run(Options{Action: ActionEnsure})
	if !repaired.Installed || repaired.SecurityComplete || !hasMessageCode(repaired.Errors, codeUserNamespaces) {
		t.Fatalf("ensure did not require a reboot after re-closing namespaces: %+v", repaired)
	}
	if got := h.read(sysctlMaxUserNamespaces); got != "0\n" {
		t.Fatalf("ensure did not restore user namespace restriction: %q", got)
	}
	if err := os.WriteFile(h.env.P(userNamespaceBootIDPath), []byte("boot-after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		if result := h.run(Options{Action: action}); hasMessageCode(result.Errors, codeUserNamespaces) {
			t.Fatalf("%s still requires a reboot after boot ID changed: %+v", action, result.Errors)
		}
	}

	// A config-only check would miss a boot-time reopening of the bypass;
	// a live-only check would miss the next reboot's exposure.
	if err := os.Remove(h.env.P(userNamespacesConfigPath)); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if r.OK || r.SecurityComplete || !hasMessageCode(r.Errors, codeUserNamespaces) {
			t.Fatalf("%s missed missing persistent restriction: %+v", action, r)
		}
	}
	repaired = h.run(Options{Action: ActionEnsure})
	if !repaired.Installed || repaired.SecurityComplete || !hasMessageCode(repaired.Errors, codeUserNamespaces) {
		t.Fatalf("ensure trusted the old boot proof after restoring the missing file: %+v", repaired)
	}
	if got := h.read(userNamespacesConfigPath); got != string(userNamespacesConfig) {
		t.Fatalf("ensure did not restore persistent restriction: %q", got)
	}
	writeKernelSetting(t, h, userNamespaceBootIDPath, "boot-final\n")
	if result := h.run(Options{Action: ActionStatus}); hasMessageCode(result.Errors, codeUserNamespaces) {
		t.Fatalf("status did not clear after the next reboot: %+v", result)
	}
}

// ptrace path translation can hide /etc/codex and /etc/claude-code without a
// user namespace. A host that opted in must require administrator-only
// tracing.
func TestLinuxManagedPtraceRestrictionIsEnforcedAndDetected(t *testing.T) {
	h, cfg := restrictedHost(t)
	const ptrace = "/proc/sys/kernel/yama/ptrace_scope"
	path := h.env.P(ptrace)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	installed := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg})
	if !installed.Installed || installed.SecurityComplete || !hasMessageCode(installed.Errors, codeUserNamespaces) {
		t.Fatalf("install trusted a boot with user ptrace available: %+v", installed)
	}
	if got := h.read(ptrace); got != "2\n" {
		t.Fatalf("install left user ptrace available: %q", got)
	}
	if got := h.read(userNamespacesConfigPath); got != string(userNamespacesConfig) {
		t.Fatalf("install did not persist the ptrace restriction: %q", got)
	}
	if marker := h.read(userNamespaceBootMarker); marker != "boot-before\n" {
		t.Fatalf("install did not require a reboot after restricting ptrace: %q", marker)
	}
	if err := os.WriteFile(h.env.P(userNamespaceBootIDPath), []byte("boot-after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		if r := h.run(Options{Action: action}); hasMessageCode(r.Errors, codeUserNamespaces) {
			t.Fatalf("%s rejected the rebooted restricted host: %+v", action, r.Errors)
		}
	}
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if r.OK || r.SecurityComplete || !hasMessageCode(r.Errors, codeUnprivilegedPtrace) {
			t.Fatalf("%s missed ptrace drift: %+v", action, r)
		}
	}
	repaired := h.run(Options{Action: ActionEnsure})
	if !repaired.Installed || repaired.SecurityComplete || !hasMessageCode(repaired.Errors, codeUserNamespaces) {
		t.Fatalf("ensure did not require reboot after ptrace drift: %+v", repaired)
	}
	if got := h.read(ptrace); got != "2\n" {
		t.Fatalf("ensure did not repair ptrace drift: %q", got)
	}
	if err := os.WriteFile(h.env.P(userNamespaceBootIDPath), []byte("boot-third\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := h.run(Options{Action: ActionVerify}); hasMessageCode(r.Errors, codeUserNamespaces) {
		t.Fatalf("ptrace repair did not clear after reboot: %+v", r.Errors)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if r := h.run(Options{Action: ActionStatus}); r.SecurityComplete || !hasMessageCode(r.Errors, codeUnprivilegedPtrace) {
		t.Fatalf("status trusted a missing ptrace kernel setting: %+v", r)
	}
	if r := h.run(Options{Action: ActionEnsure}); r.OK || !hasMessageCode(r.Errors, codeUserNamespaces) {
		t.Fatalf("ensure invented a missing ptrace kernel setting: %+v", r)
	}
}

func TestLinuxMissingPtraceAttestationRequiresReboot(t *testing.T) {
	h, cfg := restrictedHost(t)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg}))
	if err := os.Remove(h.env.P(ptraceBootMarker)); err != nil {
		t.Fatal(err)
	}
	if r := h.run(Options{Action: ActionVerify}); r.SecurityComplete || !hasMessageCode(r.Errors, codeUserNamespaces) {
		t.Fatalf("verify trusted a missing ptrace attestation: %+v", r)
	}
	repaired := h.run(Options{Action: ActionEnsure})
	if !repaired.Installed || repaired.SecurityComplete || !hasMessageCode(repaired.Errors, codeUserNamespaces) {
		t.Fatalf("ensure did not recreate ptrace attestation and require reboot: %+v", repaired)
	}
	if marker := h.read(ptraceBootMarker); marker != "boot-before\n" {
		t.Fatalf("ensure did not attest the current boot: %q", marker)
	}
}

func TestLinuxStricterPtraceScopeIsPreserved(t *testing.T) {
	h, cfg := restrictedHost(t)
	if err := os.WriteFile(h.env.P(sysctlPtraceScope), []byte("3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	installed := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg})
	if !installed.Installed || installed.SecurityComplete || !hasMessageCode(installed.Errors, codeUserNamespaces) {
		t.Fatalf("install trusted an unattested stricter setting: %+v", installed)
	}
	if got := h.read(sysctlPtraceScope); got != "3\n" {
		t.Fatalf("install weakened a stricter ptrace setting: %q", got)
	}
	if config := h.read(userNamespacesConfigPath); !strings.Contains(config, "kernel.yama.ptrace_scope = 3\n") {
		t.Fatalf("install would weaken ptrace after reboot: %q", config)
	}
	if err := os.WriteFile(h.env.P(userNamespaceBootIDPath), []byte("boot-after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := h.run(Options{Action: ActionVerify}); hasMessageCode(r.Errors, codeUnprivilegedPtrace) || hasMessageCode(r.Errors, codeUserNamespaces) {
		t.Fatalf("verify rejected a stricter ptrace setting: %+v", r.Errors)
	}
}

func TestLinuxPtraceUpgradeRequiresRebootWithoutPriorPtraceAttestation(t *testing.T) {
	h, cfg := restrictedHost(t)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg}))
	oldConfig := []byte("# DefenseClaw managed policy requires a single host view of machine policy.\nuser.max_user_namespaces = 0\n")
	if err := os.WriteFile(h.env.P(userNamespacesConfigPath), oldConfig, 0o644); err != nil {
		t.Fatal(err)
	}
	record, err := h.env.loadDeployment()
	if err != nil {
		t.Fatal(err)
	}
	record.Files[userNamespacesConfigPath] = sha256Bytes(oldConfig)
	if err := h.env.saveDeployment(record); err != nil {
		t.Fatal(err)
	}
	// The live value may already be 2 because an administrator changed it in
	// this boot. That cannot prove that no tracer attached earlier.
	h.env.ProductVersion = "1.0.5"
	upgraded := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.5")})
	if !upgraded.Installed || upgraded.SecurityComplete || !hasMessageCode(upgraded.Errors, codeUserNamespaces) {
		t.Fatalf("upgrade trusted an unattested ptrace setting: %+v", upgraded)
	}
	if marker := h.read(userNamespaceBootMarker); marker != "boot-before\n" {
		t.Fatalf("upgrade did not require a new boot: %q", marker)
	}
}

func TestLinuxFreshInstallFromUnrestrictedHostRequiresReboot(t *testing.T) {
	h, cfg := restrictedHost(t)
	if err := os.Remove(h.env.P(userNamespacesConfigPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.env.P(userNamespaceBootMarker)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(sysctlMaxUserNamespaces), []byte("63229\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	installed := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
	if !installed.Installed || installed.SecurityComplete || !hasMessageCode(installed.Errors, codeUserNamespaces) {
		t.Fatalf("fresh install marked the current boot complete: %+v", installed)
	}
	if h.read(sysctlMaxUserNamespaces) != "0\n" || h.read(userNamespacesConfigPath) != string(userNamespacesConfig) {
		t.Fatal("fresh install did not enforce and persist the restriction")
	}
	if status := h.run(Options{Action: ActionStatus}); status.SecurityComplete || !hasMessageCode(status.Errors, codeUserNamespaces) {
		t.Fatalf("status marked the old boot complete: %+v", status)
	}
	if err := os.WriteFile(h.env.P(userNamespaceBootMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if status := h.run(Options{Action: ActionStatus}); status.SecurityComplete || !hasMessageCode(status.Errors, codeUserNamespaces) {
		t.Fatalf("status trusted an empty reboot marker: %+v", status)
	}
	if err := os.WriteFile(h.env.P(userNamespaceBootMarker), []byte("boot-before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(userNamespaceBootIDPath), []byte("boot-after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if status := h.run(Options{Action: ActionStatus}); hasMessageCode(status.Errors, codeUserNamespaces) {
		t.Fatalf("status did not clear the reboot requirement: %+v", status.Errors)
	}
}

func TestLinuxFreshInstallWithZeroSettingStillRequiresReboot(t *testing.T) {
	h, cfg := restrictedHost(t)
	if err := os.Remove(h.env.P(userNamespacesConfigPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.env.P(userNamespaceBootMarker)); err != nil {
		t.Fatal(err)
	}
	installed := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
	if !installed.Installed || installed.SecurityComplete || !hasMessageCode(installed.Errors, codeUserNamespaces) {
		t.Fatalf("fresh install trusted a zero setting without proof of a reboot: %+v", installed)
	}
	if marker := h.read(userNamespaceBootMarker); marker != "boot-before\n" {
		t.Fatalf("fresh install did not record the boot needing a reboot: %q", marker)
	}
	if err := os.WriteFile(h.env.P(userNamespaceBootIDPath), []byte("boot-after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if status := h.run(Options{Action: ActionStatus}); hasMessageCode(status.Errors, codeUserNamespaces) {
		t.Fatalf("status did not accept the rebooted, restricted host: %+v", status.Errors)
	}
	if err := os.Remove(h.env.P(userNamespaceBootMarker)); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		if result := h.run(Options{Action: action}); result.SecurityComplete || !hasMessageCode(result.Errors, codeUserNamespaces) {
			t.Fatalf("%s accepted a missing reboot attestation: %+v", action, result)
		}
	}
	repaired := h.run(Options{Action: ActionEnsure})
	if !repaired.Installed || repaired.SecurityComplete || !hasMessageCode(repaired.Errors, codeUserNamespaces) {
		t.Fatalf("ensure did not recreate a missing marker and require reboot: %+v", repaired)
	}
	if marker := h.read(userNamespaceBootMarker); marker != "boot-after\n" {
		t.Fatalf("ensure did not mark the current boot: %q", marker)
	}
}

// The package's own install keeps the host's kernel settings; the
// administrator config that opts in then closes both and waits for a reboot.
func TestLinuxPackageInstallEnforcesUserNamespaceRestriction(t *testing.T) {
	h := packageHost(t, "1.0.0")
	openKernel(t, h)
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true, Reason: "package"}))
	requireKernelUntouched(t, h, "package install")
	installed := h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package", ConfigFile: restrictPolicyViewsConfig(t, h)})
	if !installed.Installed || installed.SecurityComplete || !hasMessageCode(installed.Errors, codeUserNamespaces) {
		t.Fatalf("the opted-in package config did not close namespaces and require a reboot: %+v", installed)
	}
	if h.read(sysctlMaxUserNamespaces) != "0\n" || h.read(userNamespacesConfigPath) != string(userNamespacesConfig) {
		t.Fatal("package install did not enforce and persist the host restriction")
	}
	record, err := h.env.loadDeployment()
	if err != nil || record.Files[userNamespacesConfigPath] == "" {
		t.Fatalf("package install did not track the host restriction: record=%+v err=%v", record, err)
	}
	raw, err := json.Marshal(installed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.env.P(h.env.Layout.LifecycleDir), lastPackageResultFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if failure := h.env.lastPackageInstallFailure(); failure != "" {
		t.Fatalf("committed package waiting for reboot reported an unapplied package: %q", failure)
	}
	if status := h.run(Options{Action: ActionStatus}); hasMessageCode(status.Warnings, codePackageInstallFailed) || !hasMessageCode(status.Errors, codeUserNamespaces) {
		t.Fatalf("status confused reboot requirement with an unapplied package: %+v", status)
	}
}

func TestLinuxNamespaceRebootMarkerSurvivesUninstall(t *testing.T) {
	h, cfg := restrictedHost(t)
	if err := os.WriteFile(h.env.P(sysctlMaxUserNamespaces), []byte("63229\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	installed := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
	if !installed.Installed || !hasMessageCode(installed.Errors, codeUserNamespaces) {
		t.Fatalf("first install did not mark the boot incomplete: %+v", installed)
	}
	if marker := h.read(userNamespaceBootMarker); marker != "boot-before\n" {
		t.Fatalf("wrong reboot marker: %q", marker)
	}
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	if marker := h.read(userNamespaceBootMarker); marker != "boot-before\n" {
		t.Fatalf("uninstall removed the reboot marker: %q", marker)
	}
	if marker := h.read(ptraceBootMarker); marker != "boot-before\n" {
		t.Fatalf("uninstall removed the ptrace reboot marker: %q", marker)
	}
	if got := h.read(sysctlMaxUserNamespaces); got != "0\n" {
		t.Fatalf("uninstall reopened user namespaces: %q", got)
	}
	reinstalled := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
	if !reinstalled.Installed || reinstalled.SecurityComplete || !hasMessageCode(reinstalled.Errors, codeUserNamespaces) {
		t.Fatalf("reinstall in the same boot forgot prior namespaces: %+v", reinstalled)
	}
}

func TestLinuxSafeSameBootReinstallAndUnrestrictedReboot(t *testing.T) {
	h, cfg := restrictedHost(t)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg}))
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	if marker := h.read(userNamespaceUninstalled); marker != "boot-before\n" {
		t.Fatalf("uninstall did not record when the persistent restriction was removed: %q", marker)
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg}))
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	// The fake kernel stays at zero, but the managed sysctl file was absent
	// across this reboot. The old boot marker no longer proves safety.
	if err := os.WriteFile(h.env.P(userNamespaceBootIDPath), []byte("boot-after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reinstalled := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
	if !reinstalled.Installed || reinstalled.SecurityComplete || !hasMessageCode(reinstalled.Errors, codeUserNamespaces) {
		t.Fatalf("reinstall trusted a boot without the persistent restriction: %+v", reinstalled)
	}
	if marker := h.read(userNamespaceBootMarker); marker != "boot-after\n" {
		t.Fatalf("reinstall did not require a new reboot: %q", marker)
	}
}

// A same-boot uninstall marker attests only the uninstall it recorded. Once
// a restricted deployment is installed again, losing its persistent file is
// drift: restoring the file cannot reuse that older marker to skip a reboot.
func TestLinuxRestoredMissingRestrictionRequiresNewBoot(t *testing.T) {
	h, cfg := restrictedHost(t)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg}))
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg}))
	if err := os.Remove(h.env.P(userNamespacesConfigPath)); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		if result := h.run(Options{Action: action}); result.SecurityComplete || !hasMessageCode(result.Errors, codeUserNamespaces) {
			t.Fatalf("%s missed the missing persistent restriction: %+v", action, result)
		}
	}
	repaired := h.run(Options{Action: ActionEnsure})
	if !repaired.Installed || repaired.SecurityComplete || !hasMessageCode(repaired.Errors, codeUserNamespaces) {
		t.Fatalf("ensure trusted the old uninstall marker after restoring a missing file: %+v", repaired)
	}
	if marker := h.read(userNamespaceBootMarker); marker != "boot-before\n" {
		t.Fatalf("ensure did not attest the current boot: %q", marker)
	}
	writeKernelSetting(t, h, userNamespaceBootIDPath, "boot-after\n")
	if result := h.run(Options{Action: ActionStatus}); hasMessageCode(result.Errors, codeUserNamespaces) {
		t.Fatalf("status did not clear after reboot: %+v", result)
	}
}

func TestLinuxReinstallAfterUnprovenUninstallRequiresReboot(t *testing.T) {
	h, cfg := restrictedHost(t)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg}))
	if err := os.Remove(h.env.P(userNamespacesConfigPath)); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	if marker := h.read(userNamespaceUninstalled); marker != "unproven:boot-before\n" {
		t.Fatalf("uninstall trusted a missing host restriction: %q", marker)
	}
	reinstalled := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
	if !reinstalled.Installed || reinstalled.SecurityComplete || !hasMessageCode(reinstalled.Errors, codeUserNamespaces) {
		t.Fatalf("reinstall trusted an unproven boot: %+v", reinstalled)
	}
}

func TestLinuxUserNamespaceRestrictionFailsWithoutKernelSetting(t *testing.T) {
	h, cfg := restrictedHost(t)
	if err := os.Remove(h.env.P(sysctlMaxUserNamespaces)); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
	if r.OK || !hasMessageCode(r.Errors, codeUserNamespaces) {
		t.Fatalf("install claimed protection without a kernel setting: %+v", r)
	}
	if _, err := os.Stat(h.env.P(sysctlMaxUserNamespaces)); !os.IsNotExist(err) {
		t.Fatalf("install invented a missing kernel setting: %v", err)
	}
}

func TestLinuxUserNamespaceRestrictionRefusesUntrustedConfigDirectory(t *testing.T) {
	h, cfg := restrictedHost(t)
	if err := os.Remove(h.env.P(userNamespacesConfigPath)); err != nil {
		t.Fatal(err)
	}
	h.env.Trust = func(_ string, kind TrustKind) error {
		if kind == TrustAdminDir {
			return errors.New("standard user can replace the directory")
		}
		return nil
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg})
	if r.OK || !hasMessageCode(r.Errors, codeApply) {
		t.Fatalf("install wrote a host setting through an untrusted directory: %+v", r)
	}
	if _, err := os.Stat(h.env.P(userNamespacesConfigPath)); !os.IsNotExist(err) {
		t.Fatalf("install left a host setting under an untrusted directory: %v", err)
	}
}

// macOS ignores enterprise.machine_policy.linux: the opt-in writes no Linux
// sysctl file there.
func TestMacOSUserNamespaceSettingIsNotRequired(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
	h.env.ProductVersion = "1.0.4"
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.4")}))
	requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: restrictPolicyViewsConfig(t, h)}))
	if problem := h.env.userNamespaceProblem(); problem != "" {
		t.Fatal(problem)
	}
	if err := h.env.restrictManagedPolicyViews(false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(h.env.P(userNamespacesConfigPath)); !os.IsNotExist(err) {
		t.Fatalf("macOS install wrote a Linux sysctl file: %v", err)
	}
}

// requireProvenBoot fails when action asks for a reboot on a boot that the
// restriction has covered since it started, or rewrites its boot markers.
func requireProvenBoot(t *testing.T, h *testHost, label string, r *enterprisestatus.Result, markers string) {
	t.Helper()
	if hasMessageCode(r.Errors, codeUserNamespaces) || hasMessageCode(r.Errors, codeUnprivilegedPtrace) {
		t.Fatalf("%s demanded another reboot on a proven boot: %+v", label, r.Errors)
	}
	for _, marker := range []string{userNamespaceBootMarker, ptraceBootMarker} {
		if got := h.read(marker); got != markers {
			t.Fatalf("%s rewrote proven boot marker %s: %q, want %q", label, marker, got, markers)
		}
	}
}

// An uninstall marker attests only the uninstall it recorded. Once a
// restricted deployment is installed again (in the same boot, or after a
// reboot that needed a new attestation), it is spent: kept, every later
// non-noop change after a reboot distrusted the proven boot and asked for
// another reboot (GAP-0851).
func TestLinuxProvenRestrictionAfterUninstallNeedsNoReboot(t *testing.T) {
	for _, tc := range []struct {
		name string
		// reinstall runs the reinstall after the purge and returns the boot
		// the boot markers must name afterwards.
		reinstall func(t *testing.T, h *testHost, cfg string) string
	}{
		{"same-boot reinstall", func(t *testing.T, h *testHost, cfg string) string {
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg}))
			return "boot-prior\n"
		}},
		{"reinstall after a reboot without the file", func(t *testing.T, h *testHost, cfg string) string {
			// The file was gone across this reboot, so the kernel came up open.
			writeKernelSetting(t, h, userNamespaceBootIDPath, "boot-mid\n")
			writeKernelSetting(t, h, sysctlMaxUserNamespaces, "63229\n")
			writeKernelSetting(t, h, sysctlPtraceScope, "0\n")
			r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg})
			if !r.Installed || r.SecurityComplete || !hasMessageCode(r.Errors, codeUserNamespaces) {
				t.Fatalf("reinstall after an unrestricted boot did not ask for a reboot: %+v", r)
			}
			return "boot-mid\n"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, cfg := restrictedHost(t)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg}))
			requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
			if got := h.read(userNamespaceUninstalled); got != "boot-before\n" {
				t.Fatalf("uninstall marker = %q", got)
			}
			markers := tc.reinstall(t, h, cfg)
			if _, err := os.Stat(h.env.P(userNamespaceUninstalled)); !os.IsNotExist(err) {
				t.Fatalf("reinstall kept the spent uninstall marker: %v", err)
			}
			writeKernelSetting(t, h, userNamespaceBootIDPath, "boot-after\n")
			for _, action := range []string{ActionStatus, ActionVerify} {
				r := h.run(Options{Action: action})
				requireProvenBoot(t, h, action, r, markers)
			}
			for i, version := range []string{"1.0.5", "1.0.6"} {
				h.env.ProductVersion = version
				r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload(version)})
				if !r.Installed {
					t.Fatalf("upgrade %d failed: %+v", i+1, r)
				}
				requireProvenBoot(t, h, "upgrade to "+version, r, markers)
			}
			edited := filepath.Join(t.TempDir(), "config.yaml")
			raw, err := os.ReadFile(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(edited, append(raw, []byte("# edited by the administrator\n")...), 0o600); err != nil {
				t.Fatal(err)
			}
			ensured := h.run(Options{Action: ActionEnsure, ConfigFile: edited})
			if !ensured.Installed || len(ensured.Changes) == 0 {
				t.Fatalf("config change was not applied: %+v", ensured)
			}
			requireProvenBoot(t, h, "config-change ensure", ensured, markers)
		})
	}
}

// The marker is spent only when the reinstall commits: a reinstall that rolls
// back keeps the same-boot proof, so its retry in the same boot is trusted.
func TestLinuxRolledBackReinstallKeepsSameBootUninstallProof(t *testing.T) {
	h, cfg := restrictedHost(t)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg}))
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	setLifecycleTestFault(t, h, testFaultAfterServices)
	failed := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg})
	if failed.OK || !hasMessageCode(failed.Errors, codeLifecycleTestFault) {
		t.Fatalf("the test fault did not fail the reinstall: %+v", failed)
	}
	if got := h.read(userNamespaceUninstalled); got != "boot-before\n" {
		t.Fatalf("a rolled-back reinstall spent the uninstall marker: %q", got)
	}
	clearLifecycleTestFault(t, h)
	retried := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg})
	requireOK(t, retried)
	requireProvenBoot(t, h, "same-boot retry", retried, "boot-prior\n")
	if _, err := os.Stat(h.env.P(userNamespaceUninstalled)); !os.IsNotExist(err) {
		t.Fatalf("the committed retry kept the spent uninstall marker: %v", err)
	}
}

// A marker that cannot be removed stays in place (it only ever asks for a
// reboot) and the run says so instead of reporting success.
func TestLinuxUninstallMarkerThatCannotBeRemovedFailsTheRun(t *testing.T) {
	h, cfg := restrictedHost(t)
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg}))
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	marker := h.env.P(userNamespaceUninstalled)
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(marker, "held"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4"), ConfigFile: cfg})
	if r.OK || r.SecurityComplete || !strings.Contains(messagesOf(r.Errors, codeUserNamespaces), userNamespaceUninstalled) {
		t.Fatalf("a marker that could not be removed did not fail the run: %+v", r)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the unremovable marker is gone: %v", err)
	}
}
