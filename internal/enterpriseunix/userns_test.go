// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"strings"
	"testing"
)

const (
	retiredSysctlFile      = "/etc/sysctl.d/99-zz-defenseclaw-userns.conf"
	retiredUsernsMarker    = "/etc/sysctl.d/.defenseclaw-userns-restricted-boot-id"
	retiredPtraceMarker    = "/etc/sysctl.d/.defenseclaw-ptrace-restricted-boot-id"
	retiredUninstallMarker = "/etc/sysctl.d/.defenseclaw-userns-uninstalled-boot-id"
)

func setKernelValue(t *testing.T, h *testHost, path, value string) {
	t.Helper()
	writeHostFile(t, h, path, value)
}

func assertKernelUntouched(t *testing.T, h *testHost) {
	t.Helper()
	if got := h.read(sysctlMaxUserNamespaces); got != "63229\n" {
		t.Fatalf("DefenseClaw changed user.max_user_namespaces: %q", got)
	}
	if got := h.read(sysctlPtraceScope); got != "0\n" {
		t.Fatalf("DefenseClaw changed kernel.yama.ptrace_scope: %q", got)
	}
	for _, path := range []string{retiredSysctlFile, retiredUsernsMarker, retiredPtraceMarker, retiredUninstallMarker} {
		if _, err := os.Lstat(h.env.P(path)); !os.IsNotExist(err) {
			t.Fatalf("DefenseClaw created retired host control %s: %v", path, err)
		}
	}
}

func TestLinuxLifecycleNeverChangesHostKernel(t *testing.T) {
	h := newTestHost(t, "linux")
	setKernelValue(t, h, sysctlMaxUserNamespaces, "63229\n")
	setKernelValue(t, h, sysctlPtraceScope, "0\n")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4")}))
	assertKernelUntouched(t, h)
	for _, action := range []string{ActionEnsure, ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		if hasMessageCode(result.Errors, codeUserNamespaces) || hasMessageCode(result.Errors, codeUnprivilegedPtrace) {
			t.Fatalf("%s turned observed kernel settings into errors: %+v", action, result.Errors)
		}
		if action == ActionEnsure && !result.OK {
			t.Fatalf("ensure failed with observed open kernel settings: %+v", result.Errors)
		}
		assertKernelUntouched(t, h)
	}
	status := h.run(Options{Action: ActionStatus})
	if status.SecurityComplete || !hasWarning(status, codeUserNamespaces) || !hasWarning(status, codeUnprivilegedPtrace) {
		t.Fatalf("status did not report the observed open settings: %+v", status)
	}
	for _, warning := range status.Warnings {
		if (warning.Code == codeUserNamespaces || warning.Code == codeUnprivilegedPtrace) && strings.Contains(warning.Message, "namespaces_and_ptrace") {
			t.Fatalf("status still offers retired host-setting key: %q", warning.Message)
		}
	}
	requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
	assertKernelUntouched(t, h)
}

func TestLinuxLifecycleActionsReportOpenKernelPolicyViews(t *testing.T) {
	h := newTestHost(t, "linux")
	setKernelValue(t, h, sysctlMaxUserNamespaces, "63229\n")
	setKernelValue(t, h, sysctlPtraceScope, "0\n")
	for _, action := range []string{ActionInstall, ActionEnsure, ActionRepair, ActionUpgrade, ActionStatus, ActionVerify} {
		var opts Options
		switch action {
		case ActionInstall:
			opts = Options{Action: action, PayloadDir: h.payload("1.0.4")}
		case ActionUpgrade:
			opts = Options{Action: action, PayloadDir: h.payload("1.0.5")}
		default:
			opts = Options{Action: action}
		}
		result := h.run(opts)
		if action != ActionVerify {
			requireOK(t, result)
		}
		if result.SecurityComplete || !hasWarning(result, codeUserNamespaces) || !hasWarning(result, codeUnprivilegedPtrace) {
			t.Fatalf("%s claims different kernel-view truth from status: security_complete=%t warnings=%+v", action, result.SecurityComplete, result.Warnings)
		}
	}
}

func TestLinuxStatusUsesCurrentKernelFactsWithoutBootMarkers(t *testing.T) {
	h := newTestHost(t, "linux")
	setKernelValue(t, h, sysctlMaxUserNamespaces, "0\n")
	setKernelValue(t, h, sysctlPtraceScope, "3\n")
	setKernelValue(t, h, "/proc/sys/kernel/random/boot_id", "current-boot\n")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4")}))
	// Artifacts left by an unreleased opt-in build cannot substitute for
	// what the kernel reports now or make this deployment ask for a reboot.
	for _, path := range []string{retiredUsernsMarker, retiredPtraceMarker} {
		setKernelValue(t, h, path, "current-boot\n")
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		if hasWarning(result, codeUserNamespaces) || hasWarning(result, codeUnprivilegedPtrace) ||
			hasMessageCode(result.Errors, codeUserNamespaces) || hasMessageCode(result.Errors, codeUnprivilegedPtrace) {
			t.Fatalf("%s treated retired markers as current kernel facts: %+v", action, result)
		}
	}
}

func TestLinuxStatusReportsUnreadableKernelFacts(t *testing.T) {
	h := newTestHost(t, "linux")
	setKernelValue(t, h, sysctlMaxUserNamespaces, "63229\n")
	setKernelValue(t, h, sysctlPtraceScope, "0\n")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4")}))
	for _, path := range []string{sysctlMaxUserNamespaces, sysctlPtraceScope} {
		if err := os.Remove(h.env.P(path)); err != nil {
			t.Fatal(err)
		}
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		if result.SecurityComplete || !hasWarning(result, codeUserNamespaces) || !hasWarning(result, codeUnprivilegedPtrace) {
			t.Fatalf("%s did not report missing kernel facts: %+v", action, result)
		}
	}
}

func TestMacOSLifecycleHasNoLinuxHostControls(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4")}))
	requireOK(t, h.run(Options{Action: ActionEnsure}))
	for _, path := range []string{retiredSysctlFile, retiredUsernsMarker, retiredPtraceMarker, retiredUninstallMarker} {
		if _, err := os.Stat(h.env.P(path)); !os.IsNotExist(err) {
			t.Fatalf("macOS lifecycle created Linux host control %s: %v", path, err)
		}
	}
}
