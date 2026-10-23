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
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// A user who can create a private user and mount namespace can mask every
// vendor machine-policy file before starting an agent. This is a host-wide
// prerequisite for all managed Linux connectors, not a connector setting.
const (
	codeUserNamespaces       = "unprivileged_user_namespaces"
	codeUnprivilegedPtrace   = "unprivileged_ptrace"
	sysctlMaxUserNamespaces  = "/proc/sys/user/max_user_namespaces"
	sysctlPtraceScope        = "/proc/sys/kernel/yama/ptrace_scope"
	userNamespaceBootIDPath  = "/proc/sys/kernel/random/boot_id"
	userNamespacesConfigPath = "/etc/sysctl.d/99-zz-defenseclaw-userns.conf"
	userNamespaceBootMarker  = "/etc/sysctl.d/.defenseclaw-userns-restricted-boot-id"
	ptraceBootMarker         = "/etc/sysctl.d/.defenseclaw-ptrace-restricted-boot-id"
	userNamespaceUninstalled = "/etc/sysctl.d/.defenseclaw-userns-uninstalled-boot-id"
)

var userNamespacesConfig = []byte("# DefenseClaw managed policy requires a single host view of machine policy.\nuser.max_user_namespaces = 0\nkernel.yama.ptrace_scope = 2\n")
var userNamespacesConfigStrict = []byte("# DefenseClaw managed policy requires a single host view of machine policy.\nuser.max_user_namespaces = 0\nkernel.yama.ptrace_scope = 3\n")

// Preserve an administrator's stricter ptrace scope across reboots. Once the
// managed file records 3, ensure does not lower it just because the live
// setting temporarily reports 2.
func (e *Env) desiredPolicyViewConfig() []byte {
	live, _ := readBounded(e.P(sysctlPtraceScope), 64)
	if strings.TrimSpace(string(live)) == "3" {
		return userNamespacesConfigStrict
	}
	path := e.P(userNamespacesConfigPath)
	current, _ := readBounded(path, 1024)
	if bytes.Equal(current, userNamespacesConfigStrict) && e.Trust(path, TrustAdminFile) == nil {
		return userNamespacesConfigStrict
	}
	return userNamespacesConfig
}

// restrictManagedPolicyViews applies both kernel restrictions before machine
// policy is published. The live settings are not rolled back after a failed
// transaction: reopening either path would restore the policy-masking bypass.
// Boot markers require a reboot when either control is first applied or
// reopened, because an existing namespace or tracer survives the change.
func (e *Env) restrictManagedPolicyViews(priorRestricted bool) error {
	if e.GOOS != "linux" {
		return nil
	}
	if info, err := os.Lstat(e.P(sysctlMaxUserNamespaces)); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%s is unavailable or not a kernel setting; managed policy cannot be complete until the host refuses unprivileged user namespaces", sysctlMaxUserNamespaces)
	}
	previous, err := readBounded(e.P(sysctlMaxUserNamespaces), 64)
	if err != nil {
		return fmt.Errorf("read %s before restricting user namespaces: %w", sysctlMaxUserNamespaces, err)
	}
	if info, err := os.Lstat(e.P(sysctlPtraceScope)); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%s is unavailable or not a kernel setting; managed policy cannot stop unprivileged ptrace path rewriting", sysctlPtraceScope)
	}
	previousPtrace, err := readBounded(e.P(sysctlPtraceScope), 64)
	if err != nil {
		return fmt.Errorf("read %s before restricting ptrace: %w", sysctlPtraceScope, err)
	}
	if strings.TrimSpace(string(previous)) != "0" || !ptraceRestricted(previousPtrace) ||
		!priorRestricted || e.userNamespaceBootProblem() != "" || e.ptraceBootProblem() != "" {
		bootID, err := e.currentBootID()
		if err != nil {
			return fmt.Errorf("record the boot that could create unprivileged user namespaces: %w", err)
		}
		if err := e.Trust(e.P(filepath.Dir(userNamespaceBootMarker)), TrustAdminDir); err != nil {
			return fmt.Errorf("%s is not administrator-controlled: %w", filepath.Dir(userNamespaceBootMarker), err)
		}
		if err := e.writeFileAtomic(e.P(userNamespaceBootMarker), []byte(bootID+"\n"), 0o600, rootOwner()); err != nil {
			return fmt.Errorf("record the boot that could contain a policy-hiding namespace: %w", err)
		}
		if err := e.writeFileAtomic(e.P(ptraceBootMarker), []byte(bootID+"\n"), 0o600, rootOwner()); err != nil {
			return fmt.Errorf("record the boot that could contain a policy-hiding tracer: %w", err)
		}
	}
	if err := os.WriteFile(e.P(sysctlMaxUserNamespaces), []byte("0\n"), 0o644); err != nil {
		return fmt.Errorf("apply %s=0: %w; managed policy cannot be complete until the host refuses unprivileged user namespaces", sysctlMaxUserNamespaces, err)
	}
	if strings.TrimSpace(string(previousPtrace)) != "3" {
		if err := os.WriteFile(e.P(sysctlPtraceScope), []byte("2\n"), 0o644); err != nil {
			return fmt.Errorf("apply %s=2: %w; managed policy cannot be complete until the host refuses unprivileged ptrace", sysctlPtraceScope, err)
		}
	}
	if problem := e.userNamespaceProblem(); problem != "" {
		return fmt.Errorf("%s", problem)
	}
	if problem := e.ptraceProblem(); problem != "" {
		return fmt.Errorf("%s", problem)
	}
	return nil
}

func (e *Env) currentBootID() (string, error) {
	data, err := readBounded(e.P(userNamespaceBootIDPath), 64)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if id == "" {
		return "", fmt.Errorf("%s is empty", userNamespaceBootIDPath)
	}
	return id, nil
}

// markUserNamespaceUninstall records the boot that removed our persistent
// sysctl file. A reinstall in this boot may reuse a prior-boot attestation
// when the restriction was healthy before removal, including a retry after
// that removal if the live limit remains zero. After a reboot without the
// file it may not.
func (e *Env) markUserNamespaceUninstall() error {
	if e.GOOS != "linux" {
		return nil
	}
	id, err := e.currentBootID()
	if err != nil {
		return fmt.Errorf("record the uninstall boot: %w", err)
	}
	dir := e.P(filepath.Dir(userNamespaceUninstalled))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create host security directory: %w", err)
	}
	if err := e.Trust(dir, TrustAdminDir); err != nil {
		return fmt.Errorf("%s is not administrator-controlled: %w", filepath.Dir(userNamespaceUninstalled), err)
	}
	priorSafeUninstall, _ := e.userNamespaceUninstallState()
	live, liveErr := readBounded(e.P(sysctlMaxUserNamespaces), 64)
	ptrace, ptraceErr := readBounded(e.P(sysctlPtraceScope), 64)
	stillRestricted := liveErr == nil && strings.TrimSpace(string(live)) == "0" &&
		ptraceErr == nil && ptraceRestricted(ptrace)
	priorBootProven := e.userNamespaceProblem() == "" && e.ptraceProblem() == "" && e.ptraceBootProblem() == "" ||
		(priorSafeUninstall && stillRestricted && e.ptraceBootProblem() == "")
	marker := id + "\n"
	if e.userNamespaceBootProblem() != "" || e.ptraceBootProblem() != "" || !priorBootProven {
		marker = "unproven:" + id + "\n"
	}
	if err := e.writeFileAtomic(e.P(userNamespaceUninstalled), []byte(marker), 0o600, rootOwner()); err != nil {
		return fmt.Errorf("record the boot that removed the persistent user namespace restriction: %w", err)
	}
	return nil
}

// userNamespaceUninstallState is conservative about a damaged marker: it
// cannot prove a same-boot reinstall, and it prevents an old record alone
// from claiming that the persistent restriction survived this boot.
func (e *Env) userNamespaceUninstallState() (sameBoot, exists bool) {
	if e.GOOS != "linux" {
		return false, false
	}
	marker, err := readBounded(e.P(userNamespaceUninstalled), 64)
	if errors.Is(err, os.ErrNotExist) {
		return false, false
	}
	if err != nil || e.Trust(e.P(userNamespaceUninstalled), TrustAdminFile) != nil {
		return false, true
	}
	id, err := e.currentBootID()
	if err != nil || strings.TrimSpace(string(marker)) == "" {
		return false, true
	}
	return strings.TrimSpace(string(marker)) == id, true
}

func (e *Env) userNamespaceBootProblem() string {
	if e.GOOS != "linux" {
		return ""
	}
	marker, err := readBounded(e.P(userNamespaceBootMarker), 64)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Sprintf("%s is missing; run `%s` to record the current boot, then reboot before reporting managed policy complete", userNamespaceBootMarker, e.lifecycleCommand(ActionEnsure))
	}
	if err != nil {
		return fmt.Sprintf("cannot read %s: %v; cannot prove earlier user namespaces ended", userNamespaceBootMarker, err)
	}
	if err := e.Trust(e.P(userNamespaceBootMarker), TrustAdminFile); err != nil {
		return fmt.Sprintf("%s is not administrator-controlled: %v", userNamespaceBootMarker, err)
	}
	markerID := strings.TrimSpace(string(marker))
	if markerID == "" {
		return fmt.Sprintf("%s is empty; cannot prove earlier user namespaces ended", userNamespaceBootMarker)
	}
	id, err := e.currentBootID()
	if err != nil {
		return fmt.Sprintf("cannot verify whether preexisting user namespaces survived: %v; reboot this host", err)
	}
	if markerID == id {
		return "the managed user namespace restriction was first attested in this boot; a namespace created earlier can still hide managed policy. Reboot this host before reporting managed policy complete"
	}
	return ""
}

// A separate marker prevents an upgrade from trusting a prior-boot marker
// written by releases that restricted namespaces but did not restrict ptrace.
// The original marker format stays unchanged for safe rollback to 1.0.4.
func (e *Env) ptraceBootProblem() string {
	if e.GOOS != "linux" {
		return ""
	}
	marker, err := readBounded(e.P(ptraceBootMarker), 64)
	if err != nil {
		return fmt.Sprintf("cannot read %s: %v; run `%s`, then reboot before reporting managed policy complete", ptraceBootMarker, err, e.lifecycleCommand(ActionEnsure))
	}
	if err := e.Trust(e.P(ptraceBootMarker), TrustAdminFile); err != nil {
		return fmt.Sprintf("%s is not administrator-controlled: %v", ptraceBootMarker, err)
	}
	id, err := e.currentBootID()
	if err != nil {
		return fmt.Sprintf("cannot verify when the ptrace restriction was applied: %v; reboot this host", err)
	}
	markerID := strings.TrimSpace(string(marker))
	if markerID == "" || markerID == id {
		return "the managed ptrace restriction was first attested in this boot; a tracer started earlier can still hide machine policy. Reboot this host before reporting managed policy complete"
	}
	return ""
}

// userNamespaceProblem checks both the live kernel restriction and the file
// that reapplies it at boot. Missing or unreadable evidence is incomplete.
func (e *Env) userNamespaceProblem() string {
	if e.GOOS != "linux" {
		return ""
	}
	config, err := readBounded(e.P(userNamespacesConfigPath), 1024)
	if err != nil || !bytes.Equal(config, e.desiredPolicyViewConfig()) {
		return fmt.Sprintf("%s is missing or changed; run `%s` to restore the managed user namespace restriction before standard users start agents", userNamespacesConfigPath, e.lifecycleCommand(ActionEnsure))
	}
	if err := e.Trust(e.P(userNamespacesConfigPath), TrustAdminFile); err != nil {
		return fmt.Sprintf("%s is not administrator-controlled: %v; run `%s`", userNamespacesConfigPath, err, e.lifecycleCommand(ActionEnsure))
	}
	value, err := readBounded(e.P(sysctlMaxUserNamespaces), 64)
	if err != nil {
		return fmt.Sprintf("cannot verify %s: %v; managed policy is incomplete until unprivileged user namespaces are disabled", sysctlMaxUserNamespaces, err)
	}
	if strings.TrimSpace(string(value)) != "0" {
		return fmt.Sprintf("%s=%s lets a standard user hide managed agent policy in a private mount namespace; run `%s` to set it to 0", sysctlMaxUserNamespaces, strings.TrimSpace(string(value)), e.lifecycleCommand(ActionEnsure))
	}
	return ""
}

func (e *Env) ptraceProblem() string {
	if e.GOOS != "linux" {
		return ""
	}
	value, err := readBounded(e.P(sysctlPtraceScope), 64)
	if err != nil {
		return fmt.Sprintf("cannot verify %s: %v; managed policy is incomplete until unprivileged ptrace is disabled", sysctlPtraceScope, err)
	}
	if !ptraceRestricted(value) {
		return fmt.Sprintf("%s=%s lets a standard user rewrite agent policy paths through ptrace; run `%s` to set it to at least 2", sysctlPtraceScope, strings.TrimSpace(string(value)), e.lifecycleCommand(ActionEnsure))
	}
	return ""
}

func ptraceRestricted(value []byte) bool {
	switch strings.TrimSpace(string(value)) {
	case "2", "3":
		return true
	default:
		return false
	}
}
