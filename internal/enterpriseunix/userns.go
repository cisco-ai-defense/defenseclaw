// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"
	"strings"
)

// These are observed Linux kernel settings. DefenseClaw never changes them.
const (
	codeUserNamespaces               = "unprivileged_user_namespaces"
	codeUnprivilegedPtrace           = "unprivileged_ptrace"
	sysctlMaxUserNamespaces          = "/proc/sys/user/max_user_namespaces"
	sysctlPtraceScope                = "/proc/sys/kernel/yama/ptrace_scope"
	sysctlUnprivilegedUsernsClone    = "/proc/sys/kernel/unprivileged_userns_clone"
	sysctlAppArmorRestrictUserns     = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
	sysctlAppArmorRestrictUnconfined = "/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined"
)

const restrictPolicyViewsAdvice = "ask the host administrator to apply optional kernel hardening with their own tools"

// warnOpenPolicyViews reports only live kernel facts. The gateway separately
// proves the host's vendor policy against the descriptor's pins when it
// changes (gateway/managed_policy_view.go).
func (l *lifecycle) warnOpenPolicyViews() {
	if l.env.GOOS != "linux" {
		return
	}
	read := func(path string) (string, bool) {
		data, err := readBounded(l.env.P(path), 64)
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(string(data)), true
	}
	if message := unprivilegedUserNamespaceWarning(read); message != "" {
		l.result.AddWarning(codeUserNamespaces, message)
		l.result.SecurityComplete = false
	}
	if message := unprivilegedPtraceWarning(read); message != "" {
		l.result.AddWarning(codeUnprivilegedPtrace, message)
		l.result.SecurityComplete = false
	}
}

// unprivilegedUserNamespaceWarning returns the warning text, or "" when the
// kernel has no user namespaces or already refuses them to standard users
// (user.max_user_namespaces=0, the Debian kernel.unprivileged_userns_clone=0
// switch, or AppArmor with both kernel.apparmor_restrict_unprivileged_userns=1
// and kernel.apparmor_restrict_unprivileged_unconfined=1). AppArmor's userns
// restriction alone applies only to unconfined processes: while the second
// setting is 0 (the Ubuntu 24.04 default) or absent, a standard user can
// change to a profile that allows user namespaces, so the warning names it.
func unprivilegedUserNamespaceWarning(read func(path string) (string, bool)) string {
	limit, ok := read(sysctlMaxUserNamespaces)
	if !ok {
		return fmt.Sprintf("cannot read %s, so DefenseClaw cannot verify that standard users are prevented from creating private policy views; inspect the kernel setting, %s", sysctlMaxUserNamespaces, restrictPolicyViewsAdvice)
	}
	if limit == "0" {
		return ""
	}
	if value, ok := read(sysctlUnprivilegedUsernsClone); ok && value == "0" {
		return ""
	}
	if value, ok := read(sysctlAppArmorRestrictUserns); ok && value == "1" {
		unconfined, ok := read(sysctlAppArmorRestrictUnconfined)
		if ok && unconfined == "1" {
			return ""
		}
		if !ok || unconfined == "" {
			unconfined = "unavailable"
		}
		return fmt.Sprintf("standard users can create user namespaces (user.max_user_namespaces=%s): "+
			"kernel.apparmor_restrict_unprivileged_userns=1 restricts only unconfined processes, and with "+
			"kernel.apparmor_restrict_unprivileged_unconfined=%s an unconfined process can still change to an "+
			"AppArmor profile that allows user namespaces (for example with aa-exec); an agent started in a "+
			"private user and mount namespace can be given its own view of the machine policy, runtime "+
			"descriptor and hook socket directory, outside the administrator's enforcement; set "+
			"kernel.apparmor_restrict_unprivileged_unconfined=1 or user.max_user_namespaces=0 (for example "+
			"in /etc/sysctl.d), %s", limit, unconfined, restrictPolicyViewsAdvice)
	}
	return fmt.Sprintf("standard users can create user namespaces (user.max_user_namespaces=%s): "+
		"an agent started in a private user and mount namespace can be given its own view of the "+
		"machine policy, runtime descriptor and hook socket directory, outside the administrator's "+
		"enforcement; set user.max_user_namespaces=0 (for example in /etc/sysctl.d), restrict "+
		"unprivileged user namespaces with SELinux or AppArmor, %s", limit, restrictPolicyViewsAdvice)
}

// unprivilegedPtraceWarning returns the warning text, or "" when Yama
// restricts ptrace to administrators (scope 2 or 3). Unavailable evidence
// cannot establish that tracing is disabled.
func unprivilegedPtraceWarning(read func(path string) (string, bool)) string {
	scope, ok := read(sysctlPtraceScope)
	if !ok {
		return fmt.Sprintf("cannot read %s, so DefenseClaw cannot verify that standard users cannot trace agents and rewrite policy paths; inspect the kernel setting, %s", sysctlPtraceScope, restrictPolicyViewsAdvice)
	}
	if ptraceRestricted([]byte(scope)) {
		return ""
	}
	return fmt.Sprintf("standard users can trace their own processes (kernel.yama.ptrace_scope=%s): a tracer "+
		"such as PRoot can rewrite the paths an agent opens and give it its own view of the machine policy, "+
		"outside the administrator's enforcement; set kernel.yama.ptrace_scope=2 (for example in "+
		"/etc/sysctl.d), %s", scope, restrictPolicyViewsAdvice)
}

func ptraceRestricted(value []byte) bool {
	switch strings.TrimSpace(string(value)) {
	case "2", "3":
		return true
	default:
		return false
	}
}
