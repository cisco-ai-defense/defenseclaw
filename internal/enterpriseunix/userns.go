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
	"fmt"
	"io"
	"os"
	"strings"
)

// codeUserNamespaces warns that standard users can create user namespaces.
const codeUserNamespaces = "unprivileged_user_namespaces"

// Kernel settings that decide whether an unprivileged process can create a
// user namespace (and, inside it, a mount namespace of its own).
const (
	sysctlMaxUserNamespaces       = "/proc/sys/user/max_user_namespaces"
	sysctlUnprivilegedUsernsClone = "/proc/sys/kernel/unprivileged_userns_clone"
	sysctlAppArmorRestrictUserns  = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
	// kernel.apparmor_restrict_unprivileged_unconfined decides whether an
	// unconfined process may change to another AppArmor profile (aa-exec,
	// change_profile). Ubuntu 24.04 ships it at 0, so without it a standard
	// user can enter a profile that allows user namespaces and create one
	// despite kernel.apparmor_restrict_unprivileged_userns=1.
	sysctlAppArmorRestrictUnconfined = "/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined"
)

// warnUnprivilegedUserNamespaces adds a verify warning on Linux when a
// standard user can create a private user and mount namespace. Inside one,
// the user is uid 0 for their own processes and can mount over the
// root-owned vendor machine policy, runtime descriptor and hook socket
// directory, so an agent started there does not see the administrator's
// enforcement. DefenseClaw cannot close that from user space; the host
// setting can.
func (l *lifecycle) warnUnprivilegedUserNamespaces() {
	if l.env.GOOS != "linux" {
		return
	}
	read := func(path string) (string, bool) {
		file, err := os.Open(l.env.P(path))
		if err != nil {
			return "", false
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, 64))
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(string(data)), true
	}
	if message := unprivilegedUserNamespaceWarning(read); message != "" {
		l.result.AddWarning(codeUserNamespaces, message)
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
	if !ok || limit == "0" {
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
			"in /etc/sysctl.d)", limit, unconfined)
	}
	return fmt.Sprintf("standard users can create user namespaces (user.max_user_namespaces=%s): "+
		"an agent started in a private user and mount namespace can be given its own view of the "+
		"machine policy, runtime descriptor and hook socket directory, outside the administrator's "+
		"enforcement; set user.max_user_namespaces=0 (for example in /etc/sysctl.d) or restrict "+
		"unprivileged user namespaces with SELinux or AppArmor", limit)
}
