//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"syscall"
)

// enterpriseHookWorkerSysProcAttr starts the worker in its own session,
// kills it if the guardian dies, and — from a root guardian — drops to the
// exact target uid and gid with the account's own group list.
func enterpriseHookWorkerSysProcAttr(account enterpriseHookWorkerAccount, supplementary []int) *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
	if os.Geteuid() == 0 {
		attr.Credential = enterpriseHookWorkerCredential(account, supplementary, enterpriseHookWorkerMaxGroups)
	}
	return attr
}

// enterpriseHookWorkerMaxGroups is Linux's NGROUPS_MAX.
const enterpriseHookWorkerMaxGroups = 65536

// hardenEnterpriseHookWorkerProcess marks the worker non-dumpable so other
// processes of the target user cannot attach to it or read its memory
// (the request carries scoped hook tokens) once it is running.
func hardenEnterpriseHookWorkerProcess() {
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0)
}
