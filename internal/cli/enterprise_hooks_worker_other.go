//go:build !windows && !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"syscall"
)

func enterpriseHookWorkerSysProcAttr(account enterpriseHookWorkerAccount, supplementary []int) *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{Setsid: true}
	if os.Geteuid() == 0 {
		attr.Credential = enterpriseHookWorkerCredential(account, supplementary, enterpriseHookWorkerMaxGroups)
	}
	return attr
}

// enterpriseHookWorkerMaxGroups is the portable POSIX minimum NGROUPS_MAX.
const enterpriseHookWorkerMaxGroups = 8

// hardenEnterpriseHookWorkerProcess is a no-op on other Unix systems.
func hardenEnterpriseHookWorkerProcess() {}
