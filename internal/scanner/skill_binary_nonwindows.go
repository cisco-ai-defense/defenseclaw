//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var lookSkillScanner = exec.LookPath

// resolveDefaultSkillScanner runs the skill-scanner of a per-user install
// through the DefenseClaw entry point next to it. An install without that
// entry point (an older wheel, a source checkout) keeps the bare command; a
// configured binary, Secure Client and the managed runtime are left as is.
func resolveDefaultSkillScanner(binary string, secureClient bool) (string, error) {
	if secureClient || binary != "skill-scanner" || managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return binary, nil
	}
	found, err := lookSkillScanner(binary)
	if err != nil {
		return binary, nil
	}
	installed, err := filepath.EvalSymlinks(found)
	if err != nil {
		return binary, nil
	}
	entry := filepath.Join(filepath.Dir(installed), judgeCompatSkillScanner)
	if !sameOwnerExecutable(entry, installed) {
		return binary, nil
	}
	return entry, nil
}

// sameOwnerExecutable reports whether path is an executable regular file
// (not a link) that only its owner can change, owned by the owner of peer.
func sameOwnerExecutable(path, peer string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 || info.Mode()&0o022 != 0 {
		return false
	}
	peerInfo, err := os.Stat(peer)
	if err != nil {
		return false
	}
	own, ok := info.Sys().(*syscall.Stat_t)
	other, peerOK := peerInfo.Sys().(*syscall.Stat_t)
	return ok && peerOK && own.Uid == other.Uid
}
