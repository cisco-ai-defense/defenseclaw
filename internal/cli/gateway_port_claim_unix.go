// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Per-user gateways of several accounts share the loopback port range. A
// stopped or crashed gateway leaves its port free, so a new account's init
// could take it and lock the first account out (GAP-1261). Each start
// therefore leaves an empty claim file owned by this account in the shared
// sticky /var/tmp, which init on another account skips (bootstrap.py reads
// the same names), also when the claim's account was deleted (GAP-1704). Only
// the owner can remove a claim; a claim is a hint, never an authorization.
var gatewayPortClaimDir = "/var/tmp"

const gatewayPortClaimPrefix = "defenseclaw-api-port-"

// claimGatewayAPIPort records this account's configured API port and drops
// the account's claims on other ports. Best effort.
func claimGatewayAPIPort(cfg *config.Config) {
	if cfg == nil || cfg.StandaloneEnterprise() ||
		managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return
	}
	port := cfg.Gateway.APIPort
	if port < 1 || port > 65535 {
		return
	}
	own := uint32(os.Getuid())
	target := filepath.Join(gatewayPortClaimDir, gatewayPortClaimPrefix+strconv.Itoa(port))
	if matches, err := filepath.Glob(filepath.Join(gatewayPortClaimDir, gatewayPortClaimPrefix+"*")); err == nil {
		for _, match := range matches {
			if match != target && claimOwnedBy(match, own) {
				_ = os.Remove(match)
			}
		}
	}
	// O_EXCL never follows a symlink; an existing claim stays with its owner.
	if f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644); err == nil {
		_ = f.Close()
	}
}

// removeOwnGatewayPortClaims drops every port claim this account owns. The
// enterprise purge removes the account's per-user install (GAP-1502), as
// per-user `uninstall --all` does (bootstrap.remove_own_api_port_claims), so
// other accounts' init stops skipping the port. Best effort.
func removeOwnGatewayPortClaims() {
	matches, err := filepath.Glob(filepath.Join(gatewayPortClaimDir, gatewayPortClaimPrefix+"*"))
	if err != nil {
		return
	}
	own := uint32(os.Getuid())
	for _, match := range matches {
		if claimOwnedBy(match, own) {
			_ = os.Remove(match)
		}
	}
}

// gatewayPortClaimedByOtherAccount reports whether another account, also a
// deleted one, holds the claim for port, as bootstrap.py's
// _api_port_claimed_by_other_account does. A seam for tests.
var gatewayPortClaimedByOtherAccount = func(port int) bool {
	info, err := os.Lstat(filepath.Join(gatewayPortClaimDir, gatewayPortClaimPrefix+strconv.Itoa(port)))
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid != uint32(os.Getuid())
}

func claimOwnedBy(path string, uid uint32) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid
}
