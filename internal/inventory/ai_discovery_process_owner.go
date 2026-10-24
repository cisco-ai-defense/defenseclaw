// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// CurrentProcessOwner names the account (user name and uid) whose processes
// a per-user, unmanaged install reports. Such an install belongs to one
// account, so other accounts' agents, PIDs and command lines stay out of its
// inventory and telemetry (GAP-1105, GAP-1194). Both values are empty on
// Windows, which keeps its own process attribution, and when the account
// cannot be resolved.
func CurrentProcessOwner() (name, uid string) {
	if runtime.GOOS == "windows" {
		return "", ""
	}
	current, err := user.Current()
	if err != nil {
		return "", ""
	}
	return current.Username, current.Uid
}

// perUserAccount is the account a per-user, unmanaged install belongs to,
// and so the owner of every signal its scans find; its process detector
// already reports only this account's processes. It is zero where scans
// attribute through profile owners or per-user scans (managed and
// standalone enterprise) and under the Secure Client integration.
func perUserAccount(opts AIDiscoveryOptions) ideOwner {
	if opts.ManagedEnterprise || opts.StandaloneEnterprise || opts.UserScanDir != "" || opts.SecureClient {
		return ideOwner{}
	}
	return currentIDEOwner()
}

// perUserProcessOwners is the processOwners filter of a per-user install, or
// nil when every visible process is in scope (managed and standalone
// enterprise, per-user scans).
func perUserProcessOwners(opts AIDiscoveryOptions) map[string]bool {
	if opts.ManagedEnterprise || opts.StandaloneEnterprise || opts.UserScanDir != "" {
		return nil
	}
	name, uid := CurrentProcessOwner()
	if runtime.GOOS == "windows" {
		// Windows process rows name their account DOMAIN\account, and a
		// standard account cannot open another account's process, so those
		// rows had no user and no start time ("Up 0s") and were listed as
		// this account's (GAP-1296).
		name = currentWindowsAccount()
	}
	owners := map[string]bool{}
	for _, owner := range []string{name, uid} {
		if owner != "" {
			owners[owner] = true
		}
	}
	if len(owners) == 0 {
		return nil
	}
	return owners
}

// keepEvidencePath reports whether a detector records an evidence row's raw
// path: when raw paths are stored, and for the scan that attributes by them
// (ownHomeRoots).
func (s *ContinuousDiscoveryService) keepEvidencePath() bool {
	return s.opts.StoreRawLocalPaths || s.ownHomeRoots != nil
}

// perUserOwnHomeRoots is the own home of a per-user install that also scans
// other folders (ai_discovery.home_dirs), or nil when every finding belongs
// to the account anyway (one folder) or to no single account.
func (s *ContinuousDiscoveryService) perUserOwnHomeRoots() []string {
	home := strings.TrimSpace(s.opts.HomeDir)
	if s.account.id == "" || home == "" || len(s.homesToScan()) <= 1 {
		return nil
	}
	home = filepath.Clean(home)
	roots := []string{home}
	if resolved, err := filepath.EvalSymlinks(home); err == nil && filepath.Clean(resolved) != home {
		roots = append(roots, filepath.Clean(resolved))
	}
	return roots
}

// evidenceInOwnHome reports a finding whose every evidence path lies in the
// per-user account's own home (GAP-1278). A finding without raw paths
// proves nothing.
func (s *ContinuousDiscoveryService) evidenceInOwnHome(evidence []AIEvidence) bool {
	if s.ownHomeRoots == nil || len(evidence) == 0 {
		return false
	}
	for _, ev := range evidence {
		if ev.RawPath == "" || !evidenceInsideHome([]AIEvidence{ev}, s.ownHomeRoots) {
			return false
		}
	}
	return true
}
