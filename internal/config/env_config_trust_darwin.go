// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// trustEnvConfigFilePlatform judges env_config.json, which the Secure Client
// installer writes and owns. A non-root caller still fails closed, and the
// caller has already refused anything but a regular file opened without
// following links. Ownership, mode and link-count drift is accepted so a
// re-permissioned file never closes inspection: an administrator owner or
// wheel/admin group write is logged as accepted drift, and a standard-user
// owner, other write, another group's write or an extra hard link (someone
// who could redirect the endpoint) is logged as a boundary finding. The hook
// guardian removes group and other write; the endpoint value is still
// validated by the caller.
func trustEnvConfigFilePlatform(info os.FileInfo) error {
	if os.Geteuid() != 0 {
		return errors.New(
			"env_config trust requires the caller to run as root; " +
				"set DEFENSECLAW_ENV_CONFIG_SKIP_TRUST=1 for parser-only test fixtures",
		)
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("file metadata not verifiable on this platform")
	}
	drift, untrusted := judgeEnvConfigMetadata(sys.Uid, sys.Gid, info.Mode().Perm(), uint64(sys.Nlink), managed.IsAdministratorUID)
	if len(drift) == 0 {
		return nil
	}
	marker := managed.MarkerAccept
	if untrusted {
		marker = managed.MarkerBoundary
	}
	managed.EmitResilienceEventOnce(DefaultEnvConfigPath, marker, map[string]string{
		"path":   DefaultEnvConfigPath,
		"reason": "env_config.json permissions drifted; accepted: " + strings.Join(drift, "; "),
	})
	return nil
}

// judgeEnvConfigMetadata lists how env_config.json differs from root-owned
// and not group or other writable, and whether a principal outside root,
// wheel and admin could have written it.
func judgeEnvConfigMetadata(uid, gid uint32, perm os.FileMode, links uint64, admin func(uint32) bool) ([]string, bool) {
	var drift []string
	untrusted := false
	if uid != 0 {
		if admin(uid) {
			drift = append(drift, fmt.Sprintf("owned by administrator uid %d", uid))
		} else {
			drift = append(drift, fmt.Sprintf("owned by uid %d", uid))
			untrusted = true
		}
	}
	if perm&0o020 != 0 {
		drift = append(drift, fmt.Sprintf("group gid %d can write (mode %o)", gid, perm))
		if gid != 0 && gid != 80 {
			untrusted = true
		}
	}
	if perm&0o002 != 0 {
		drift = append(drift, fmt.Sprintf("other can write (mode %o)", perm))
		untrusted = true
	}
	if links > 1 {
		drift = append(drift, fmt.Sprintf("has %d hard links", links))
		untrusted = true
	}
	return drift, untrusted
}
