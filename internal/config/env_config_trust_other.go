// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix && !darwin

package config

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// trustEnvConfigFilePlatform enforces the uid==0 + not-group/world-writable
// check on Unix.
//
// A non-root caller cannot enforce the invariant (Fstat's uid check
// still runs but comparing to 0 is only meaningful for a root caller),
// so we FAIL CLOSED rather than silently return nil. This surfaces
// misconfiguration where LoadEnvConfigEndpoint is wired in a mode that
// isn't managed_enterprise-as-root, instead of trusting arbitrary file
// content in that case. Tests that need to exercise the parse path
// with a non-root euid must set DEFENSECLAW_ENV_CONFIG_SKIP_TRUST=1 —
// trustEnvConfigFile short-circuits before reaching this helper (see
// env_config.go).
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
	if sys.Uid != 0 {
		return fmt.Errorf("must be owned by root (uid %d)", sys.Uid)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("must not be group- or world-writable (mode %o)", info.Mode().Perm())
	}
	return nil
}
