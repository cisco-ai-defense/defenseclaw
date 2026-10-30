// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// identityRefreshSSSCacheNoMatch is the sss_cache exit code for "No cache
// object matched the specified search".
const identityRefreshSSSCacheNoMatch = 2

var (
	identityRefreshSSSCache    = "/usr/sbin/sss_cache"
	identityRefreshGetent      = "/usr/bin/getent"
	identityRefreshNSSwitch    = "/etc/nsswitch.conf"
	identityRefreshSSSDBackend = identityRefreshUsesSSSD
)

// identityRefreshUsesSSSD reports SSSD as an account backend: sss_cache is
// installed and the passwd line of nsswitch.conf names sss.
func identityRefreshUsesSSSD() bool {
	if _, err := os.Stat(identityRefreshSSSCache); err != nil {
		return false
	}
	file, err := os.Open(identityRefreshNSSwitch)
	if err != nil {
		return false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "passwd:") {
			continue
		}
		for _, source := range strings.Fields(strings.TrimPrefix(line, "passwd:")) {
			if source == "sss" {
				return true
			}
		}
	}
	return false
}

// identityRefreshPlatformFlushOSCache drops the SSSD cache: of the named
// account only (sss_cache -u) when name is set, else every entry
// (sss_cache -E).
func identityRefreshPlatformFlushOSCache(name string) (identityRefreshFlush, *enterprisestatus.Message) {
	flush := identityRefreshFlush{Flushed: "none"}
	if !identityRefreshSSSDBackend() {
		flush.Reason = "not_sssd"
		return flush, nil
	}
	args, scope := []string{"-E"}, "all"
	if name != "" {
		args, scope = []string{"-u", name}, "user"
	}
	err := identityRefreshRun(identityRefreshSSSCache, args...)
	var exit *exec.ExitError
	if name != "" && errors.As(err, &exit) && exit.ExitCode() == identityRefreshSSSCacheNoMatch {
		// A local (files) account is not in the SSSD cache: nothing to flush.
		flush.Reason = "not_in_sssd_cache"
		return flush, nil
	}
	if err != nil {
		flush.Reason = "failed"
		return flush, &enterprisestatus.Message{Code: "os_cache_flush_failed", Message: "sss_cache failed: " + err.Error() + "; the facts were re-read from the SSSD cache as it is"}
	}
	if name != "" {
		// Resolve the account again as root, so SSSD holds it before the
		// gateway, with its shorter lookup budget, re-reads it.
		_ = identityRefreshRun(identityRefreshGetent, "initgroups", name)
	}
	flush.Flushed, flush.Method = scope, "sss_cache"
	return flush, nil
}
