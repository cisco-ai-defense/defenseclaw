// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import "github.com/defenseclaw/defenseclaw/internal/enterprisestatus"

// identityRefreshPlatformFlushOSCache flushes the Directory Services and
// membership caches. macOS has no per-account flush, so with --user nothing
// is flushed: the other accounts keep their cache.
func identityRefreshPlatformFlushOSCache(name string) (identityRefreshFlush, *enterprisestatus.Message) {
	flush := identityRefreshFlush{Flushed: "none"}
	if name != "" {
		flush.Reason = "no_per_user_flush"
		return flush, &enterprisestatus.Message{Code: "os_cache_not_flushed",
			Message: "macOS has no per-account directory cache flush; run without --user to flush the whole cache"}
	}
	for _, step := range [][]string{{"/usr/bin/dscacheutil", "-flushcache"}, {"/usr/sbin/dsmemberutil", "flushcache"}} {
		if err := identityRefreshRun(step[0], step[1:]...); err != nil {
			flush.Reason = "failed"
			return flush, &enterprisestatus.Message{Code: "os_cache_flush_failed", Message: step[0] + " failed: " + err.Error()}
		}
	}
	flush.Flushed, flush.Method = "all", "dscacheutil"
	return flush, nil
}
