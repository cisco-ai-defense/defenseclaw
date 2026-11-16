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

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// identityRefreshFlushDirectoryCaches empties the Open Directory caches the
// way the hook guardian does after an outage; replaceable in tests.
var identityRefreshFlushDirectoryCaches = enterprisehooks.FlushDirectoryCaches

// identityRefreshPlatformFlushOSCache flushes the Directory Services and
// membership caches (dscacheutil -flushcache, dsmemberutil flushcache).
// macOS has no per-account flush, so with --user nothing is flushed: the
// other accounts keep their cache.
func identityRefreshPlatformFlushOSCache(name string) (identityRefreshFlush, *enterprisestatus.Message) {
	flush := identityRefreshFlush{Flushed: "none"}
	if name != "" {
		flush.Reason = "no_per_user_flush"
		return flush, &enterprisestatus.Message{Code: "os_cache_not_flushed",
			Message: "macOS has no per-account directory cache flush; run without --user to flush the whole cache"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), identityRefreshCommandTimeout)
	defer cancel()
	if err := identityRefreshFlushDirectoryCaches(ctx); err != nil {
		flush.Reason = "failed"
		return flush, &enterprisestatus.Message{Code: "os_cache_flush_failed", Message: "the Open Directory cache flush failed: " + err.Error()}
	}
	flush.Flushed, flush.Method = "all", "dscacheutil"
	return flush, nil
}
