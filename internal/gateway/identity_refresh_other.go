// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

// identityRefreshPrepare returns the cache key of the uid key. On Linux and
// macOS the lookup itself asks NSS or Open Directory, after the CLI's OS
// cache flush (--flush-os-cache), so nothing else is cached to make current.
func identityRefreshPrepare(key string) string { return key }
