// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import "strings"

// identityRefreshPrepare returns the cache key of the SID key (upper case,
// as the hook path keys it).
func identityRefreshPrepare(key string) string {
	return strings.ToUpper(strings.TrimSpace(key))
}
