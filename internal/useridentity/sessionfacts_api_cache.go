// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

type apiCacheOps interface {
	init() uintptr
	freeContext(uintptr)
	defaultCache(uintptr) uintptr
	namedCache(uintptr, string) uintptr
	close(uintptr, uintptr)
	principal(uintptr, uintptr) string
}

func readAPIPrincipalWithOps(cacheName string, ops apiCacheOps) (string, bool) {
	if len(cacheName) > maxCCacheString {
		return "", true
	}
	context := ops.init()
	if context == 0 {
		return "", true
	}
	defer ops.freeContext(context)
	var cache uintptr
	if cacheName == "" {
		cache = ops.defaultCache(context)
	} else {
		cache = ops.namedCache(context, cacheName)
	}
	if cache == 0 {
		return "", true
	}
	defer ops.close(context, cache)
	return NormalizePrincipal(ops.principal(context, cache)), true
}
