// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package useridentity

import (
	"runtime"
	"syscall"
	"unsafe"
)

// The system Kerberos framework reads the same API: cache as macOS klist.
// These calls preserve the current session-facts file cache without a helper
// process on a cold read. Release binaries are built without cgo.
//
//go:cgo_import_dynamic krb5_init_context krb5_init_context "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"
//go:cgo_import_dynamic krb5_free_context krb5_free_context "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"
//go:cgo_import_dynamic krb5_cc_default krb5_cc_default "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"
//go:cgo_import_dynamic krb5_cc_resolve krb5_cc_resolve "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"
//go:cgo_import_dynamic krb5_cc_close krb5_cc_close "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"
//go:cgo_import_dynamic krb5_cc_get_principal krb5_cc_get_principal "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"
//go:cgo_import_dynamic krb5_free_principal krb5_free_principal "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"
//go:cgo_import_dynamic krb5_unparse_name krb5_unparse_name "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"
//go:cgo_import_dynamic krb5_free_unparsed_name krb5_free_unparsed_name "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"

var (
	krb5InitContextAddr      uintptr
	krb5FreeContextAddr      uintptr
	krb5CCDefaultAddr        uintptr
	krb5CCResolveAddr        uintptr
	krb5CCCloseAddr          uintptr
	krb5CCGetPrincipalAddr   uintptr
	krb5FreePrincipalAddr    uintptr
	krb5UnparseNameAddr      uintptr
	krb5FreeUnparsedNameAddr uintptr
)

//go:linkname sessionFactsLibcall syscall.syscall
func sessionFactsLibcall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

type nativeAPICacheOps struct{}

// readAPIPrincipal reads a default or named API: cache through the system
// Kerberos API. No cache or principal is a settled empty result.
func readAPIPrincipal(cacheName string) (string, bool) {
	return readAPIPrincipalWithOps(cacheName, nativeAPICacheOps{})
}

func (nativeAPICacheOps) init() uintptr {
	context := new(uintptr)
	if status, _, _ := sessionFactsLibcall(krb5InitContextAddr, uintptr(unsafe.Pointer(context)), 0, 0); int32(status) != 0 {
		return 0
	}
	return *context
}

func (nativeAPICacheOps) freeContext(context uintptr) {
	sessionFactsLibcall(krb5FreeContextAddr, context, 0, 0)
}

func (nativeAPICacheOps) defaultCache(context uintptr) uintptr {
	cache := new(uintptr)
	if status, _, _ := sessionFactsLibcall(krb5CCDefaultAddr, context, uintptr(unsafe.Pointer(cache)), 0); int32(status) != 0 {
		return 0
	}
	return *cache
}

func (nativeAPICacheOps) namedCache(context uintptr, cacheName string) uintptr {
	name, err := syscall.BytePtrFromString(CCacheAPI + ":" + cacheName)
	if err != nil {
		return 0
	}
	cache := new(uintptr)
	status, _, _ := sessionFactsLibcall(krb5CCResolveAddr, context, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(cache)))
	runtime.KeepAlive(name)
	if int32(status) != 0 {
		return 0
	}
	return *cache
}

func (nativeAPICacheOps) close(context, cache uintptr) {
	sessionFactsLibcall(krb5CCCloseAddr, context, cache, 0)
}

func (nativeAPICacheOps) principal(context, cache uintptr) string {
	principal := new(uintptr)
	if status, _, _ := sessionFactsLibcall(krb5CCGetPrincipalAddr, context, cache,
		uintptr(unsafe.Pointer(principal))); int32(status) != 0 || *principal == 0 {
		return ""
	}
	defer sessionFactsLibcall(krb5FreePrincipalAddr, context, *principal, 0)
	rendered := new(unsafe.Pointer)
	if status, _, _ := sessionFactsLibcall(krb5UnparseNameAddr, context, *principal,
		uintptr(unsafe.Pointer(rendered))); int32(status) != 0 || *rendered == nil {
		return ""
	}
	defer sessionFactsLibcall(krb5FreeUnparsedNameAddr, context, uintptr(*rendered), 0)
	value := make([]byte, 0, maxCCacheString)
	for offset := uintptr(0); offset <= maxCCacheString; offset++ {
		c := *(*byte)(unsafe.Add(*rendered, offset))
		if c == 0 {
			return string(value)
		}
		value = append(value, c)
	}
	return ""
}
