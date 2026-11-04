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
//go:cgo_import_dynamic krb5_cc_resolve krb5_cc_resolve "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"
//go:cgo_import_dynamic krb5_cc_close krb5_cc_close "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"
//go:cgo_import_dynamic krb5_cc_get_principal krb5_cc_get_principal "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"
//go:cgo_import_dynamic krb5_free_principal krb5_free_principal "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"
//go:cgo_import_dynamic krb5_unparse_name krb5_unparse_name "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"
//go:cgo_import_dynamic krb5_free_unparsed_name krb5_free_unparsed_name "/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos"

var (
	krb5InitContextAddr      uintptr
	krb5FreeContextAddr      uintptr
	krb5CCResolveAddr        uintptr
	krb5CCCloseAddr          uintptr
	krb5CCGetPrincipalAddr   uintptr
	krb5FreePrincipalAddr    uintptr
	krb5UnparseNameAddr      uintptr
	krb5FreeUnparsedNameAddr uintptr
)

//go:linkname sessionFactsLibcall syscall.syscall
func sessionFactsLibcall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

// readAPIPrincipal reads a default or named API: cache through the system
// Kerberos API. No cache or principal is a settled empty result.
func readAPIPrincipal(cacheName string) (string, bool) {
	if len(cacheName) > maxCCacheString {
		return "", true
	}
	name, err := syscall.BytePtrFromString(CCacheAPI + ":" + cacheName)
	if err != nil {
		return "", true
	}
	context, cache, principal := new(uintptr), new(uintptr), new(uintptr)
	rendered := new(unsafe.Pointer)
	if status, _, _ := sessionFactsLibcall(krb5InitContextAddr, uintptr(unsafe.Pointer(context)), 0, 0); int32(status) != 0 || *context == 0 {
		return "", true
	}
	defer sessionFactsLibcall(krb5FreeContextAddr, *context, 0, 0)
	if status, _, _ := sessionFactsLibcall(krb5CCResolveAddr, *context, uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(cache))); int32(status) != 0 || *cache == 0 {
		return "", true
	}
	runtime.KeepAlive(name)
	defer sessionFactsLibcall(krb5CCCloseAddr, *context, *cache, 0)
	if status, _, _ := sessionFactsLibcall(krb5CCGetPrincipalAddr, *context, *cache,
		uintptr(unsafe.Pointer(principal))); int32(status) != 0 || *principal == 0 {
		return "", true
	}
	defer sessionFactsLibcall(krb5FreePrincipalAddr, *context, *principal, 0)
	if status, _, _ := sessionFactsLibcall(krb5UnparseNameAddr, *context, *principal,
		uintptr(unsafe.Pointer(rendered))); int32(status) != 0 || *rendered == nil {
		return "", true
	}
	defer sessionFactsLibcall(krb5FreeUnparsedNameAddr, *context, uintptr(*rendered), 0)
	value := make([]byte, 0, maxCCacheString)
	for offset := uintptr(0); offset <= maxCCacheString; offset++ {
		c := *(*byte)(unsafe.Add(*rendered, offset))
		if c == 0 {
			return NormalizePrincipal(string(value)), true
		}
		value = append(value, c)
	}
	return "", true
}
