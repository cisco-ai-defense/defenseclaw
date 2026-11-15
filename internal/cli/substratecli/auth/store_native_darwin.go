// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package auth

import (
	"runtime"
	"syscall"
	"unsafe"
)

// The launcher keeps its sealing key with the Security framework itself
// (GAP-0165), not through /usr/bin/security: an item the launcher creates
// trusts the launcher binary, so reading it asks nothing, also from SSH or
// tmux while the keychain is unlocked, and any other program (the security
// tool included) needs the person's approval. Release binaries are built
// without cgo; the calls go through assembly trampolines, as
// internal/useridentity does for Kerberos.

//go:cgo_import_dynamic SecKeychainFindGenericPassword SecKeychainFindGenericPassword "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic SecKeychainAddGenericPassword SecKeychainAddGenericPassword "/System/Library/Frameworks/Security.framework/Versions/A/Security"
//go:cgo_import_dynamic SecKeychainItemFreeContent SecKeychainItemFreeContent "/System/Library/Frameworks/Security.framework/Versions/A/Security"

var (
	secFindGenericPasswordAddr uintptr
	secAddGenericPasswordAddr  uintptr
	secItemFreeContentAddr     uintptr
)

//go:linkname secLibcall9 syscall.syscall9
func secLibcall9(fn, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2 uintptr, err syscall.Errno)

// secNative is the Security framework.
type secNative struct{}

func newNativeKeychain() nativeKeychain { return secNative{} }

func (secNative) find(service, account string) ([]byte, int32) {
	s, a := []byte(service), []byte(account)
	var plen uint32
	var pdata unsafe.Pointer
	r, _, _ := secLibcall9(secFindGenericPasswordAddr,
		0,
		uintptr(len(s)), uintptr(unsafe.Pointer(&s[0])),
		uintptr(len(a)), uintptr(unsafe.Pointer(&a[0])),
		uintptr(unsafe.Pointer(&plen)), uintptr(unsafe.Pointer(&pdata)),
		0, 0)
	runtime.KeepAlive(s)
	runtime.KeepAlive(a)
	st := int32(r)
	if st != 0 || pdata == nil {
		return nil, st
	}
	out := make([]byte, plen)
	copy(out, unsafe.Slice((*byte)(pdata), plen)) // the framework owns it until FreeContent
	secLibcall9(secItemFreeContentAddr, 0, uintptr(pdata), 0, 0, 0, 0, 0, 0, 0)
	return out, 0
}

func (secNative) add(service, account string, secret []byte) int32 {
	s, a := []byte(service), []byte(account)
	if len(secret) == 0 {
		return -50 // errSecParam
	}
	r, _, _ := secLibcall9(secAddGenericPasswordAddr,
		0,
		uintptr(len(s)), uintptr(unsafe.Pointer(&s[0])),
		uintptr(len(a)), uintptr(unsafe.Pointer(&a[0])),
		uintptr(len(secret)), uintptr(unsafe.Pointer(&secret[0])),
		0, 0)
	runtime.KeepAlive(s)
	runtime.KeepAlive(a)
	runtime.KeepAlive(secret)
	return int32(r)
}
