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

package cloud

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

// defaultLibPath is the ships-with-Secure-Client install location of
// libcmidapi.dylib on macOS. Overridable via config or the
// DEFENSECLAW_CMID_LIB_PATH env var.
const defaultLibPath = "/opt/cisco/secureclient/cloudmanagement/lib/libcmidapi.dylib"

// dylibCaller binds libcmidapi.dylib symbols via purego and implements
// caller. Instances hold the dlopen handle open only for the duration of
// a single Refresh cycle — Close dlopens it. This matches Cisco's
// documented "load afresh, unload as soon as you have the values"
// guidance.
type dylibCaller struct {
	handle uintptr

	refreshToken  func() int32
	getID         func(buf unsafe.Pointer, buflen *int32) int32
	getToken      func(buf unsafe.Pointer, buflen *int32) int32
	getBusinessID func(buf unsafe.Pointer, buflen *int32) int32
	getURL        func(kind int32, buf unsafe.Pointer, buflen *int32) int32
}

func newLibCaller(path string) (caller, error) {
	handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("dlopen %s: %w", path, err)
	}
	c := &dylibCaller{handle: handle}
	// If any RegisterLibFunc call fails (missing symbol), close the handle
	// before returning so we don't leak it.
	defer func() {
		if err != nil {
			_ = purego.Dlclose(handle)
		}
	}()
	if err = registerFunc(&c.refreshToken, handle, "cmid_refresh_token"); err != nil {
		return nil, err
	}
	if err = registerFunc(&c.getID, handle, "cmid_get_id"); err != nil {
		return nil, err
	}
	if err = registerFunc(&c.getToken, handle, "cmid_get_token"); err != nil {
		return nil, err
	}
	if err = registerFunc(&c.getBusinessID, handle, "cmid_get_business_id"); err != nil {
		return nil, err
	}
	if err = registerFunc(&c.getURL, handle, "cmid_get_url"); err != nil {
		return nil, err
	}
	return c, nil
}

// registerFunc wraps purego.RegisterLibFunc so a missing symbol surfaces
// as a Go error rather than a panic mid-call.
func registerFunc(fnPtr any, handle uintptr, name string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("cmid: register %s: %v", name, r)
		}
	}()
	purego.RegisterLibFunc(fnPtr, handle, name)
	return nil
}

func (c *dylibCaller) RefreshToken() int32 {
	return c.refreshToken()
}

func (c *dylibCaller) GetID(buf []byte, buflen *int32) int32 {
	rc := c.getID(bufPtr(buf), buflen)
	runtime.KeepAlive(buf)
	return rc
}

func (c *dylibCaller) GetToken(buf []byte, buflen *int32) int32 {
	rc := c.getToken(bufPtr(buf), buflen)
	runtime.KeepAlive(buf)
	return rc
}

func (c *dylibCaller) GetBusinessID(buf []byte, buflen *int32) int32 {
	rc := c.getBusinessID(bufPtr(buf), buflen)
	runtime.KeepAlive(buf)
	return rc
}

func (c *dylibCaller) GetURL(kind int32, buf []byte, buflen *int32) int32 {
	rc := c.getURL(kind, bufPtr(buf), buflen)
	runtime.KeepAlive(buf)
	return rc
}

func (c *dylibCaller) Close() error {
	if c.handle == 0 {
		return nil
	}
	h := c.handle
	c.handle = 0
	if err := purego.Dlclose(h); err != nil {
		return fmt.Errorf("cmid: dlclose: %w", err)
	}
	return nil
}

// bufPtr returns nil for empty/nil slices (so the C code sees NULL, which
// is what the size-query path expects) and a pointer to the first byte
// otherwise.
func bufPtr(buf []byte) unsafe.Pointer {
	if len(buf) == 0 {
		return nil
	}
	return unsafe.Pointer(&buf[0])
}
