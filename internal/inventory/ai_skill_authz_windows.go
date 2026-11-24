// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modAuthz                           = windows.NewLazySystemDLL("authz.dll")
	procAuthzInitializeResourceManager = modAuthz.NewProc("AuthzInitializeResourceManager")
	procAuthzInitializeContextFromSid  = modAuthz.NewProc("AuthzInitializeContextFromSid")
	procAuthzAccessCheck               = modAuthz.NewProc("AuthzAccessCheck")
	procAuthzFreeContext               = modAuthz.NewProc("AuthzFreeContext")
)

// authzRMFlagNoAudit is AUTHZ_RM_FLAG_NO_AUDIT.
const authzRMFlagNoAudit = 0x1

// skillAuthzMaxAge is how long the group list of an account is kept: a change
// of the account's groups reaches the next scan after it.
const skillAuthzMaxAge = 5 * time.Minute

// authzAccessRequest is AUTHZ_ACCESS_REQUEST and authzAccessReply is
// AUTHZ_ACCESS_REPLY, for one result and no object type list.
type authzAccessRequest struct {
	DesiredAccess        uint32
	PrincipalSelfSid     *windows.SID
	ObjectTypeList       uintptr
	ObjectTypeListLength uint32
	OptionalArguments    uintptr
}

type authzAccessReply struct {
	ResultListLength      uint32
	GrantedAccessMask     *uint32
	SaclEvaluationResults *uint32
	Error                 *uint32
}

// skillAuthz keeps the resource manager and one client context per account:
// building a context reads the account's groups, too much to do for each file.
var skillAuthz struct {
	sync.Mutex
	manager  uintptr
	contexts map[string]skillAuthzContext
}

type skillAuthzContext struct {
	handle uintptr
	at     time.Time
}

// skillAuthzGranted reports whether Windows itself grants account every right
// in need on descriptor: the account's own groups are read (AuthzAccessCheck
// on a context built from the account's SID), so a deny entry for a group the
// account is in takes the right away and an allow entry for one gives it. Any
// failure to evaluate reads as not granted (GAP-2146).
func skillAuthzGranted(descriptor *windows.SECURITY_DESCRIPTOR, account *windows.SID, need windows.ACCESS_MASK) bool {
	if descriptor == nil || account == nil {
		return false
	}
	skillAuthz.Lock()
	defer skillAuthz.Unlock()
	context, ok := skillAuthzContextFor(account)
	if !ok {
		return false
	}
	request := authzAccessRequest{DesiredAccess: uint32(need)}
	var granted, status uint32
	reply := authzAccessReply{ResultListLength: 1, GrantedAccessMask: &granted, Error: &status}
	done, _, _ := procAuthzAccessCheck.Call(0, context, uintptr(unsafe.Pointer(&request)), 0,
		uintptr(unsafe.Pointer(descriptor)), 0, 0, uintptr(unsafe.Pointer(&reply)), 0)
	return done != 0 && status == 0 && granted&uint32(need) == uint32(need)
}

// skillAuthzContextFor returns the client context of account; the caller
// holds skillAuthz.
func skillAuthzContextFor(account *windows.SID) (uintptr, bool) {
	if skillAuthz.manager == 0 {
		var manager uintptr
		if done, _, _ := procAuthzInitializeResourceManager.Call(authzRMFlagNoAudit, 0, 0, 0, 0,
			uintptr(unsafe.Pointer(&manager))); done == 0 {
			return 0, false
		}
		skillAuthz.manager = manager
	}
	key := account.String()
	if kept, ok := skillAuthz.contexts[key]; ok {
		if time.Since(kept.at) < skillAuthzMaxAge {
			return kept.handle, true
		}
		_, _, _ = procAuthzFreeContext.Call(kept.handle)
		delete(skillAuthz.contexts, key)
	}
	// The identifier is a LUID passed by value: two words on a 32-bit build.
	var handle, done uintptr
	if unsafe.Sizeof(uintptr(0)) == 4 {
		done, _, _ = procAuthzInitializeContextFromSid.Call(0, uintptr(unsafe.Pointer(account)), skillAuthz.manager, 0, 0, 0, 0,
			uintptr(unsafe.Pointer(&handle)))
	} else {
		done, _, _ = procAuthzInitializeContextFromSid.Call(0, uintptr(unsafe.Pointer(account)), skillAuthz.manager, 0, 0, 0,
			uintptr(unsafe.Pointer(&handle)))
	}
	if done == 0 {
		return 0, false
	}
	if skillAuthz.contexts == nil {
		skillAuthz.contexts = map[string]skillAuthzContext{}
	}
	skillAuthz.contexts[key] = skillAuthzContext{handle: handle, at: time.Now()}
	return handle, true
}
