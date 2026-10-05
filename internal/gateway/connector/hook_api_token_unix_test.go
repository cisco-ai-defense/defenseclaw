// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"os/user"
	"reflect"
	"runtime"
	"testing"
)

func TestHookAPITrustedOwnerRejectsUnrelatedUID(t *testing.T) {
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")
	t.Setenv("SUDO_USER", "")
	if hookAPITrustedOwner(^uint32(0)) {
		t.Fatal("hook API trusted an unrelated UID")
	}
}

func TestHookAPITrustedOwnerAcceptsTheStandaloneMacOSServiceAccount(t *testing.T) {
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")
	t.Setenv("SUDO_USER", "")
	if got, want := hookAPIServiceAccounts("darwin"), []string{"defenseclaw", "_defenseclaw"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin service accounts = %v, want %v", got, want)
	}
	if got, want := hookAPIServiceAccounts("linux"), []string{"defenseclaw"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("linux service accounts = %v, want %v", got, want)
	}
	const serviceUID = 4242424
	restore := hookAPILookupUser
	t.Cleanup(func() { hookAPILookupUser = restore })
	hookAPILookupUser = func(name string) (*user.User, error) {
		for _, account := range hookAPIServiceAccounts(runtime.GOOS) {
			if name == account && name == hookAPIServiceAccounts(runtime.GOOS)[len(hookAPIServiceAccounts(runtime.GOOS))-1] {
				return &user.User{Username: name, Uid: "4242424", Gid: "4242424"}, nil
			}
		}
		return nil, errors.New("unknown user")
	}
	if !hookAPITrustedOwner(serviceUID) {
		t.Fatal("the platform gateway service account was not trusted")
	}
	if hookAPITrustedOwner(serviceUID + 1) {
		t.Fatal("an unrelated UID was trusted")
	}
}
