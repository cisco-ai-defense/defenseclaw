// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestHookAPITokenLocationWalksAncestorChainOnce(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	hooksDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(hooksDir, "codex.token")
	var inspected []string
	element := func(path string) error {
		inspected = append(inspected, "element:"+path)
		return nil
	}
	chain := func(path string) error {
		inspected = append(inspected, "chain:"+path)
		return nil
	}
	if err := validateHookAPITokenLocationWith(dataDir, tokenPath, element, chain); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inspected, []string{"element:" + dataDir, "chain:" + hooksDir}) {
		t.Fatalf("validated directories = %v, want the data dir as protected element and the hooks chain once", inspected)
	}

	// The single walk still checks dataDir as an ancestor. A token under a
	// writable parent must remain unusable even when the token file is sound.
	if err := os.Chmod(dataDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateHookAPITokenLocation(dataDir, tokenPath); err == nil {
		t.Fatal("accepted a token below a writable data directory")
	}
}

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
