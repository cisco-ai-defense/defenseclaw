//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"testing"
)

func TestParseDSCLUniqueIDsResolvesAndSkipsDaemonAccounts(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	output := fmt.Sprintf("_spotlight 89\n%s %s\nbogus notanumber\nghost 4000000123\n", current.Username, current.Uid)
	accounts := parseDSCLUniqueIDs(output, NewOSUserResolver(context.Background()))
	if len(accounts) != 1 || accounts[0].Name != current.Username {
		t.Fatalf("parseDSCLUniqueIDs = %+v", accounts)
	}
	if accounts[0].UID != os.Getuid() {
		t.Fatalf("uid = %d, want %d", accounts[0].UID, os.Getuid())
	}
}

func TestDarwinDefaultResolverFindsCurrentUser(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	account, err := Default(context.Background()).LookupUser(current.Username)
	if err != nil || account.Home != current.HomeDir {
		t.Fatalf("LookupUser(%s) = %+v, %v", current.Username, account, err)
	}
	if _, err := Default(context.Background()).LookupUser("dc-no-such-user-7f3a"); !IsNotFound(err) {
		t.Fatalf("missing account error = %v, want ErrNotFound", err)
	}
}

// DirectoryConfigured was hard-coded true on macOS, so on an unbound Mac a
// deleted local account whose source was not recorded as local was kept
// for good. It now follows this Mac's search policy.
func TestDarwinDirectoryConfiguredFollowsTheSearchPolicy(t *testing.T) {
	output, err := exec.Command(darwinDSCL, "-plist", "/Search", "-read", "/", "SearchPath", "CSPSearchPath", "NSPSearchPath").Output()
	if err != nil {
		t.Skipf("dscl: %v", err)
	}
	want := ParseDSCLSearchPolicyDirectoryConfigured(output)
	if got := DirectoryConfigured(); got != want {
		t.Fatalf("DirectoryConfigured() = %v, but the search policy says %v:\n%s", got, want, output)
	}
	if !want && !strings.Contains(string(output), "/Local/Default") {
		t.Fatalf("an unbound search policy must list /Local/Default:\n%s", output)
	}
	t.Logf("directory configured: %v", want)
}
