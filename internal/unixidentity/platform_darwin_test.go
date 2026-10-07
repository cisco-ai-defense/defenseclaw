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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
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

// TestAccountGroupIDsListPastTheOSUserLimit pins GAP-0201: os/user lists at
// most 256 groups on macOS, failing for an account in more or cutting the list
// at 256 without an error, so a list that failed or filled the buffer is read
// again from `id -G`: whole, once each, refused past maxDirectoryGroups, and
// never answered with the cut-short list when id fails.
func TestAccountGroupIDsListPastTheOSUserLimit(t *testing.T) {
	if err := validateTrustedTool(darwinID); err != nil {
		t.Skip(err)
	}
	account := &user.User{Username: "alice", Uid: "501", Gid: "20"}
	listErr := errors.New("user: list groups for alice failed")
	var gotArgs []string
	runWith := func(gids int, exitCode int) commandRunner {
		return func(_ context.Context, path string, args []string) (commandResult, error) {
			gotArgs = args
			var out strings.Builder
			for gid := 20; gid < 20+gids; gid++ {
				fmt.Fprintf(&out, "%d ", gid)
			}
			out.WriteString("20\n") // the primary group repeats
			return commandResult{stdout: []byte(out.String()), exitCode: exitCode}, nil
		}
	}
	cut := make([]string, osUserGroupBuffer)
	for i := range cut {
		cut[i] = strconv.Itoa(20 + i)
	}
	for name, ids := range map[string][]string{"failed": nil, "cut at 256": cut} {
		var listing error
		if ids == nil {
			listing = listErr
		}
		gotArgs = nil
		got, err := platformAccountGroupIDs(context.Background(), runWith(437, 0), account, ids, listing)
		if err != nil || len(got) != 437 || got[0] != "20" || strings.Join(gotArgs, " ") != "-G -- alice" {
			t.Fatalf("%s: ids = %d, err = %v, id args %v; want the 437 groups once each from id -G -- alice", name, len(got), err, gotArgs)
		}
		if _, err := platformAccountGroupIDs(context.Background(), runWith(3, 1), account, ids, listing); err == nil {
			t.Fatalf("%s: a failing id answered with the os/user list", name)
		}
	}
	whole := []string{"20", "12", "61"}
	gotArgs = nil
	if got, err := platformAccountGroupIDs(context.Background(), runWith(1, 1), account, whole, nil); err != nil || len(got) != 3 || gotArgs != nil {
		t.Fatalf("a list below the buffer = %v, %v (id args %v); want it as is without running id", got, err, gotArgs)
	}
	if _, err := platformAccountGroupIDs(context.Background(), runWith(maxDirectoryGroups+1, 0), account, nil, listErr); err == nil {
		t.Fatal("an account in more than maxDirectoryGroups groups listed")
	}
}
