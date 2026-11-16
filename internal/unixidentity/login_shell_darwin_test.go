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
	"os/user"
	"strings"
	"testing"
)

// GAP-2483: the macOS login shell comes from the Open Directory search node.
func TestPlatformLoginShellReadsUserShellThroughTheSearchNode(t *testing.T) {
	var gotArgs []string
	runner := func(_ context.Context, path string, args []string, _ ...outputFilter) (commandResult, error) {
		if path != darwinDSCL {
			t.Fatalf("path = %s", path)
		}
		gotArgs = args
		return commandResult{stdout: []byte("UserShell: /usr/bin/false\n")}, nil
	}
	if got := platformLoginShell(context.Background(), runner, "pm65m"); got != "/usr/bin/false" {
		t.Fatalf("shell = %q", got)
	}
	if strings.Join(gotArgs, " ") != "/Search -read /Users/pm65m UserShell" {
		t.Fatalf("args = %v", gotArgs)
	}
	failing := func(context.Context, string, []string, ...outputFilter) (commandResult, error) {
		return commandResult{exitCode: 56}, nil
	}
	if got := platformLoginShell(context.Background(), failing, "gone"); got != "" {
		t.Fatalf("a record dscl cannot read has no shell, got %q", got)
	}
	erroring := func(context.Context, string, []string, ...outputFilter) (commandResult, error) {
		return commandResult{}, errors.New("boom")
	}
	if got := platformLoginShell(context.Background(), erroring, "x"); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := LoginShell(context.Background(), "bad/name"); got != "" {
		t.Fatalf("an invalid name is never passed to dscl, got %q", got)
	}
}

// The real dscl gives the current account a shell.
func TestLoginShellOfTheCurrentAccount(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if got := LoginShell(context.Background(), current.Username); !strings.HasPrefix(got, "/") {
		t.Fatalf("LoginShell(%s) = %q", current.Username, got)
	}
}
