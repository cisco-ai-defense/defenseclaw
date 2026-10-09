// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// accountRunner answers getent after systemd-sysusers "creates" the account.
// With sysusersNoop, systemd-sysusers exits 0 without creating it and only
// useradd does.
type accountRunner struct {
	created      bool
	sysusersNoop bool
	calls        [][]string
}

func (r *accountRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	switch {
	case name == "getent" && len(args) == 2 && args[0] == "passwd":
		if !r.created {
			return CommandResult{ExitCode: 2}, errors.New("exit status 2")
		}
		return CommandResult{Stdout: []byte("defenseclaw:x:991:988:DefenseClaw gateway:/var/lib/defenseclaw:/usr/sbin/nologin\n")}, nil
	case name == "getent" && len(args) == 2 && args[0] == "group":
		if !r.created {
			return CommandResult{ExitCode: 2}, errors.New("exit status 2")
		}
		return CommandResult{Stdout: []byte("defenseclaw:x:988:\n")}, nil
	case name == "systemd-sysusers":
		if r.sysusersNoop {
			return CommandResult{Stderr: []byte("Failed to check if group defenseclaw already exists: Connection refused\n")}, nil
		}
		r.created = true
		return CommandResult{}, nil
	case name == "groupadd" && r.sysusersNoop:
		return CommandResult{}, nil
	case name == "useradd" && r.sysusersNoop:
		r.created = true
		return CommandResult{}, nil
	}
	return CommandResult{ExitCode: 1}, errors.New("exit status 1")
}

// On a host whose nsswitch.conf lists sss while sssd is masked,
// systemd-sysusers exits 0 without creating the service account; the
// account is then created with groupadd and useradd instead of the install
// failing with "service account defenseclaw was not created" (GAP-1214).
func TestLinuxAccountEnsureFallsBackToUseraddWhenSysusersCreatesNothing(t *testing.T) {
	runner := &accountRunner{sysusersNoop: true}
	accounts := &linuxAccounts{env: &Env{GOOS: "linux", Runner: runner}}
	account, err := accounts.Ensure(context.Background(), "defenseclaw")
	if err != nil {
		t.Fatal(err)
	}
	var tools []string
	for _, call := range runner.calls {
		if call[0] == "groupadd" || call[0] == "useradd" {
			tools = append(tools, call[0])
		}
	}
	if !account.Created || account.UID != 991 || strings.Join(tools, ",") != "groupadd,useradd" {
		t.Fatalf("account = %+v, tools = %q, want the account created with groupadd and useradd", account, tools)
	}
}

// A fresh host has no sysusers.d file yet when the account is created, so
// the entry must be passed inline instead of by path.
func TestLinuxAccountEnsureCreatesTheAccountFromInlineSysusersEntries(t *testing.T) {
	runner := &accountRunner{}
	accounts := &linuxAccounts{env: &Env{GOOS: "linux", Runner: runner}}
	account, err := accounts.Ensure(context.Background(), "defenseclaw")
	if err != nil {
		t.Fatal(err)
	}
	if !account.Created || account.UID != 991 || account.GID != 988 {
		t.Fatalf("account = %+v", account)
	}
	var sysusers []string
	for _, call := range runner.calls {
		if call[0] == "systemd-sysusers" {
			sysusers = call
		}
	}
	if len(sysusers) < 3 || sysusers[1] != "--inline" {
		t.Fatalf("systemd-sysusers call = %q, want --inline entries", sysusers)
	}
	for _, arg := range sysusers[2:] {
		if strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "#") {
			t.Fatalf("systemd-sysusers got a path or comment %q", arg)
		}
	}
	if !strings.HasPrefix(sysusers[2], "u defenseclaw ") {
		t.Fatalf("sysusers entry = %q", sysusers[2])
	}
}

// A pre-existing account someone can sign in to is refused as the gateway
// service account instead of being adopted (GAP-0433).
func TestLinuxAccountEnsureRefusesALoginAccount(t *testing.T) {
	runner := &loginAccountRunner{}
	accounts := &linuxAccounts{env: &Env{GOOS: "linux", Runner: runner}}
	_, err := accounts.Ensure(context.Background(), "defenseclaw")
	if err == nil || !strings.Contains(err.Error(), "login shell /bin/bash") || !strings.Contains(err.Error(), "userdel defenseclaw") {
		t.Fatalf("Ensure error = %v, want a login-account refusal", err)
	}
	for _, call := range runner.calls {
		if call[0] == "systemd-sysusers" || call[0] == "useradd" {
			t.Fatalf("Ensure ran %q for an existing account", call)
		}
	}
}

// loginAccountRunner answers getent with an interactive account.
type loginAccountRunner struct{ calls [][]string }

func (r *loginAccountRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	switch {
	case name == "getent" && len(args) == 2 && args[0] == "passwd":
		return CommandResult{Stdout: []byte("defenseclaw:x:1008:1008:pilot account:/home/defenseclaw:/bin/bash\n")}, nil
	case name == "getent" && len(args) == 2 && args[0] == "group":
		return CommandResult{Stdout: []byte("defenseclaw:x:1008:\n")}, nil
	}
	return CommandResult{ExitCode: 1}, errors.New("exit status 1")
}
