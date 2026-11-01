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

// An existing macOS service account with a login shell must be rejected
// before the gateway adopts it (GAP-1124).
func TestDSCLAccountEnsureRefusesLoginShell(t *testing.T) {
	runner := dsclLoginRunner{}
	accounts := &dsclAccounts{env: &Env{GOOS: "darwin", Runner: runner}}
	account, ok, err := accounts.Lookup(t.Context(), "_defenseclaw")
	if err != nil || !ok || account.LoginShell != "/bin/zsh" {
		t.Fatalf("Lookup = %+v, %v, %v", account, ok, err)
	}
	if _, err := accounts.Ensure(t.Context(), "_defenseclaw"); err == nil {
		t.Fatal("adopted an interactive macOS account")
	}
}

type dsclLoginRunner struct{}

func (dsclLoginRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	if name != "dscl" || len(args) != 4 || args[0] != "." || args[1] != "-read" {
		return CommandResult{ExitCode: 1}, errors.New("unexpected command")
	}
	switch args[2] + " " + args[3] {
	case "/Users/_defenseclaw UniqueID":
		return CommandResult{Stdout: []byte("UniqueID: 499\n")}, nil
	case "/Users/_defenseclaw PrimaryGroupID", "/Groups/_defenseclaw PrimaryGroupID":
		return CommandResult{Stdout: []byte("PrimaryGroupID: 499\n")}, nil
	case "/Users/_defenseclaw UserShell":
		return CommandResult{Stdout: []byte("UserShell: /bin/zsh\n")}, nil
	case "/Users/_defenseclaw NFSHomeDirectory":
		return CommandResult{Stdout: []byte("NFSHomeDirectory: /Users/_defenseclaw\n")}, nil
	}
	return CommandResult{ExitCode: 1}, errors.New("unexpected attribute")
}

// GAP-0769: a macOS uninstall that could not delete the service account
// repeated dscl's raw output (exit 40, "DS Error: -14120
// (eDSPermissionError)") next to the command that deletes it by hand. It
// names the record and the Open Directory error instead.
func TestDsclDeleteErrorNamesTheRecordAndTheError(t *testing.T) {
	raw := errors.New("dscl . -delete /Users/_defenseclaw: exit status 40: <main> delete status: eDSPermissionError\nDS Error: -14120 (eDSPermissionError)")
	got := dsclDeleteError("/Users/_defenseclaw", raw).Error()
	if got != "macOS refused to delete the directory record /Users/_defenseclaw (eDSPermissionError: macOS lets only a process with Full Disk Access delete a user account, and this one has none)" {
		t.Fatalf("message = %q", got)
	}
	notFound := errors.New("dscl . -delete /Groups/_defenseclaw: exit status 40: DS Error: -14136 (eDSRecordNotFound)")
	if got := dsclDeleteError("/Groups/_defenseclaw", notFound).Error(); got != "macOS refused to delete the directory record /Groups/_defenseclaw (eDSRecordNotFound)" {
		t.Fatalf("another Open Directory error = %q, want only its name", got)
	}
	other := errors.New("dscl: exit status 1: unexpected")
	if got := dsclDeleteError("/Groups/_defenseclaw", other); !errors.Is(got, other) || !strings.Contains(got.Error(), "remove /Groups/_defenseclaw") {
		t.Fatalf("an error without an Open Directory name = %v", got)
	}
}

// appearingLoginAccountRunner answers no defenseclaw account until
// systemd-sysusers ran, then a login account: a directory account NSS could
// not reach at the first lookup, which sysusers found and left alone.
type appearingLoginAccountRunner struct{ sysusersRan bool }

func (r *appearingLoginAccountRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	switch {
	case name == "systemd-sysusers":
		r.sysusersRan = true
		return CommandResult{}, nil
	case name == "getent" && len(args) == 2 && args[0] == "passwd" && r.sysusersRan:
		return CommandResult{Stdout: []byte("defenseclaw:x:1404:1404:Dee Fense:/home/defenseclaw:/bin/bash\n")}, nil
	case name == "getent" && len(args) == 2 && args[0] == "group" && r.sysusersRan:
		return CommandResult{Stdout: []byte("defenseclaw:x:1404:\n")}, nil
	}
	return CommandResult{ExitCode: 2}, errors.New("exit status 2")
}

// GAP-1457: the lookup after systemd-sysusers recorded any account it found
// as created, also a login account that existed before (sysusers found it
// and created nothing), which the uninstall then deleted. It is refused like
// a login account found before.
func TestLinuxAccountEnsureRefusesALoginAccountFoundAfterSysusers(t *testing.T) {
	accounts := &linuxAccounts{env: &Env{GOOS: "linux", Runner: &appearingLoginAccountRunner{}}}
	account, err := accounts.Ensure(context.Background(), "defenseclaw")
	if err == nil || account.Created || !strings.Contains(err.Error(), "login shell /bin/bash") {
		t.Fatalf("Ensure = %+v, %v; want a login-account refusal", account, err)
	}
}
