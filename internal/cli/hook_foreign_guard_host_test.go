// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// withForeignGuardHostSeams points the guard at summaryPath with the given
// directory verdict and load result, on a host without the standalone
// registration, and counts summary loads.
func withForeignGuardHostSeams(t *testing.T, dirErr, loadErr error) *int {
	t.Helper()
	previousPath, previousLoad, previousDir := hookForeignGuardSummaryPath, hookForeignGuardLoad, hookForeignGuardSummaryDirTrusted
	previousRegistered := hookForeignGuardStandaloneRegistered
	hookForeignGuardStandaloneRegistered = func() bool { return false }
	loads := 0
	hookForeignGuardSummaryPath = func() (string, bool) {
		return `C:\ProgramData\Cisco\DefenseClaw-HookRuntime\machine-policy.json`, true
	}
	hookForeignGuardSummaryDirTrusted = func(string) error { return dirErr }
	hookForeignGuardLoad = func(string) (*enterprisepolicy.PublicPolicy, error) {
		loads++
		return nil, loadErr
	}
	t.Cleanup(func() {
		hookForeignGuardSummaryPath, hookForeignGuardLoad, hookForeignGuardSummaryDirTrusted = previousPath, previousLoad, previousDir
		hookForeignGuardStandaloneRegistered = previousRegistered
	})
	return &loads
}

// withForeignGuardStandaloneRegistration sets the administrator-only
// standalone registration and counts how often the gate reads it.
func withForeignGuardStandaloneRegistration(registered bool) *int {
	reads := 0
	hookForeignGuardStandaloneRegistered = func() bool {
		reads++
		return registered
	}
	return &reads
}

// A summary a standard user planted in a folder they created (any content,
// or a folder in its place) must leave every hook exactly as it was before
// the guard existed. This is the Secure Client and unmanaged-host case.
func TestHostForeignHookGuardIgnoresSummaryInUntrustedDirectory(t *testing.T) {
	for _, managedEnterprise := range []bool{true, false} {
		loads := withForeignGuardHostSeams(t,
			errors.New("owner S-1-5-21-1-2-3-1001 is not trusted"),
			errors.New("machine policy summary: owner S-1-5-21-1-2-3-1001 is not trusted"))
		payload := strings.NewReader(`{"cwd":"C:\\work"}`)
		opts := hookexec.Options{Connector: "codex", ManagedEnterprise: managedEnterprise, Stdin: payload}
		applyHostEnterpriseForeignHookGuard(&opts)
		if opts.ManagedEnterprise != managedEnterprise || opts.ManagedRuntimeFailure != "" {
			t.Fatalf("managed=%v: a planted summary must not change the hook: %+v", managedEnterprise, opts)
		}
		if opts.Stdin != io.Reader(payload) || payload.Len() != len(`{"cwd":"C:\\work"}`) {
			t.Fatalf("managed=%v: the hook payload must not be touched", managedEnterprise)
		}
		if *loads != 0 {
			t.Fatalf("managed=%v: the summary must not be read from an untrusted directory", managedEnterprise)
		}
	}

	// A host without a summary directory, or without a standalone layout, is
	// untouched too.
	loads := withForeignGuardHostSeams(t, os.ErrNotExist, nil)
	opts := hookexec.Options{Connector: "claudecode", Stdin: strings.NewReader("{}")}
	applyHostEnterpriseForeignHookGuard(&opts)
	if opts.ManagedEnterprise || opts.ManagedRuntimeFailure != "" || *loads != 0 {
		t.Fatalf("a host without a summary directory must be untouched: %+v loads=%d", opts, *loads)
	}
	hookForeignGuardSummaryPath = func() (string, bool) { return "", false }
	applyHostEnterpriseForeignHookGuard(&opts)
	if opts.ManagedEnterprise || opts.ManagedRuntimeFailure != "" || *loads != 0 {
		t.Fatalf("a host without a standalone layout must be untouched: %+v loads=%d", opts, *loads)
	}
}

// On a standalone host the administrator-written directory is trusted, so an
// untrusted summary inside it still fails closed.
func TestHostForeignHookGuardKeepsFailClosedInTrustedDirectory(t *testing.T) {
	loads := withForeignGuardHostSeams(t, nil, errors.New("machine policy summary is writable by Users"))
	opts := hookexec.Options{Connector: "codex", Stdin: strings.NewReader("{}")}
	applyHostEnterpriseForeignHookGuard(&opts)
	if !opts.ManagedEnterprise || opts.ManagedRuntimeFailure != "enterprise_machine_policy_summary_untrusted" {
		t.Fatalf("an untrusted summary in the trusted directory must fail closed: %+v", opts)
	}
	if *loads != 1 {
		t.Fatalf("summary loads = %d, want 1", *loads)
	}
}

// A standalone host whose summary directory fails its check for a reason no
// standard user controls (drifted ACLs, an unreadable security descriptor,
// a refused drive mount) still carries the administrator-only registration:
// the guard must keep failing closed there instead of switching off.
func TestHostForeignHookGuardKeepsFailClosedOnRegisteredStandaloneHost(t *testing.T) {
	for _, dirErr := range []error{
		errors.New("machine policy summary directory grants write access to S-1-5-32-545"),
		errors.New("machine policy summary directory: inspect Windows security descriptor: Access is denied."),
		errors.New("machine policy summary directory is not on a trusted mount-manager NTFS drive"),
	} {
		loads := withForeignGuardHostSeams(t, dirErr, errors.New("machine policy summary is writable by Users"))
		reads := withForeignGuardStandaloneRegistration(true)
		opts := hookexec.Options{Connector: "codex", Stdin: strings.NewReader("{}")}
		applyHostEnterpriseForeignHookGuard(&opts)
		if !opts.ManagedEnterprise || opts.ManagedRuntimeFailure != "enterprise_machine_policy_summary_untrusted" {
			t.Fatalf("%v: a registered standalone host must fail closed: %+v", dirErr, opts)
		}
		if *loads != 1 || *reads != 1 {
			t.Fatalf("%v: summary loads = %d, registration reads = %d, want 1 and 1", dirErr, *loads, *reads)
		}
	}
	// A registered host without a summary is untouched, as before the gate.
	loads := withForeignGuardHostSeams(t, os.ErrNotExist, enterprisepolicy.ErrNoPublicPolicy)
	withForeignGuardStandaloneRegistration(true)
	opts := hookexec.Options{Connector: "claudecode", Stdin: strings.NewReader("{}")}
	applyHostEnterpriseForeignHookGuard(&opts)
	if opts.ManagedEnterprise || opts.ManagedRuntimeFailure != "" || *loads != 1 {
		t.Fatalf("a registered host without a summary must be untouched: %+v loads=%d", opts, *loads)
	}
}

// The hook command must enter the guard only through the host gate.
func TestHookCommandEntersForeignGuardThroughHostGate(t *testing.T) {
	source, err := os.ReadFile("hook.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "applyHostEnterpriseForeignHookGuard(&opts)") {
		t.Fatal("hook.go must call applyHostEnterpriseForeignHookGuard")
	}
	if regexp.MustCompile(`(^|[^A-Za-z])applyEnterpriseForeignHookGuard\(`).MatchString(text) {
		t.Fatal("hook.go must not call applyEnterpriseForeignHookGuard without the host gate")
	}
}
