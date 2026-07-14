// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"strings"
	"testing"
)

func allowedSetupLaunchFacts() setupLaunchFacts {
	return setupLaunchFacts{
		SessionID:                1,
		InteractiveToken:         true,
		InteractiveWindowStation: true,
		DialogSafe:               true,
	}
}

func TestDecideSetupLaunchContext(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*setupLaunchFacts)
		want        setupLaunchRejection
		allowDialog bool
	}{
		{name: "normal current user", want: setupLaunchAllowed},
		{
			name:   "elevated interactive user",
			mutate: func(facts *setupLaunchFacts) { facts.Elevated = true },
			want:   setupLaunchElevated, allowDialog: true,
		},
		{
			name:   "service identity",
			mutate: func(facts *setupLaunchFacts) { facts.ServiceIdentity = true },
			want:   setupLaunchService,
		},
		{
			name:   "session zero",
			mutate: func(facts *setupLaunchFacts) { facts.SessionID = 0 },
			want:   setupLaunchSessionZero,
		},
		{
			name:   "batch token",
			mutate: func(facts *setupLaunchFacts) { facts.InteractiveToken = false },
			want:   setupLaunchNonInteractive,
		},
		{
			name:   "invisible service window station",
			mutate: func(facts *setupLaunchFacts) { facts.InteractiveWindowStation = false },
			want:   setupLaunchNonInteractive,
		},
		{
			name: "service takes precedence over elevation",
			mutate: func(facts *setupLaunchFacts) {
				facts.ServiceIdentity = true
				facts.Elevated = true
			},
			want: setupLaunchService,
		},
		{
			name: "session zero takes precedence over elevation",
			mutate: func(facts *setupLaunchFacts) {
				facts.SessionID = 0
				facts.Elevated = true
			},
			want: setupLaunchSessionZero,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := allowedSetupLaunchFacts()
			if test.mutate != nil {
				test.mutate(&facts)
			}
			got := decideSetupLaunchContext(facts)
			if got.Reason != test.want || got.AllowDialog != test.allowDialog {
				t.Fatalf("decision = %+v, want reason=%q allowDialog=%v", got, test.want, test.allowDialog)
			}
		})
	}
}

func TestRequireCurrentUserInteractiveSetupFailsClosedOnProbeError(t *testing.T) {
	original := inspectCurrentSetupLaunchContext
	inspectCurrentSetupLaunchContext = func() (setupLaunchFacts, error) {
		return setupLaunchFacts{}, errors.New("token query denied")
	}
	t.Cleanup(func() { inspectCurrentSetupLaunchContext = original })

	err := requireCurrentUserInteractiveSetup()
	var launchErr *setupLaunchContextError
	if !errors.As(err, &launchErr) || launchErr.Decision.Reason != setupLaunchProbeFailed {
		t.Fatalf("error = %v, want probe-failed setupLaunchContextError", err)
	}
	for _, fragment := range []string{"could not verify", "No system or user settings were changed", "token query denied"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("error %q does not contain %q", err, fragment)
		}
	}
}

func TestProbeFailureRetainsSafeInteractiveDialog(t *testing.T) {
	original := inspectCurrentSetupLaunchContext
	inspectCurrentSetupLaunchContext = func() (setupLaunchFacts, error) {
		return allowedSetupLaunchFacts(), errors.New("elevation query unavailable")
	}
	t.Cleanup(func() { inspectCurrentSetupLaunchContext = original })

	err := requireCurrentUserInteractiveSetup()
	var launchErr *setupLaunchContextError
	if !errors.As(err, &launchErr) || launchErr.Decision.Reason != setupLaunchProbeFailed {
		t.Fatalf("error = %v, want probe-failed setupLaunchContextError", err)
	}
	if !launchErr.Decision.AllowDialog {
		t.Fatal("independently verified interactive context did not retain a safe error dialog")
	}
}

func TestRunHelpDoesNotProbeOrAcquireLock(t *testing.T) {
	originalProbe := inspectCurrentSetupLaunchContext
	originalLock := acquireSetupOperationLock
	probeCalled := false
	lockCalled := false
	inspectCurrentSetupLaunchContext = func() (setupLaunchFacts, error) {
		probeCalled = true
		return setupLaunchFacts{}, errors.New("unexpected probe")
	}
	acquireSetupOperationLock = func() (func() error, error) {
		lockCalled = true
		return nil, errors.New("unexpected lock")
	}
	t.Cleanup(func() {
		inspectCurrentSetupLaunchContext = originalProbe
		acquireSetupOperationLock = originalLock
	})

	code, err := run(options{Action: "help", Quiet: true})
	if code != 0 || err != nil {
		t.Fatalf("help = (%d, %v), want success", code, err)
	}
	if probeCalled || lockCalled {
		t.Fatalf("help performed launch probe or setup lock: probe=%v lock=%v", probeCalled, lockCalled)
	}
}

func TestRunRejectsLaunchBeforeSetupLock(t *testing.T) {
	originalProbe := inspectCurrentSetupLaunchContext
	originalLock := acquireSetupOperationLock
	inspectCurrentSetupLaunchContext = func() (setupLaunchFacts, error) {
		facts := allowedSetupLaunchFacts()
		facts.Elevated = true
		return facts, nil
	}
	lockCalled := false
	acquireSetupOperationLock = func() (func() error, error) {
		lockCalled = true
		return func() error { return nil }, nil
	}
	t.Cleanup(func() {
		inspectCurrentSetupLaunchContext = originalProbe
		acquireSetupOperationLock = originalLock
	})

	code, err := run(options{Action: "install", Quiet: true})
	if code != retryRequiredCode {
		t.Fatalf("code = %d, want %d", code, retryRequiredCode)
	}
	var launchErr *setupLaunchContextError
	if !errors.As(err, &launchErr) || launchErr.Decision.Reason != setupLaunchElevated {
		t.Fatalf("error = %v, want elevated setupLaunchContextError", err)
	}
	if lockCalled {
		t.Fatal("setup lock was acquired before the launch context was rejected")
	}
}

func TestRunAllowsNormalInteractiveContextToReachSetupLock(t *testing.T) {
	originalProbe := inspectCurrentSetupLaunchContext
	originalLock := acquireSetupOperationLock
	inspectCurrentSetupLaunchContext = func() (setupLaunchFacts, error) {
		return allowedSetupLaunchFacts(), nil
	}
	wantErr := errors.New("lock sentinel")
	lockCalled := false
	acquireSetupOperationLock = func() (func() error, error) {
		lockCalled = true
		return nil, wantErr
	}
	t.Cleanup(func() {
		inspectCurrentSetupLaunchContext = originalProbe
		acquireSetupOperationLock = originalLock
	})

	code, err := run(options{Action: "install", Quiet: true})
	if code != installAlreadyRunningCode || !errors.Is(err, wantErr) {
		t.Fatalf("run = (%d, %v), want (%d, %v)", code, err, installAlreadyRunningCode, wantErr)
	}
	if !lockCalled {
		t.Fatal("normal current-user interactive context did not reach the setup lock")
	}
}
